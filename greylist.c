#include "gld.h"
#include "sockets.h"

int GreyList(char *ip,char *sender,char *recipient,config *conf)
{

char query[QLEN];
long n,x;
int ts;
char *domain;
char netw[BLEN];
int i,l;
char oip[BLEN];
int a,b,c,d;
int pid;
char osender[BLEN];
char orecipient[BLEN];
struct result found;
struct in6_addr ip6result;

pid=getpid();
ts=time(0);
strncpy(oip,ip,sizeof(oip)-1);
strncpy(osender,sender,sizeof(osender)-1);
strncpy(orecipient,recipient,sizeof(orecipient)-1);

if(conf->debug==1) printf("%d: Starting the greylist algo\n",pid);

//
// If we do lightgreylisting, then we just keep the network part of ip (FIXME: IPv6)
//
if ((conf->light==1) && (inet_pton(AF_INET6, oip, &ip6result) != 1))
{
	if(conf->debug==1) printf("%d: lightgrey is on, let's remove the last octet of ip\n",pid);
	l=strlen(ip);
	for(i=l-1;i>=0;i--)
	{
		if(ip[i]=='.')
		{
			ip[i+1]='0';
			ip[i+2]=0;
			break;
		}
	}
}

//
// Do we have this entry in our database?
//
snprintf(query,sizeof(query)-1,"select first from greylist where ip='%s' and sender='%s' and recipient='%s'",ip,sender,recipient);
n=SQLQuery(query);
if(conf->debug==1) printf("%d: Query=(%s) result=%ld\n",pid,query,n);

//
// If request failed, return the error
//
if(n<0)
{
	return(-1);
}

//
// If the triplet is in our db
//
if(n>0)
{
	// and mintime+, always update last timestamp (cleanup needs this) and accept it
	if(ts-n>conf->mini)
	{
		snprintf(query,sizeof(query)-1,"update greylist set last=%d,n=n+1 where ip='%s' and sender='%s' and recipient='%s'",ts,ip,sender,recipient);
		SQLQuery(query);
		if(conf->debug==1) printf("%d: Query=(%s)\n",pid,query);
		return(1);
	}
	// any other case (mintime-), refuse it
	else
	{
		if(conf->debug==1) printf("%d: MINTIME has not been reached yet\n",pid);
		return(0);
	}
}

// #########################################################
// From this point to the end, the triplet WAS NOT in the db
// #########################################################

//
// Now we do some whitelist checks before inserting it
//

//
// First we check our local whitelist
//
if(conf->whitelist==1)
{
	if(conf->debug==1) printf("%d: whitelist is on\n",pid);
	domain=(char *)strstr(osender,"@");
	if(domain==NULL) domain=osender;

	if (inet_pton(AF_INET6, oip, &ip6result) != 1) { /* FIXME: Only IPv4 */
		strncpy(netw,oip,sizeof(netw)-1);
		l=strlen(netw);
		for(i=l-1;i>=0;i--) {
			if(netw[i]=='.') {
				netw[i]=0;
				break;
			}
		}
	}

	snprintf(query, sizeof(query)-1, "SELECT COUNT(mail) FROM whitelist WHERE mail IN ('%s', '%s', '%s', '%s')", osender, domain, oip, netw);
	n=SQLQuery(query);
	if(conf->debug==1) printf("%d: Query=(%s) result=%ld\n",pid,query,n);
	if(n>0)
	{
		if(conf->syslog==1) Log(conf,orecipient,osender,oip,MSGLOCALWL);
		return(1);
	}
}

if (conf->wlbydnsnodes == 1) {
	/* If oip resolves to xyz.google.com and xyz.google.com resolves to oip,
	   search whitelist for .google.com, if no match, return NULL */
	if (conf->debug==1) printf("%d: whitelist by DNS node is on\n", pid);
	if (conf->debug==1) printf("%d: doing double DNS lookup on \"%s\"\n", pid, oip);
	if ((i = doubleDNSlookup(oip, &found, conf)) != 0) {
		if (conf->debug==1)printf("%d: found %d matching IP addresses\n", pid, i);
		if (found.total != 0) {
			if (conf->debug==1) printf("%d: found %d domains\n", pid, found.total);
			snprintf(query, sizeof(query)-1, "SELECT COUNT(mail) FROM whitelist WHERE mail IN (");
			for (i = 0; i < found.total; i++) {
				if (conf->debug==1) printf("%d: Adding node = %s\n", pid, found.domain[i]);
				strcat(query, "'"); /* 'tld.cc' */
				strncat(query, found.domain[i], 255);
				if (i == (found.total - 1)) /* Last? */
					strcat(query, "'");
				else
					strcat(query, "', ");
			}
			strcat(query, ")");
			n=SQLQuery(query);
			if (conf->debug==1) printf("%d: Query=(%s) result=%ld\n", pid, query, n);
			if (n > 0) {
				snprintf(query, sizeof(query)-1, "ip=<%s> dns=<%s>", oip, found.domain[0]);
				if (conf->syslog==1) Log(conf, orecipient, osender, query, MSGLOCALWLDNS);
				return(1);
			}
		} else
			if (conf->debug==1) printf("%d: found NO nodes\n", pid);
	} else {
		if (conf->debug==1) printf("%d: Could not resolve \"%s\".\n", pid, oip);
	}
}

//
// then we check the DNS whitelist (FIXME: IPv6)
//

if ((conf->dnswl[0]!=0) && (inet_pton(AF_INET6, oip, &ip6result) != 1))
{
	if (conf->debug==1) printf("%d: DNS whitelist is on\n",pid);
	x = sscanf(oip,"%d.%d.%d.%d",&a,&b,&c,&d);
	if (x==4) { // We need to parse and count the number elements in the conf->dnswl variable
		char *token;
		token = strtok(conf->dnswl, " "); /* get the first token */
		while (token != NULL) { /* walk through other tokens */
			snprintf(query,sizeof(query)-1,"%d.%d.%d.%d.%s",d,c,b,a,token);
			n=DnsIp(query,NULL);
			if (conf->debug==1) printf("%d: DNSQuery=(%s) result=%ld\n",pid,query,n);
			if (n==0) {
				if (conf->syslog==1) Log(conf,orecipient,osender,oip,MSGDNSWL);
				return(1);
			}
			token = strtok(NULL, " ");
		}
	}
}
//
// If we are here, The mail was not in our database
// was not whitelisted and thus we have to insert it
//
snprintf(query,sizeof(query)-1,"insert into greylist values('%s','%s','%s',%d,%d,1)",ip,sender,recipient,ts,ts);
SQLQuery(query);
if(conf->debug==1) printf("%d: Query=(%s)\n",pid,query);

//
// If we have activated the mxgrey
// Let's accept the mail if this ip already succeded the required number of greylists
//
if(conf->mxgrey>0)
{
	// check for unique triplets already graylisted from the IP
	snprintf(query,sizeof(query)-1,"SELECT COUNT(first) FROM greylist WHERE ip='%s' AND n>1",ip);
	n=SQLQuery(query);
	if(conf->debug==1) printf("%d: Mxgrey Query=(%s) result=%ld (minimum needed is %d)\n",pid,query,n,conf->mxgrey);
	// if found, accept it
	if(n>=conf->mxgrey)
	{
		return(1);
	}
}

return(0);

}
