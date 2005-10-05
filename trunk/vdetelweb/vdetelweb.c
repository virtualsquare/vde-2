/*   
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   vdetelweb.c: main
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */
#include  <stdio.h>
#include  <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include  <errno.h>
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <sys/select.h>
#include  <sys/poll.h>
#include  <sys/utsname.h>
#include <linux/un.h>
#include  <netinet/in.h>
#include  <arpa/inet.h>
#include  <string.h>
#include <getopt.h>
#include <lwipv6.h>
#include "vdetelweb.h"

int daemonize;
int telnet;
int web;
char *mgmt;
char *banner;
char *progname;
char *prompt;
int logok;
char *passwd;

#define MAXFD 16
int npfd=0;
struct pollfd pfd[MAXFD];
typedef int (*intfun)();
intfun fpfd[MAXFD];
void *status[MAXFD];

#define ROOTCONFFILE "/etc/vde/vdetelwebrc"

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",progname);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}


static void cleanup(void)
{
}

static void sig_handler(int sig)
{
	cleanup();
	signal(sig, SIG_DFL);
	exit(0);
}

static void setsighandlers()
{
	/* setting signal handlers.
	 *    * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 *       * ignores all the others signals which could cause termination. */
	struct { int sig; const char *name; int ignore; } signals[] = {
		{ SIGHUP, "SIGHUP", 0 },
		{ SIGINT, "SIGINT", 0 },
		{ SIGPIPE, "SIGPIPE", 1 },
		{ SIGALRM, "SIGALRM", 1 },
		{ SIGTERM, "SIGTERM", 0 },
		{ SIGUSR1, "SIGUSR1", 1 },
		{ SIGUSR2, "SIGUSR2", 1 },
		{ SIGPOLL, "SIGPOLL", 1 },
		{ SIGPROF, "SIGPROF", 1 },
		{ SIGVTALRM, "SIGVTALRM", 1 },
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
		{ SIGUNUSED, "SIGUNUSED", 1 },
		{ 0, NULL, 0 }
	};

	int i;
	for(i = 0; signals[i].sig != 0; i++)
		if(signal(signals[i].sig,
					signals[i].ignore ? SIG_IGN : sig_handler) < 0)
			perror("Setting handler");
}

static void usage(char *progname) {
	fprintf (stderr,"Usage: %s [-w] [-t] [-d] [-n nodename] mgmt_socket\n"
			"       %s [--web] [--telnet] [--daemon] [--nodename nodename] mgmt_socket\n",progname,progname);
	exit(-1);
}

void setprompt(char *ctrl,char *nodename)
{
	char buf[BUFSIZE];
	if (nodename==NULL) {
		struct utsname un;
		uname(&un);
		snprintf(buf,BUFSIZE,"VDE2@%s[%s]: ",un.nodename,ctrl);
	} else
		snprintf(buf,BUFSIZE,"VDE2@%s[%s]: ",nodename,ctrl);
	prompt=strdup(buf);
}

int openvdem(char *mgmt,char *progname, struct netif **nif,char *nodename)
{
	struct sockaddr_un sun;
	int fd,n;
	char buf[BUFSIZE+1],*line2,*ctrl;
	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",mgmt);
	fd=socket(PF_UNIX,SOCK_STREAM,0);
	if (connect(fd,(struct sockaddr *)(&sun),sizeof(sun)) < 0) {
		printlog(LOG_ERR,"mgmt connect %s",strerror(errno));
		exit(-1);
	}
	if ((n=read(fd,buf,BUFSIZE))<=0) {
		printlog(LOG_ERR,"banner %s",strerror(errno));
		exit(-1);
	}
	buf[n]=0;
	if ((ctrl=rindex(buf,'\n')) != NULL)
		*ctrl=0;
	banner=strdup(buf);
	write(fd,"ds/showinfo\n",13);
	if ((n=read(fd,buf,BUFSIZE))<=0) {
		printlog(LOG_ERR,"read ctl socket %s",strerror(errno));
		exit(-1);
	}
	buf[n]=0;
	if ((line2=index(buf,'\n')) == NULL) {
		printlog(LOG_ERR,"read ctl socket parse error 1");
		exit(-1);
	}
	line2++;
	if (strncmp(line2,"ctl dir ",8) != 0) {
		printlog(LOG_ERR,"read ctl socket parse error");
		exit(-1);
	}
	for(ctrl=line2+8;*ctrl!='\n' && ctrl<buf+n;ctrl++)
		;
	*ctrl=0;
	ctrl=line2+8;
	setprompt(ctrl,nodename);
	strcat(ctrl,"[0]");
	*nif=lwip_vdeif_add(ctrl);
	if (*nif == NULL) {
		printlog(LOG_ERR,"cannot connect to the switch");
		exit(-1);
	}
	lwip_ifup(*nif);

	return fd;
}

int readip4(char *arg,struct netif *nif)
{
	char *bit=rindex(arg,'/');
	int bitno=0;
	int addr[4];
	struct ip_addr ipaddr,netmask;
	if (bit == 0) 
		printlog(LOG_ERR,"ip addresses must include the netmask e.g. 192.168.0.1/24");
	else {
		int i;
		bitno=atoi(bit+1);
		if(sscanf(arg,"%i.%i.%i.%i",&addr[0],&addr[1],&addr[2],&addr[3]) != 4){
			printlog(LOG_ERR,"invalid ip address",arg);
			return(-1);
		}
		IP64_ADDR(&ipaddr, addr[0],addr[1],addr[2],addr[3]);
		for(i=0;i<4;i++,bitno -= 8) {
			if (bitno >= 8) 
				addr[i]=255; 
			else if (bitno <= 0) 
				addr[i]=0;
			else 
				addr[i]=256 - (1<<(8-bitno));
		}
		IP64_MASKADDR(&netmask, addr[0],addr[1],addr[2],addr[3]);
		lwip_add_addr(nif,&ipaddr,&netmask);
	}
}

int readip6(char *arg,struct netif *nif)
{
}

int readdefroute4(char *arg,struct netif *nif)
{
	int addr[4];
	struct ip_addr ipaddr;
	sscanf(arg,"%d.%d.%d.%d",addr,addr+1,addr+2,addr+3);
	IP64_ADDR(&ipaddr, addr[0],addr[1],addr[2],addr[3]);
	lwip_add_route(IP_ADDR_ANY,IP_ADDR_ANY,&ipaddr,nif,0);
}

int readdefroute6(char *arg,struct netif *nif)
{
}

int readpassword(char *arg)
{
	passwd=strdup(arg);
}

struct cf {
	char *tag;
	int (*f)();
} cft[]= {
	{"ip4",readip4},
	{"ip6",readip6},
	{"defroute4",readdefroute4},
	{"defroute6",readdefroute6},
	{"password",readpassword},
	{NULL,NULL}};

int readconffile(char *path,struct netif *nif)
{
	FILE *f;
	char buf[BUFSIZE],*s;
	if (path == NULL && geteuid() == 0)
		path=ROOTCONFFILE;
	if (path==NULL)
		return -1;
	if((f=fopen(path,"r"))==NULL)
		return -1;
	while (fgets(buf,BUFSIZE,f) != NULL) {
		if ((s=rindex(buf,'\n')) != NULL)
			*s=0;
		for(s=buf;*s == ' ' || *s == '\t';s++)
			;
		if (*s != '#') {
			struct cf *scf;
			for (scf=cft;scf->tag != NULL;scf++)
				if(strncmp(s,scf->tag,strlen(scf->tag)) == 0){
					s+=strlen(scf->tag);
					for(;*s == ' ' || *s == '\t';s++)
						;
					if (*s == '=') s++;
					for(;*s == ' ' || *s == '\t';s++)
						;
					scf->f(s,nif);
					break;
				}
			if (scf->tag == NULL) {
				printlog(LOG_ERR,"rc file syntax error: %s",buf);
			}
		}
	}
	return 0;
}

int addpfd(int fd,intfun cb)
{
	if (npfd < MAXFD) {
		pfd[npfd].fd=fd;
		pfd[npfd].events=POLLIN|POLLHUP;
		pfd[npfd].revents=0;
		fpfd[npfd]=cb;
		npfd++;
	}
	return npfd-1;
}

void delpfd(int fn)
{
	int i=fn;
	for (i=fn;i<npfd-1;i++) {
		pfd[i]=pfd[i+1];
		fpfd[i]=fpfd[i+1];
		status[i]=status[i+1];
	}
	npfd--;
}

int pfdsearch(int fd)
{
	int i;
	for (i=0;i<npfd && pfd[i].fd!=fd;i++)
		;
	return i;
}

int setfds(fd_set *rds, fd_set *exc)
{
	int i,max=0;
	FD_ZERO(rds);
	FD_ZERO(exc);
	for (i=0;i<npfd;i++) {
		FD_SET(pfd[i].fd,rds);
		FD_SET(pfd[i].fd,exc);
		if (pfd[i].fd>max) max=pfd[i].fd;
	}
	return max+1;
}

int main(int argc, char *argv[])
{
	struct netif *nif;
	int vdefd;
	char *conffile=NULL;
	char *nodename=NULL;
	progname=argv[0];
	{
		int c;
		while (1) {
			int option_index = 0;

			static struct option long_options[] = {
				{"daemon", 0, 0, 'd'},
				{"mgmt", 1, 0, 'M'},
				{"telnet", 0, 0, 't'},
				{"web", 0, 0, 'w'},
				{"help",0,0,'h'},
				{"rcfile",1,0,'f'},
				{"nodename",1,0,'n'},
				{0, 0, 0, 0}
			};
			c = getopt_long_only (argc, argv, "hdwtM:f:n:",
					long_options, &option_index);
			if (c == -1)
				break;

			switch (c) {
				case 'M':
					mgmt=strdup(optarg);
					break;
				case 'f':
					conffile=strdup(optarg);
					break;
				case 'n':
					nodename=strdup(optarg);
					break;
				case 't':
					telnet=1;
					break;
				case 'w':
					web=1;
					break;
				case 'd':
					daemonize=1;
					break;
				case 'h':
					usage(argv[0]); //implies exit
					break;
			}
		}
		if (optind < argc && mgmt==NULL)
			mgmt=argv[optind];
	}
	if (mgmt==NULL) {
		printlog(LOG_ERR,"mgmt_socket not defined");
		exit(-1);
	}
	if (telnet==0 && web==0) {
		printlog(LOG_ERR,"at least one service option (-t -w) must be specified");
		exit(-1);
	}
	setsighandlers();
	vdefd=openvdem(mgmt,argv[0],&nif,nodename);
	if (readconffile(conffile,nif) < 0) {
		printlog(LOG_ERR,"configuration file not found");
		exit(1);
	}
	if (daemonize && daemon(0, 1)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}
	if (telnet)
		telnet_init(vdefd);
	if (web)
		web_init(vdefd);

	while (1)
	{
		int n,m,i;
		fd_set rds,exc;
		int max=setfds(&rds,&exc);
		m=lwip_select(max,&rds,NULL,&exc,NULL);
		for(i=0; m>0 && i<max; i++) {
			if (FD_ISSET(i,&rds) || FD_ISSET(i,&exc)) {
				n=pfdsearch(i);
				fpfd[n](n,i,vdefd);
				m--;
			}
		}
	}
}

