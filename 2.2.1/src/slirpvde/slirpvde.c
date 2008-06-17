/* Copyright 2003-2007 Renzo Davoli 
 * Licensed under the GPL
 * Modified by Ludovico Gardenghi 2005
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libslirp.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <limits.h>


#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <libvdeplug.h>
#include "misc.h"
#include "tcp2unix.h"

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
#	if defined HAVE_SYSLIMITS_H
#		include <syslimits.h>
#	elif defined HAVE_SYS_SYSLIMITS_H
#		include <sys/syslimits.h>
#	else
#		error "No syslimits.h found"
#	endif
#endif

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define ETH_ALEN 6

VDECONN *conn;
int dhcpmgmt=0;
static char *pidfile = NULL;
static char pidfile_path[_POSIX_PATH_MAX];
int logok=0;
char *prog;
extern FILE *lfd;

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",prog);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}


static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, PATH_MAX - strlen(pidfile_path));
	else
		strcpy(pidfile_path, pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

static void cleanup(void)
{
	if((pidfile != NULL) && unlink(pidfile_path) < 0) {
		printlog(LOG_WARNING,"Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
	}
	vde_close(conn);
}

/* XXX Apparently unused... check if ok to be removed */

/*static void sig_handler(int sig)
{
	  cleanup();
		  signal(sig, SIG_DFL);
			  kill(getpid(), sig);
}*/



/*static void setsighandlers()
{
	|+ setting signal handlers.
	 * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 * ignores all the others signals which could cause termination. +|
	struct { int sig; const char *name; int ignore; } signals[] = {
		{ SIGHUP, "SIGHUP", 0 },
		{ SIGINT, "SIGINT", 0 },
		{ SIGPIPE, "SIGPIPE", 1 },
		{ SIGALRM, "SIGALRM", 1 },
		{ SIGTERM, "SIGTERM", 0 },
		{ SIGUSR1, "SIGUSR1", 1 },
		{ SIGUSR2, "SIGUSR2", 1 },
		{ SIGPROF, "SIGPROF", 1 },
		{ SIGVTALRM, "SIGVTALRM", 1 },
#ifdef VDE_LINUX
		{ SIGPOLL, "SIGPOLL", 1 },
#ifdef SIGSTKFLT
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
#endif
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
#ifdef SIGUNUSED
		{ SIGUNUSED, "SIGUNUSED", 1 },
#endif
#endif
#ifdef VDE_DARWIN
		{ SIGXCPU, "SIGXCPU", 1 },
		{ SIGXFSZ, "SIGXFSZ", 1 },
#endif
		{ 0, NULL, 0 }
	};

	int i;
	for(i = 0; signals[i].sig != 0; i++)
		if(signal(signals[i].sig,
					signals[i].ignore ? SIG_IGN : sig_handler) < 0)
			perror("Setting handler");
}*/

unsigned char bufin[BUFSIZE];

int slirp_can_output(void)
{
	return 1;
}


#if 0
#define convery2ascii(x) ((x)>=' ' && (x) <= '~')?(x):'.'
void dumppkt(const uint8_t *pkt, int pkt_len)
{
	register int i,j;
	printf("Packet dump len=%d\n",pkt_len);
	if (pkt_len == 0) 
		return;
	for (i=0;i<((pkt_len-1)/16)+1;i++) {
		for (j=0;j<16;j++)
			if (i*16+j > pkt_len)
				printf("   ");
			else
				printf("%02x ",pkt[i*16+j]);
		printf("  ");
		for (j=0;j<16;j++)
			if (i*16+j > pkt_len)
				printf(" ");
			else
				printf("%c",convery2ascii(pkt[i*16+j]));
		printf("\n");
	}
}
#endif

void slirp_output(const uint8_t *pkt, int pkt_len)
{
	/* slirp -> vde */
	//fprintf(stderr,"RX from slirp %d\n",pkt_len);
	//dumppkt(pkt,pkt_len);
	vde_send(conn,pkt,pkt_len,0);
}

struct redirx {
	u_int32_t inaddr;
	int start_port;
	int display;
	int screen;
	struct redirx *next;
};

struct redirtcp {
	u_int32_t inaddr;
	int port;
	int lport;
	struct redirtcp *next;
};

static struct redirtcp *parse_redir_tcp(struct redirtcp *head, char *buff)
{
	u_int32_t inaddr=0;
	int port=0;
	int lport=0;
	char *ipaddrstr=NULL;
	char *portstr=NULL;
	struct redirtcp *new;
			
	if ((ipaddrstr = strchr(buff, ':'))) {
		*ipaddrstr++ = 0;
		if (*ipaddrstr == 0) {
			fprintf(stderr,"redir TCP syntax error\n");
			return head;
		}
	}
	if ((portstr = strchr(ipaddrstr, ':'))) {
		*portstr++ = 0;
		if (*portstr == 0) {
			fprintf(stderr,"redir TCP syntax error\n");
			return head;
		}
	}

	sscanf(buff,"%d",&lport);
	sscanf(portstr,"%d",&port);
	if (ipaddrstr) 
		inaddr = inet_addr(ipaddrstr);

	if (!inaddr) {
		fprintf(stderr,"TCP redirection error: an IP address must be specified\r\n");
		return head;
	}

	if ((new=malloc(sizeof(struct redirtcp)))==NULL)
		return head;
	else {
		new->inaddr=inaddr;
		new->port=port;
		new->lport=lport;
		new->next=head;
		return new;
	}
}

static struct redirx *parse_redir_x(struct redirx *head, char *buff)
{
	char *ptr=NULL;
	u_int32_t inaddr = 0;
	int display=0;
	int screen=0;
	int start_port = 0;
	struct redirx *new;
	if ((ptr = strchr(buff, ':'))) {
		*ptr++ = 0;
		if (*ptr == 0) {
			fprintf(stderr,"X-redirection syntax error\n");
			return head;
		}
	}
	if (buff[0]) {
		inaddr = inet_addr(buff);
		if (inaddr == 0xffffffff) {
			fprintf(stderr,"Error: X-redirection bad address\r\n");
			return head;
		}
	}
	if (ptr) {
		if (strchr(ptr, '.')) {
			if (sscanf(ptr, "%d.%d", &display, &screen) != 2)
				return head;
		} else {
			if (sscanf(ptr, "%d", &display) != 1)
				return head;
		}
	}

	if (!inaddr) {
		fprintf(stderr,"Error: X-redirection an IP address must be specified\r\n");
		return head;
	}

	if ((new=malloc(sizeof(struct redirx)))==NULL)
		return head;
	else {
		new->inaddr=inaddr;
		new->display=display;
		new->screen=screen;
		new->start_port=start_port;
		new->next=head;
		return new;
	}
}

static void parse_redir_locx(char *buff)
{
	char *path;
	int port=atoi(buff);
	if ((path = strchr(buff, ':'))) {
		*path++=0;
		tcp2unix_add(port,path);
	} else 
		fprintf(stderr,"Error: tcp2unix redirection sytax error -x port:path e.g. -x 6000:/tmp/.X11-unix/X0\r\n");
}

static void do_redir_tcp(struct redirtcp *head)
{
	if (head) {
		do_redir_tcp(head->next);
		redir_tcp(head->inaddr,head->port,head->lport);
		free(head);
	}
}

static void do_redir_x(struct redirx *head)
{
	if (head) {
		do_redir_x(head->next);
		redir_x(head->inaddr,head->start_port,head->display,head->screen);
		free(head);
	}
}

void usage(char *name) {
	fprintf(stderr,
			"Usage:\n"
			" %s [-socket vdesock] [-dhcp] [-daemon] [-network netaddr] \n"
			"\t [-L host_port:guest_addr:guest_port] [-X guest_addr[:display[.screen]]] \n"
			"\t [-x portno:unix_socket_path]\n"
			" %s [-s vdesock] [-D] [-d] [-n netaddr]\n"
			"\t [-L host_port:guest_addr:guest_port] [-X guest_addr[:display[.screen]]] \n" 
			"\t [-x portno:unix_socket_path]\n"
			,name,name);
	exit(-1);
}

struct option slirpvdeopts[] = {
	{"socket",1,NULL,'s'},
	{"sock",1,NULL,'s'},
	{"vdesock",1,NULL,'s'},
	{"unix",1,NULL,'s'},
	{"pidfile", 1, 0, 'p'},
	{"dhcp",0,NULL,'D'},
	{"daemon",0,NULL,'d'},
	{"network",1,NULL,'n'},
	{"mod",1,0,'m'},
	{"group",1,0,'g'},
	{"port",1,0,'P'},
	{NULL,0,0,0}};

int main(int argc, char **argv)
{
  char *sockname=NULL;
  int result,nfds;
  register ssize_t nx;
  /*register int i;*/
  fd_set rs,ws,xs;
  int opt,longindx;
  char *netw=NULL;
	int daemonize=0;
	struct redirtcp *rtcp=NULL;
	struct redirx *rx=NULL;
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};

  prog=basename(argv[0]);

  while ((opt=GETOPT_LONG(argc,argv,"s:n:p:g:m:L:X:x:dD",slirpvdeopts,&longindx)) > 0) {
		switch (opt) {
			case 's' : sockname=optarg;
								 break;
			case 'D' : dhcpmgmt = 1;
								 break;
			case 'd' : daemonize = 1;
								 break;
			case 'n' : netw=optarg;
								 break;
			case 'm' : sscanf(optarg,"%o",&(open_args.mode));
								 break;
			case 'g' : open_args.group=strdup(optarg);
								 break;
			case 'p':  pidfile=strdup(optarg);
								 break;
			case 'P' : open_args.port=atoi(optarg);
								 break;
			case 'L': rtcp=parse_redir_tcp(rtcp,optarg);
								 break;
			case 'X': rx=parse_redir_x(rx,optarg);
								 break;
			case 'x': parse_redir_locx(optarg);
								 break;
			default  : usage(prog);
								 break;
		}
  }
	atexit(cleanup);
	if (daemonize) {
		openlog(basename(prog), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"slirpvde started");
	}
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	
	conn=vde_open(sockname,"slirpvde:",&open_args);
	if (!conn)
	{
		printlog(LOG_ERR, "Could not connect to the VDE switch at '%s': %s",
				sockname, strerror(errno));
		exit(1);
	}
	
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	if(pidfile) save_pidfile();

	lfd=stderr;
	slirp_init(netw);

	do_redir_tcp(rtcp);
	do_redir_x(rx);

	for(;;) {
		int datafd,ctlfd;
		FD_ZERO(&rs);
		FD_ZERO(&ws);
		FD_ZERO(&xs);
		nfds= -1;
		slirp_select_fill(&nfds,&rs,&ws,&xs);
		datafd = vde_datafd(conn);
		ctlfd = vde_ctlfd(conn);
		
		if (datafd < 0 || ctlfd < 0)
		{
			printlog(LOG_ERR, "Wrong file descriptor(s) for the VDE plug: (%d, %d)",
					datafd, ctlfd);
			exit(1);
		}

		FD_SET(datafd,&rs);
		FD_SET(ctlfd,&rs);
		if (datafd>nfds) nfds=datafd;
		if (ctlfd>nfds) nfds=ctlfd;
		result=select(nfds+1,&rs,&ws,&xs,NULL);
		//printf("SELECT %d %d\n",nfds,result);
		if (FD_ISSET(datafd,&rs)) {
			nx=vde_recv(conn,bufin,BUFSIZE,0);
		  //fprintf(stderr,"TX to slirp %d\n",nx);
			result--;
		  slirp_input(bufin,nx);
		  //fprintf(stderr,"TX to slirp %d exit\n",nx);
	  }
	  if (result > 0) {
		  //fprintf(stderr,"slirp poll\n");
		  slirp_select_poll(&rs,&ws,&xs);
		  //fprintf(stderr,"slirp poll exit\n");
	  }
		if (FD_ISSET(ctlfd,&rs)) {
			if(read(ctlfd,bufin,BUFSIZE)==0)
				exit(0);
		}
  }
  return(0);
}
