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

#include <slirp.h>
#include <libvdeplug.h>
//#include "misc.h"
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

#define DEFAULT_IP_ADDR "10.0.2.2"

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 4096
#define ETH_ALEN 6

struct Slirp *slirp;
struct in_addr vnetwork;
struct in_addr vnetmask;
struct in_addr vhost;
struct in_addr vdhcp_start;
struct in_addr vnameserver;

VDECONN *conn;
VDESTREAM *vdestream;
int dhcpmgmt=0;
static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];
int logok=0;
char *prog;

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
		strncat(pidfile_path, pidfile, sizeof(pidfile_path) - strlen(pidfile_path) -1);
	else {
		pidfile_path[0] = 0;
		strncat(pidfile_path, pidfile, sizeof(pidfile_path)-1);
	}

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
	if (vdestream != NULL)
		vdestream_close(vdestream);
	if (conn != NULL)
		vde_close(conn);
}

unsigned char bufin[BUFSIZE];

int slirp_can_output(void *opaque)
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

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len)
{
	/* slirp -> vde */
	//fprintf(stderr,"RX from slirp %d\n",pkt_len);
	//dumppkt(pkt,pkt_len);
	if (vdestream == NULL)
		vde_send(conn,pkt,pkt_len,0);
	else
		vdestream_send(vdestream, pkt, pkt_len);
}

#define IS_TCP 0
#define IS_UDP 1
static char *tcpudp[]={"TCP","UDP"};

struct redir_tcp_udp {
	struct in_addr inaddr;
	int is_udp;
	int port;
	int lport;
	struct redir_tcp_udp *next;
};

struct redirx {
	struct in_addr inaddr;
	int start_port;
	int display;
	int screen;
	struct redirx *next;
};

static struct redir_tcp_udp *parse_redir_tcp(struct redir_tcp_udp *head, char *buff,int is_udp)
{
	u_int32_t inaddr=0;
	int port=0;
	int lport=0;
	char *ipaddrstr=NULL;
	char *portstr=NULL;
	struct redir_tcp_udp *new;
			
	if ((ipaddrstr = strchr(buff, ':'))==NULL || *(ipaddrstr+1)==0) {
			fprintf(stderr,"redir %s syntax error\n",tcpudp[is_udp]);
			return head;
	}
	*ipaddrstr++ = 0;

	if ((portstr = strchr(ipaddrstr, ':'))==NULL || *(portstr+1)==0) {
		fprintf(stderr,"redir %s syntax error\n",tcpudp[is_udp]);
		return head;
	}
	*portstr++ = 0;

	sscanf(buff,"%d",&lport);
	sscanf(portstr,"%d",&port);
	if (ipaddrstr) 
		inaddr = inet_addr(ipaddrstr);

	if (!inaddr) {
		fprintf(stderr,"%s redirection error: an IP address must be specified\n",tcpudp[is_udp]);
		return head;
	}

	if ((new=malloc(sizeof(struct redir_tcp_udp)))==NULL)
		return head;
	else {
		inet_aton(ipaddrstr,&new->inaddr);
		new->is_udp=is_udp;
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
		inet_aton(buff,&new->inaddr);
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

static void do_redir_tcp(struct redir_tcp_udp *head, int quiet)
{
	struct in_addr host_addr={.s_addr=htonl(INADDR_ANY)};
	if (head) {
		do_redir_tcp(head->next,quiet);
		if (slirp_add_hostfwd(slirp, head->is_udp, host_addr, head->lport, head->inaddr,head->port) >= 0) {
			if (!quiet)
				lprint("                   redir %s   =%d:%s:%d\n", 
						tcpudp[head->is_udp],head->lport,inet_ntoa(head->inaddr),head->port);
		}
		free(head);
	}
}

static void do_redir_x(struct redirx *head, int quiet)
{
	struct in_addr host_addr={.s_addr=htonl(INADDR_ANY)};
	if (head) {
		do_redir_x(head->next,quiet);
		int i;

		//redir_x(head->inaddr,head->start_port,head->display,head->screen);
		for (i = 6000 + head->start_port; i <= 6100; i++) {
			if (slirp_add_hostfwd(slirp, IS_TCP, host_addr, htons(i), 
						head->inaddr, htons(6000 + head->display)) == 0) {
				if (!quiet)
					lprint("                   redir X     =%s:%d.%d\n", 
							inet_ntoa(head->inaddr),head->display,head->screen);
				break;
			}
		}
		free(head);
	}
}

static ssize_t vdeslirp_plug_recv(void *opaque, void *buf, size_t count)
{
	struct Slirp *slirp=opaque;
	slirp_input(slirp,(uint8_t *)buf,count);
	return count;
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

int main(int argc, char **argv)
{
  char *sockname=NULL;
  int result,nfds;
  register ssize_t nx;
  /*register int i;*/
  fd_set rs,ws,xs;
  int opt,longindx;
	int daemonize=0;
	struct redir_tcp_udp *rtcp=NULL;
	struct redirx *rx=NULL;
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
	char *tftp_path=NULL;
	int maskbits=24;
	int datafd=0,ctlfd=0;
	int quiet=0;
	
	static struct option slirpvdeopts[] = {
		{"socket",required_argument,NULL,'s'},
		{"sock",required_argument,NULL,'s'},
		{"vdesock",required_argument,NULL,'s'},
		{"unix",required_argument,NULL,'s'},
		{"pidfile", required_argument, NULL, 'p'},
		{"dhcp",optional_argument,NULL,'D'},
		{"daemon",no_argument,NULL,'d'},
		{"network",required_argument,NULL,'n'},
		{"nameserver",required_argument,NULL,'N'},
		{"dns",required_argument,NULL,'N'},
		{"host",required_argument,NULL,'H'},
		{"mod",required_argument,NULL,'m'},
		{"group",required_argument,NULL,'g'},
		{"port",required_argument,NULL,'P'},
		{"tftp",required_argument,NULL,'t'},
		{"quiet",no_argument,NULL,'q'},
		{"help",no_argument,NULL,'h'},
		{NULL,no_argument,NULL,0}};

	inet_aton(DEFAULT_IP_ADDR,&vhost);

  prog=basename(argv[0]);

  while ((opt=GETOPT_LONG(argc,argv,"Ds:n:H:p:g:m:L:U:X:x:t:N:dqh",slirpvdeopts,&longindx)) > 0) {
		switch (opt) {
			case 's' : sockname=optarg;
								 break;
			case 'D' : dhcpmgmt = 1;
								 if (optarg != NULL)
									 inet_aton(optarg,&vdhcp_start);
								 break;
			case 'd' : daemonize = 1;
								 break;
			case 'H' :
			case 'n' : {
									 char *slash=strchr(optarg,'/');
									 if (slash) {
										 maskbits=atoi(slash+1);
										 *slash=0;
									 }
									 inet_aton(optarg,&vhost);
								 }
								 break;
			case 'N' : inet_aton(optarg,&vnameserver);
								 break;
			case 'm' : sscanf(optarg,"%o",&(open_args.mode));
								 break;
			case 'g' : open_args.group=strdup(optarg);
								 break;
			case 'p':  pidfile=strdup(optarg);
								 break;
			case 'P' : open_args.port=atoi(optarg);
								 break;
			case 'L': rtcp=parse_redir_tcp(rtcp,optarg,IS_TCP);
								 break;
			case 'U': rtcp=parse_redir_tcp(rtcp,optarg,IS_UDP);
								 break;
			case 'X': rx=parse_redir_x(rx,optarg);
								 break;
			case 'x': parse_redir_locx(optarg);
								 break;
			case 't': tftp_path=strdup(optarg);
								break;
			case 'q': quiet=1;
								break;
			default  : usage(prog);
								 break;
		}
  }

	if (optind < argc && sockname==NULL)
		sockname=argv[optind++];

	if (optind < argc)
			usage(prog);

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
	
	if (sockname==NULL || strcmp(sockname,"-") != 0) {
		conn=vde_open(sockname,"slirpvde:",&open_args);
		if (!conn)
		{
			printlog(LOG_ERR, "Could not connect to the VDE switch at '%s': %s",
					sockname, strerror(errno));
			exit(1);
		}
		datafd = vde_datafd(conn);
		ctlfd = vde_ctlfd(conn);

		if (datafd < 0 || ctlfd < 0)
		{
			printlog(LOG_ERR, "Wrong file descriptor(s) for the VDE plug: (%d, %d)",
					datafd, ctlfd);
			exit(1);
		}

		strncat(pidfile_path, "/", sizeof(pidfile_path) - strlen(pidfile_path) -1);
		if (daemonize && daemon(0, 0)) {
			printlog(LOG_ERR,"daemon: %s",strerror(errno));
			exit(1);
		}
	}

	if(pidfile) save_pidfile();

	vnetmask.s_addr=htonl(~((1<< (32-maskbits)) - 1));
	vnetwork.s_addr=vhost.s_addr & vnetmask.s_addr;
	if ((vhost.s_addr & ~vnetmask.s_addr) == 0)
		    vhost.s_addr=htonl(ntohl(vnetwork.s_addr) | 2);
	if (vdhcp_start.s_addr == 0 && dhcpmgmt)
		vdhcp_start.s_addr=htonl(ntohl(vnetwork.s_addr) | 15);
	if (vnameserver.s_addr == 0)
		vnameserver.s_addr=htonl(ntohl(vnetwork.s_addr) | 3);

	/* netw */
	slirp = slirp_init(0, vnetwork, vnetmask, vhost, NULL, tftp_path, NULL, 
			vdhcp_start, vnameserver, conn);

	if (sockname != NULL && strcmp(sockname,"-")==0) {
		vdestream=vdestream_open(slirp,STDOUT_FILENO,vdeslirp_plug_recv,NULL);
		if (vdestream == NULL)
		{
			printlog(LOG_ERR, "Could not connect to the PLUG: %s",
					strerror(errno));
			exit(1);
		}
		datafd=ctlfd=STDIN_FILENO;
		quiet=1;
	}

	if (!quiet) {
		lprint("Starting slirpvde: virtual_host=%s/%d\n", inet_ntoa(vhost), 
				maskbits);
		lprint("                   DNS         =%s\n", inet_ntoa(vnameserver));
		if (vdhcp_start.s_addr != 0)
			lprint("                   dhcp_start  =%s\n", inet_ntoa(vdhcp_start));
		if (tftp_path != NULL)
			lprint("                   tftp prefix =%s\n", tftp_path);
		lprint("                   vde switch  =%s\n", 
				(sockname == NULL)?"*DEFAULT*":sockname);
	}

	do_redir_tcp(rtcp,quiet);
	do_redir_x(rx,quiet);

	for(;;) {
		FD_ZERO(&rs);
		FD_ZERO(&ws);
		FD_ZERO(&xs);
		nfds= -1;
		slirp_select_fill(&nfds,&rs,&ws,&xs);
		
		FD_SET(datafd,&rs);
		FD_SET(ctlfd,&rs);
		if (datafd>nfds) nfds=datafd;
		if (ctlfd>nfds) nfds=ctlfd;
		result=select(nfds+1,&rs,&ws,&xs,NULL);
		if (conn != NULL) {
			//printf("SELECT %d %d\n",nfds,result);
			if (FD_ISSET(datafd,&rs)) {
				nx=vde_recv(conn,bufin,BUFSIZE,0);
				//fprintf(stderr,"TX to slirp %d\n",nx);
				//dumppkt(bufin,nx);
				result--;
				slirp_input(slirp,bufin,nx);
				//fprintf(stderr,"TX to slirp %d exit\n",nx);
			}
			if (result > 0) {
				//fprintf(stderr,"slirp poll\n");
				slirp_select_poll(&rs,&ws,&xs,0);
				//fprintf(stderr,"slirp poll exit\n");
			}
			if (FD_ISSET(ctlfd,&rs)) {
				if(read(ctlfd,bufin,BUFSIZE)==0)
					exit(0);
			}
		} else { /* vdestream != NULL */
			if (FD_ISSET(datafd,&rs)) {
				nx=read(datafd,bufin,BUFSIZE);
				if (nx==0)
					exit(0);
				vdestream_recv(vdestream, bufin, nx);
				result--;
			}
			if (result > 0) {
				//fprintf(stderr,"slirp poll\n");
				slirp_select_poll(&rs,&ws,&xs,0);
				//fprintf(stderr,"slirp poll exit\n");
			}
		}
	}
  return(0);
}
