/* Copyright 2002 Renzo Davoli 
 * Licensed under the GPL
 * Modified by Ludovico Gardenghi 2005
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>
#include <libvdeplug.h>

#ifdef VDE_IP_LOG
#define DO_SYSLOG
#endif
#ifdef DO_SYSLOG
#include <syslog.h>
#include <ctype.h>
#include <arpa/inet.h>
#endif

#ifndef MIN
#define MIN(X,Y) (((X)<(Y))?(X):(Y))
#endif

#define BUFSIZE 2048
#define ETH_ALEN 6

VDECONN *conn;

struct utsname me;
#define myname me.nodename

static struct passwd *callerpwd;
#ifdef DO_SYSLOG
static char host[256];

void write_syslog_entry(char *message)
{
	char *ssh_client;
	size_t ip_length;

	openlog("vde_plug", 0, LOG_USER);

	//get the caller IP address
	//TNX Giordani-Macchia code from vish.c
	if ((ssh_client=getenv("SSH_CLIENT"))!=NULL)
	{
		for (ip_length=0;ip_length<sizeof(host)&&ssh_client[ip_length]!=0&&!isspace(ssh_client[ip_length]);ip_length++);
		if (ip_length>=sizeof(host))
			ip_length=sizeof(host)-1;
		memcpy(host,ssh_client,ip_length);
		host[ip_length]=0;
	}
	else
		strcpy(host,"UNKNOWN_IP_ADDRESS");
	syslog(LOG_INFO,"%s: user %s IP %s",message,callerpwd->pw_name,host);
	closelog();
}

void write_syslog_close()
{
	write_syslog_entry("STOP");
}
#endif

#ifdef VDE_IP_LOG
#define MAX_IP 256
int vde_ip_log;

struct header {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

union body {
	struct {
		unsigned char version;
		unsigned char filler[11];
		unsigned char ip4src[4];
		unsigned char ip4dst[4];
	} v4;
	struct {
		unsigned char version;
		unsigned char filler[7];
		unsigned char ip6src[16];
		unsigned char ip6dst[16];
	} v6;
	struct {
		unsigned char priovlan[2];
	} vlan;
};

unsigned char ip4list[MAX_IP][4];
unsigned char ip6list[MAX_IP][16];
static unsigned char nulladdr[16];

static int hash4(unsigned char *addr)
{
	return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]) % MAX_IP);
}

static int hash6(unsigned char *addr)
{
	return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]+
				7*addr[4]+11*addr[5]+13*addr[6]+17*addr[7]+
				19*addr[8]+23*addr[9]+29*addr[10]+31*addr[11]+
				37*addr[12]+41*addr[13]+43*addr[14]+47*addr[15]) % MAX_IP);
}

static void vde_ip_check(const unsigned char *buf,int rnx) 
{
	struct header *ph=(struct header *) buf;
	register int i,j,vlan=0;
	char addr[256];
	union body *pb;

	pb=(union body *)(ph+1);
	if (ph->proto[0]==0x81 && ph->proto[1]==0x00) { /*VLAN*/
		vlan=((pb->vlan.priovlan[0] << 8) + pb->vlan.priovlan[1]) & 0xfff;
		pb=(union body *)(((char *)pb)+4);
	}
	if (ph->proto[0]==0x08 && ph->proto[1]==0x00 && 
			pb->v4.version == 0x45) {
		/*v4 */ 
		i=hash4(pb->v4.ip4src);
		j=(i+MAX_IP-1)%MAX_IP;
		while (1) {
			/* most frequent case first */
			if (memcmp(pb->v4.ip4src,ip4list[i],4) == 0)
				break;
			else if (memcmp(ip4list[i],nulladdr,4) == 0) {
				memcpy(ip4list[i],pb->v4.ip4src,4);
				syslog(LOG_INFO,"user %s Real-IP %s has got VDE-IP4 %s on vlan %d",callerpwd->pw_name,host,inet_ntop(AF_INET,ip4list[i],addr,256),vlan);
				/*new ipv4*/
				break;
			} else if (i==j) {
				syslog(LOG_ERR,"IPv4 table full. Exiting\n");
				/*full table*/
				exit(-1);
			} else 
				i= (i+1)%MAX_IP;
		}
	}
	else if (ph->proto[0]==0x86 && ph->proto[1]==0xdd && 
			pb->v4.version == 0x60) {
		/* v6 */
		i=hash6(pb->v6.ip6src);
		j=(i+MAX_IP-1)%MAX_IP;
		while (1) {
			/* most frequent case first */
			if (memcmp(pb->v6.ip6src,ip6list[i],16) == 0)
				break;
			else if (memcmp(ip6list[i],nulladdr,16) == 0) {
				memcpy(ip6list[i],pb->v6.ip6src,16);
				syslog(LOG_INFO,"user %s Real-IP %s has got VDE-IP6 %s on vlan %d",callerpwd->pw_name,host,inet_ntop(AF_INET6,ip6list[i],addr,256),vlan);
				/*new ipv6*/
				break;
			} else if (i==j) {
				syslog(LOG_ERR,"IPv6 table full. Exiting\n");
				/*full table*/
				exit(-1);
			} else 
				i= (i+1)%MAX_IP;
		}
	}
}
#endif

unsigned char bufin[BUFSIZE];

void splitpacket(const unsigned char *buf,int size,VDECONN *conn)
{
	static char fragment[BUFSIZE];
	static char *fragp;
	static unsigned int rnx,remaining;

	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",myname,rnx,remaining,size);
	if (size==0) return;
	if (rnx>0) {
		register int amount=MIN(remaining,size);
		//fprintf(stderr,"%s: fragment amount %d\n",myname,amount);
		memcpy(fragp,buf,amount);
		remaining-=amount;
		fragp+=amount;
		buf+=amount;
		size-=amount;
		if (remaining==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",myname,rnx);
			//send(fd,fragment,rnx,0);
#ifdef VDE_IP_LOG
			if (vde_ip_log)
				vde_ip_check(buf,rnx);
#endif
			vde_send(conn,fragment,rnx,0);
			rnx=0;
		}
	}
	while (size > 0) {
		rnx=(buf[0]<<8)+buf[1];
		size-=2;
		//fprintf(stderr,"%s %d: packet %d size %d %x %x\n",myname,getpid(),rnx,size,buf[0],buf[1]);
		buf+=2;
		if (rnx>1521) {
			fprintf(stderr,"%s: Packet length error size %d rnx %d\n",myname,size,rnx);
			rnx=0;
			return;
		}
		if (rnx > size) {
			//fprintf(stderr,"%s: begin defrag %d\n",myname,rnx);
			fragp=fragment;
			memcpy(fragp,buf,size);
			remaining=rnx-size;
			fragp+=size;
			size=0;
		} else {
			//fprintf(stderr,"%s: deliver %d\n",myname,rnx);
			//send(fd,buf,rnx,0);
#ifdef VDE_IP_LOG
			if (vde_ip_log)
				vde_ip_check(buf,rnx);
#endif
			vde_send(conn,(char *)buf,rnx,0);
			buf+=rnx;
			size-=rnx;
			rnx=0;
		}
	}
}

static void cleanup(void)
{
  vde_close(conn);
}

static void sig_handler(int sig)
{
	cleanup();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

static void setsighandlers()
{
	/* setting signal handlers.
	 * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 * ignores all the others signals which could cause termination. */
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
}

struct pollfd pollv[]={{STDIN_FILENO,POLLIN|POLLHUP},{0,POLLIN|POLLHUP},{0,POLLIN|POLLHUP}};

static void netusage() {
#ifdef DO_SYSLOG
	write_syslog_entry("FAILED");
#endif
	fprintf (stderr,"This is a Virtual Distributed Ethernet (vde) tunnel broker. \n"
			"This is not a login shell, only vde_plug can be executed\n");
	exit(-1);
}

static void usage(char *progname) {
	fprintf (stderr,"Usage: %s [-p portnum] [-g group] [-m mod] socketname\n\n",progname);
	exit(-1);
}

int main(int argc, char **argv)
{
	static char *sockname=NULL;
	int result;
	register ssize_t nx;
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};

	uname(&me);
	//get the login name
	callerpwd=getpwuid(getuid());

	if (argv[0][0] == '-')
		netusage(); //implies exit
	/* option parsing */
	{
		int c;
		while (1) {
			int option_index = 0;

			static struct option long_options[] = {
				{"sock", 1, 0, 's'},
				{"vdesock", 1, 0, 's'},
				{"unix", 1, 0, 's'},
				{"port", 1, 0, 'p'},
				{"help",0,0,'h'},
				{"mod",1,0,'m'},
				{"group",1,0,'g'},
				{0, 0, 0, 0}
			};
			c = GETOPT_LONG (argc, argv, "hc:p:s:m:g:l",
					long_options, &option_index);
			if (c == -1)
				break;

			switch (c) {
				case 'c':
					if (strcmp(optarg,"vde_plug")==0) {
#ifdef DO_SYSLOG
						write_syslog_entry("START");
						atexit(write_syslog_close);
#ifdef VDE_IP_LOG
						vde_ip_log=1;
#endif
#endif

					}
					else
						netusage(); //implies exit
					break;

				case 'p':
					open_args.port=atoi(optarg);
					if (open_args.port <= 0)
						usage(argv[0]); //implies exit
					break;

				case 'h':
					usage(argv[0]); //implies exit
					break;

				case 's':
					sockname=strdup(optarg);
					break;

				case 'm': 
					sscanf(optarg,"%o",&(open_args.mode));
					break;

				case 'g':
					open_args.group=strdup(optarg);
					break;

				case 'l':
#ifdef VDE_IP_LOG
					write_syslog_entry("START");
					atexit(write_syslog_close);
					vde_ip_log=1;
					break;
#endif

				default:
					usage(argv[0]); //implies exit
			}
		}

		if (optind < argc && sockname==NULL)
			sockname=argv[optind];
	}
	atexit(cleanup);
	setsighandlers();
	conn=vde_open(sockname,"vde_plug:",&open_args);
	if (conn == NULL)
		exit(1);

	pollv[1].fd=vde_datafd(conn);
	pollv[2].fd=vde_ctlfd(conn);

	for(;;) {
		result=poll(pollv,3,-1);
		if ((pollv[0].revents | pollv[1].revents | pollv[2].revents) & POLLHUP ||
				pollv[2].revents & POLLIN)
			break;
		if (pollv[0].revents & POLLIN) {
			nx=read(STDIN_FILENO,bufin,sizeof(bufin));
			/* if POLLIN but not data it means that the stream has been
			 * closed at the other end */
			/*fprintf(stderr,"%s: RECV %d %x %x \n",myname,nx,bufin[0],bufin[1]);*/
			if (nx==0)
				break;
			splitpacket(bufin,nx,conn);
		}
		if (pollv[1].revents & POLLIN) {
			nx=vde_recv(conn,(char *)(bufin+2),BUFSIZE-2,0);
			if (nx<0)
				perror("vde_plug: recvfrom ");
			else
			{
				bufin[0]=nx >> 8;
				bufin[1]=nx & 0xff;
				write(STDOUT_FILENO,bufin,nx+2);
				/*fprintf(stderr,"%s: SENT %d %x %x \n",myname,nx,bufin[0],bufin[1]);*/
			}
		}
	}

	return(0);
}
