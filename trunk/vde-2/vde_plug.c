/* Copyright 2002 Renzo Davoli 
 * Licensed under the GPL
 */

#include <config.h>
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
#include <linux/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <vde.h>
#ifdef VDE_IP_LOG
#define DO_SYSLOG
#endif
#ifdef DO_SYSLOG
#include <syslog.h>
#include <ctype.h>
#include <arpa/inet.h>
#endif

#define MIN(X,Y) (((X)<(Y))?(X):(Y))
#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define MAXDESCR 128
#define ETH_ALEN 6

enum request_type { REQ_NEW_CONTROL };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
};

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

void splitpacket(const unsigned char *buf,int size,int fd, struct sockaddr_un *pd)
{
	static unsigned char fragment[BUFSIZE];
	static unsigned char *fragp;
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
			sendto(fd,fragment,rnx,0,(struct sockaddr *) pd,sizeof(struct sockaddr_un));

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
			sendto(fd,buf,rnx,0,(struct sockaddr *) pd,sizeof(struct sockaddr_un));
			buf+=rnx;
			size-=rnx;
			rnx=0;
		}
	}
}

static struct sockaddr_un inpath;

static int send_fd(char *name, int fddata, struct sockaddr_un *datasock, int port, char *g, int m)
{
	int pid = getpid();
	struct request_v3 req;
	int fdctl;
	int gid;
	struct group *gs;
	static struct sockaddr_un sock;

	if((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit(1);
	}

	if (name == NULL)
		name=VDESTDSOCK;
	else {
		char *split;
		if(name[strlen(name)-1] == ']' && (split=rindex(name,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (*name==0) name=VDESTDSOCK;
		}
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
	if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
		if (name == VDESTDSOCK) {
			name=VDETMPSOCK;
			snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
			if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
				snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name);
				if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
					perror("connect");
					exit(1);
				}
			}
		}
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=REQ_NEW_CONTROL+(port << 8);
	req.sock.sun_family=AF_UNIX;

	/* First choice, return socket from the switch close to the control dir*/
	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	sprintf(req.sock.sun_path, "%s.%05d-%02d", name, pid, 0);
	if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0){
		/* if it is not possible -> /tmp */
		memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
		sprintf(req.sock.sun_path, "/tmp/vde.%05d-%02d", pid, 0);
		if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0) {
			perror("bind");
			exit(1);
		}
	}

	snprintf(req.description,MAXDESCR,"vde_plug user=%s PID=%d %s SOCK=%s",
			callerpwd->pw_name,pid,getenv("SSH_CLIENT")?getenv("SSH_CLIENT"):"",req.sock.sun_path);
	memcpy(&inpath,&req.sock,sizeof(req.sock));
	if (send(fdctl,&req,sizeof(req)-MAXDESCR+strlen(req.description),0) < 0) {
		perror("send");
		exit(1);
	}

	if (recv(fdctl,datasock,sizeof(struct sockaddr_un),0)<0) {
		perror("recv");
		exit(1);
	}

	if (g) {
		if ((gs=getgrnam(g)) == NULL)
			gid=atoi(g);
		else
			gid=gs->gr_gid;
		chown(inpath.sun_path,-1,gid);
	}
	if (m>=0)
		chmod(inpath.sun_path,m);
	return fdctl;
}

static void cleanup(void)
{
  unlink(inpath.sun_path);
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
	int fddata;
	struct sockaddr_un dataout;
	struct sockaddr_un datain;
	static char *sockname=NULL;
	unsigned int datainsize;
	int result;
	int port=0;
	int connected_fd;
	register ssize_t nx;
	char *group=NULL;
	int mode=0700;

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
			c = getopt_long_only (argc, argv, "hc:p:s:m:g:l",
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
					port=atoi(optarg);
					if (port <= 0 || port > 255 )
						usage(argv[0]); //implies exit
					break;

				case 'h':
					usage(argv[0]); //implies exit
					break;

				case 's':
					sockname=strdup(optarg);
					break;

				case 'm':
					sscanf(optarg,"%o",&mode);
					break;

				case 'g':
					group=strdup(optarg);
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
	if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(1);
	}
	connected_fd=send_fd(sockname, fddata, &dataout, port, group, mode);

	pollv[1].fd=fddata;
	pollv[2].fd=connected_fd;

	for(;;) {
		result=poll(pollv,3,-1);
		if ((pollv[0].revents | pollv[1].revents | pollv[2].revents) & POLLHUP ||
				pollv[2].revents & POLLIN)
			break;
		if (pollv[0].revents & POLLIN) {
			nx=read(STDIN_FILENO,bufin,sizeof(bufin));
			/* if POLLIN but not data it means that the stream has been
			 * closed at the other end */
			if (nx==0)
				break;
			splitpacket(bufin,nx,fddata,&dataout);
		}
		if (pollv[1].revents & POLLIN) {
			datainsize=sizeof(datain);
			nx=recvfrom(fddata,(char *)(bufin+2),BUFSIZE-2,0,(struct sockaddr *) &datain, &datainsize);
			if (nx<0)
				perror("vde_plug: recvfrom ");
			else
			{
				bufin[0]=nx >> 8;
				bufin[1]=nx & 0xff;
				write(STDOUT_FILENO,bufin,nx+2);
				//fprintf(stderr,"%s: SENT %d %x %x \n",myname,nx,bufin[0],bufin[1]);
			}
		}
	}

	return(0);
}
