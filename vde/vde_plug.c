/* Copyright 2003 Renzo Davoli 
 * Licensed under the GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include "vde.h"
#ifdef VDE_IP_LOG
#define DO_SYSLOG
#endif
#ifdef DO_SYSLOG
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>
#include <ctype.h>
#include <arpa/inet.h>
#endif

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define ETH_ALEN 6

enum request_type { REQ_NEW_CONTROL };

struct request_v3 {
  uint32_t magic;
  uint32_t version;
  enum request_type type;
  struct sockaddr_un sock;
};

struct utsname me;
#define myname me.nodename

#ifdef DO_SYSLOG
static struct passwd *callerpwd;
static char host[256];

void write_syslog_entry(char *message)
{
	char *ssh_client;
	size_t ip_length;

	openlog("vde_plug", 0, LOG_USER);

	//get the login name
	callerpwd=getpwuid(getuid());

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

struct packet {
	struct {
		unsigned char dest[ETH_ALEN];
		unsigned char src[ETH_ALEN];
		unsigned char proto[2];
	} header;
	union {
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
	} body;
};

unsigned char ip4list[MAX_IP][4];
unsigned char ip6list[MAX_IP][16];
static unsigned char nulladdr[16];

static int hash4(char *addr)
{
	return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]) % MAX_IP);
}
	
static int hash6(char *addr)
{
	return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]+
	7*addr[4]+11*addr[5]+13*addr[6]+17*addr[7]+
	19*addr[7]+23*addr[8]+29*addr[9]+31*addr[10]+
	37*addr[7]+41*addr[8]+43*addr[9]+47*addr[10]) % MAX_IP);
}
	
static void vde_ip_check(const char *buf,int rnx) 
{
	struct packet *p=(struct packet *) buf;
	register int i,j;
	char addr[256];

	if (p->header.proto[0]==0x08 && p->header.proto[1]==0x00 && 
			p->body.v4.version == 0x45) {
		/*v4 */ 
		i=hash4(p->body.v4.ip4src);
		j=(i+MAX_IP-1)%MAX_IP;
		while (1) {
			/* more frequent case first */
			if (memcmp(p->body.v4.ip4src,ip4list[i],4) == 0)
				break;
			else if (memcmp(ip4list[i],nulladdr,4) == 0) {
				memcpy(ip4list[i],p->body.v4.ip4src,4);
				syslog(LOG_INFO,"user %s Real-IP %s has got VDE-IP4 %s",callerpwd->pw_name,host,inet_ntop(AF_INET,ip4list[i],addr,256));
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
	else if (p->header.proto[0]==0x86 && p->header.proto[1]==0xdd && 
			p->body.v4.version == 0x60) {
		/* v6 */
		i=hash6(p->body.v6.ip6src);
		j=(i+MAX_IP-1)%MAX_IP;
		while (1) {
			/* more frequent case first */
			if (memcmp(p->body.v6.ip6src,ip6list[i],16) == 0)
				break;
			else if (memcmp(ip6list[i],nulladdr,16) == 0) {
				memcpy(ip6list[i],p->body.v6.ip6src,16);
				syslog(LOG_INFO,"user %s Real-IP %s has got VDE-IP6 %s",callerpwd->pw_name,host,inet_ntop(AF_INET6,ip6list[i],addr,256));
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

static int send_fd(char *name, int fddata, struct sockaddr_un *datasock, int group)
{
  int pid = getpid();
  struct request_v3 req;
  int fdctl;

  struct sockaddr_un sock;

  if((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }

  sock.sun_family = AF_UNIX;
  snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name);
  if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
    perror("connect");
    exit(1);
  }

  req.magic=SWITCH_MAGIC;
  req.version=3;
  req.type=REQ_NEW_CONTROL+((group > 0)?((geteuid()<<8) + group) << 8:0);
  
  req.sock.sun_family=AF_UNIX;
  memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
  sprintf(&req.sock.sun_path[1], "%5d", pid);

  if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0){
    perror("bind");
    exit(1);
  }

  if (send(fdctl,&req,sizeof(req),0) < 0) {
    perror("send");
    exit(1);
  }

  if (recv(fdctl,datasock,sizeof(struct sockaddr_un),0)<0) {
	  perror("recv");
	  exit(1);
  }

  return fdctl;
}

unsigned char bufin[BUFSIZE];
#define MIN(X,Y) ((X)<(Y))?(X):(Y)

void splitpacket(const unsigned char *buf,int size,int fd, struct sockaddr_un *pd)
{
	static unsigned char fragment[BUFSIZE];
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
		       sendto(fd,fragment,rnx,0,(struct sockaddr *) pd,sizeof(struct sockaddr_un));

			rnx=0;
		}
	}
	while (size > 0) {
		rnx=(buf[0]<<8)+buf[1];
		size-=2;
		//fprintf(stderr,"%s: packet %d size %d %x %x\n",myname,rnx,size,buf[0],buf[1]);
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

struct pollfd pollv[]={{STDIN_FILENO,POLLIN|POLLHUP,0},{0,POLLIN|POLLHUP,0}};

static void netusage() {
#ifdef DO_SYSLOG
	write_syslog_entry("FAILED");
#endif
	fprintf (stderr,"This is a Virtual Distributed Ethernet (vde) tunnel broker. \n"
			"This is not a login shell, only vde_plug can be executed\n");
	exit(-1);
}

static void usage(char *progname) {
	fprintf (stderr,"Usage: %s [-g num] [socketname]\n   ( 0 < num < 256 )\n\n",progname);
	exit(-1);
}

int main(int argc, char **argv)
{
  int fddata;
  char *sockname=NULL;
  struct sockaddr_un dataout;
  struct sockaddr_un datain;
  int datainsize;
  int result;
  int group=0;
  int connected_fd;
  register ssize_t nx;

  uname(&me);
  if (argv[0][0] == '-')
	  netusage(); //implies exit
  sockname=VDESTDSOCK;
  /* option parsing */
  {
	  int c;
	  while (1) {
		  int option_index = 0;

		  static struct option long_options[] = {
			  {"group", 1, 0, 's'},
			  {"sock", 1, 0, 's'},
			  {"vdesock", 1, 0, 's'},
			  {"unix", 1, 0, 's'},
			  {"help",0,0,'h'},
			  {0, 0, 0, 0}
		  };
		  c = getopt_long_only (argc, argv, "c:g:s:l",
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

			  case 'g':
				  group=atoi(optarg);
				  if (group <= 0 || group > 255 )
					  usage(argv[0]); //implies exit
				  break;

			  case 'h':
			          usage(argv[0]); //implies exit
				  break;

			  case 's':
				  sockname=strdup(optarg);
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

	  if (optind < argc && sockname==VDESTDSOCK)
		  sockname=argv[optind];
  }
  if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
    perror("socket");
    exit(1);
  }
  connected_fd=send_fd(sockname, fddata, &dataout, group);
  pollv[1].fd=fddata;

  for(;;) {
	  result=poll(pollv,2,-1);
	  if (pollv[0].revents & POLLHUP || pollv[1].revents & POLLHUP)
		  break;
	  if (pollv[0].revents & POLLIN) {
		  nx=read(STDIN_FILENO,bufin,sizeof(bufin));
		  splitpacket(bufin,nx,fddata,&dataout);
		  //sendto(fddata,bufin,nx,0,(struct sockaddr *) &dataout,sizeof(dataout));

	  }
	  if (pollv[1].revents & POLLIN) {
		  datainsize=sizeof(datain);
		  nx=recvfrom(fddata,bufin+2,BUFSIZE-2,0,(struct sockaddr *) &datain, &datainsize);
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
