/* Copyright 2003 Renzo Davoli 
 * Licensed under the GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <libslirp.h>
#include <getopt.h>

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define ETH_ALEN 6

int dhcpmgmt=0;

enum request_type { REQ_NEW_CONTROL };

struct request_v3 {
  uint32_t magic;
  uint32_t version;
  enum request_type type;
  struct sockaddr_un sock;
};

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

struct pollfd pollv[]={{STDIN_FILENO,POLLIN|POLLHUP,0},{0,POLLIN|POLLHUP,0}};

char *filename;
char numfd[10];

int slirp_can_output(void)
{
	return 1;
}

static int fddata;
static struct sockaddr_un dataout;

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
	sendto(fddata,pkt,pkt_len,0,(struct sockaddr *) &dataout, sizeof(struct sockaddr_un));
}

void usage(char *name) {
	fprintf(stderr,"Usage: %s [-socket vdesock] [-dhcp] [-network netaddr] \n\t%s [-s vdesock] [-d] [-n netaddr]",name);
	exit(-1);
}

struct option slirpvdeopts[] = {
	{"socket",1,NULL,'s'},
	{"unix",1,NULL,'s'},
	{"dhcp",0,NULL,'d'},
	{"network",0,NULL,'n'},
	{NULL,0,0,0}};

int main(int argc, char **argv)
{
  char *sockname;
  struct sockaddr_un datain;
  int datainsize;
  int result,nfds;
  int group=0;
  int connected_fd;
  register ssize_t nx;
  register int i;
  fd_set rs,ws,xs;
  int opt,longindx;
  char *netw=NULL;

  filename=basename(argv[0]);
  sockname="/tmp/vde.ctl";

  while ((opt=getopt_long_only(argc,argv,"s:n:d",slirpvdeopts,&longindx)) > 0) {
	  switch (opt) {
		  case 's' : sockname=optarg;
			     break;
		  case 'd' : dhcpmgmt = 1;
			     break;
		  case 'n' : netw=optarg;
			     break;
	          default  : usage(filename);
			     break;
	  }
  }

  if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
    perror("socket");
    exit(1);
  }
  connected_fd=send_fd(sockname, fddata, &dataout, group);
  slirp_init(netw);

  for(;;) {
	  FD_ZERO(&rs);
	  FD_ZERO(&ws);
	  FD_ZERO(&xs);
	  nfds= -1;
	  slirp_select_fill(&nfds,&rs,&ws,&xs);
	  FD_SET(fddata,&rs);
	  if (fddata>nfds) nfds=fddata;
	  result=select(nfds+1,&rs,&ws,&xs,NULL);
	  //printf("SELECT %d %d\n",nfds,result);
	  if (FD_ISSET(fddata,&rs)) {
		  nx=recvfrom(fddata,bufin,BUFSIZE,0,(struct sockaddr *) &datain, &datainsize);
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
  }
  return(0);
}
