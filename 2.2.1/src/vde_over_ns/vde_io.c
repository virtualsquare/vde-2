/* ----------------------------------------------------------------------------
 *
    VDE_OVER_NS 
	(C) 2007 Daniele Lacamera

    Derived from:
    NSTX -- tunneling network-packets over DNS

     (C) 2000 by Florian Heinz and Julien Oster

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  -------------------------------------------------------------------------- */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "fun.h"

#define MAXPKT 2000


static int ifd,ofd,nfd;
VDECONN *vconn = NULL;

void
init_vdesock(char *s)
{
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
	if(s){
		vconn = vde_open(s,"vde_over_ns",&open_args);
		if(!vconn){
			fprintf(stderr,"Fatal Error. Vdeplug %s: %s\n",s,strerror(errno));
			exit(1);
		}
		ifd = ofd = vde_datafd(vconn);
		return;	
	}
	
	ifd = STDIN_FILENO, ofd = STDOUT_FILENO, nfd = -1;
}

void
open_ns(const char *ip)
{
	struct sockaddr_in sock = { 0 };
   
	fprintf(stderr, "Opening nameserver-socket... ");
	if ((nfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("failed!\nUnexpected error creating socket");
		exit(EX_OSERR);
	}
	sock.sin_family = AF_INET;
	sock.sin_port = htons(53);
	sock.sin_addr.s_addr = inet_addr(ip);
	if (connect(nfd, (struct sockaddr *)&sock,
	    sizeof(struct sockaddr_in))) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Using nameserver %s\n", ip);
}

void
open_ns_bind(in_addr_t bindip)
{
	struct sockaddr_in sock = { 0 };
   
	fprintf(stderr, "Opening nameserver-socket... ");
	if ((nfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("failed!\nUnexpected error creating socket");
		exit(EX_OSERR);
	}
	sock.sin_family = AF_INET;
	sock.sin_port = htons(53);
 
	sock.sin_addr.s_addr = bindip;
	if (bind (nfd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) {
	   fprintf(stderr, "failed!\n");
	   switch (errno) {
	    case EADDRINUSE:
	      fprintf(stderr, "Address is in use, please kill other processes "
		      "listening on UDP-Port 53 on %s\n",
		      bindip == INADDR_ANY ?
			"all local IPs" : "the specified IP");
	      break;
	    case EACCES:
	    case EPERM:
	      fprintf(stderr, "Permission denied binding port 53. You generally "
		      "have to be root to bind privileged ports.\n");
	      break;
	    default:
	      fprintf(stderr, "Unexpected error: bind: %s\n", strerror(errno));
	      break;
	   }
	   exit(EXIT_FAILURE);
	}
	fprintf(stderr, "listening on 53/UDP\n");
}

struct nstxmsg *nstx_select (int timeout)
{
   unsigned peerlen;
   int c,pollret;
   struct pollfd pfd[2];
   static struct nstxmsg *ret = NULL;
   u_int16_t vde_len;
   pfd[0].fd=ifd;
   pfd[1].fd=nfd;
   pfd[0].events=pfd[1].events= POLLIN | POLLHUP;
for(;;){
  pollret=poll(pfd,2,1000);
  if(pollret<0){
	  perror("poll");
	  exit(1);
  }
  if (!ret)
	  ret = malloc(sizeof(struct nstxmsg));
  if (pfd[0].revents&POLLIN) {
	  
	if(vconn!=NULL){
		ret->len = vde_recv(vconn,ret->data,MAXPKT,0);
	}else{
		c=read(ifd,ret->data,2);
		if(c<2) 
			return NULL;
		vde_len=0;
		vde_len+=((unsigned char)(ret->data[0]))<<8;
		vde_len+=(unsigned char)(ret->data[1]);
	  
		ret->len=2;
		while(ret->len < (vde_len + 2)){
		ret->len += read(ifd, ret->data+ret->len, ((vde_len+2) - ret->len));
	  }
	}
	// fprintf(stderr,"Read %d.\n",vde_len);

	ret->src = FROMTUN;
	return ret;
		
  }
  
  if (pfd[1].revents&POLLIN) {
	  peerlen = sizeof(struct sockaddr_in);
	  ret->len = recvfrom(nfd, ret->data, MAXPKT, 0,
			  (struct sockaddr *) &ret->peer, &peerlen);
	  if(ret->len > 0){
	  
#ifdef WITH_PKTDUMP
		  pktdump("/tmp/nstx/pkt.", *((unsigned short *)ret->data),
				  ret->data, ret->len, 0);
#endif
		  ret->src = FROMNS;
		  return ret;
 	 }
  }
}
  return NULL;
}

  

void
send_vde(const char *data, size_t len)
  {
	static unsigned int outbuf[MAXPKT];
	static int outp;
	static u_int16_t outlen;
	if(len<=0)
		return;
	if (vconn!=NULL){
		vde_send(vconn,data,len,0);
		return;
	}
	if(outp==0 && (len >=2) ){
		outlen=2;
		outlen+=(unsigned char)data[1];
		outlen+=((unsigned char)(data[0]))<<8;
	}
	
	if(len>=outlen){
		write(ofd,data,outlen);
		send_vde(data+outlen,len-outlen);
		return;
	}
		
	memcpy(outbuf+outp,data,len);
	outp+=len;
	if(outp>=outlen){
		write(ofd,outbuf,outlen);
		outp=0;
	}			
 }
	 

void
sendns (const char *data, size_t len, const struct sockaddr *peer)
{
   if (peer)
     sendto(nfd, data, len, 0, peer,
	    sizeof(struct sockaddr_in));
   else
     send(nfd, data, len, 0);
#ifdef WITH_PKTDUMP
   pktdump("/tmp/nstx/pkt.", *((unsigned short *)data), data, len, 1);
#endif
}
