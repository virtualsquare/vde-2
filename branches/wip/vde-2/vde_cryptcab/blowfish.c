/*
 * Blowfish functions
 * Copyright © 2006 Daniele Lacamera
 * Released under the terms of GNU GPL v.2
 * http://www.gnu.org/copyleft/gpl.html
 *
 * This program is released under the GPL with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "compat/poll.h"
#include <sys/stat.h>
#include <sys/time.h>
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

#include <config.h>

#include "blowfish.h"
#include "crc32.h"

unsigned char *crc32(unsigned char*,int);
static unsigned long long mycounter=1;

static EVP_CIPHER_CTX ctx;
static int nfd = -1;
static struct peer *list=NULL;

static struct itimerval TIMER = {
	.it_interval={ .tv_sec=0, .tv_usec=0},
	.it_value={ .tv_sec=SESSION_TIMEOUT/2, .tv_usec=0 }
};

/*
 * Add a peer to the main list.
 * Client will have a list of one peer only,
 * server will have a peer in the list for each "connection"
 * it establishes.
 */

void addpeer(struct peer *np)
{
	np->next=list;
	list=np;

}

/*
 * Internal, recursive functions:
 */
static int _peers(struct peer *iter)
{
	if(!iter)
		return 0;
	else
		return 1+_peers(iter->next);
}

static void _populatepoll(struct pollfd *pfd, struct peer *iter,int index, struct peer *peerlist)
{
	int datafd;
	if(!iter)
		return;
	memcpy(&(peerlist[index]),iter,sizeof(struct peer));
	datafd=vde_datafd(iter->plug);
	if(datafd >= 0){
		pfd[index].fd=datafd;
		pfd[index++].events=POLLIN|POLLHUP;
	} else {
		vde_plug(iter);
		usleep(100000);
		_populatepoll(pfd,iter->next,index, peerlist);
		return;

	}
	
	_populatepoll(pfd,iter->next,index, peerlist);

}


struct peer *_getpeer(struct sockaddr_in saddr, struct peer *sublist)
{
	if(!sublist)
		return NULL;
	if(sublist->in_a.sin_addr.s_addr==saddr.sin_addr.s_addr && sublist->in_a.sin_port==saddr.sin_port)
		return sublist;
	return _getpeer(saddr,sublist->next);
	
}

struct peer *_getpeerbna(struct sockaddr_in saddr, struct peer *sublist)
{
	if(!sublist)
		return NULL;
	if(sublist->handover_a.sin_addr.s_addr==saddr.sin_addr.s_addr && sublist->handover_a.sin_port==saddr.sin_port)
		return sublist;
	return _getpeerbna(saddr,sublist->next);
	
}

static struct peer *_getpeerbyid(struct datagram *pkt, struct peer *sublist)
{
	if(pkt->len!=FILENAMESIZE+1)
		return NULL;
	if(!sublist)
		return NULL;
	if(strncmp((char *)pkt->data+1,sublist->id,FILENAMESIZE)==0)
		return sublist;
	return _getpeerbyid(pkt,sublist->next);
	
}


void 
set_expire(struct peer *p)
{
	gettimeofday(&(p->expire),NULL);
	p->expire.tv_sec+=SESSION_TIMEOUT;
}

/*
 * Check progressive number validity in incoming datagram
 */
int
isvalid_timestamp(unsigned char *block, int size, struct peer *p)
{
	
	
	int i;
	unsigned long long pktcounter=0;
	for(i=0;i<8;i++){
		pktcounter+=block[size-12+i]<<(i*8);
	}
	if(pktcounter>p->counter){
		p->counter=pktcounter;
		return 1;
	}else{
		//fprintf(stderr,"bad timestamp!\n");
		return 0;
	}
	
}

/*
 * Check CRC32 Checksum from incoming datagram
 */
int 
isvalid_crc32(unsigned char *block, int len)
{
	unsigned char *crc=(unsigned char *)crc32(block,len-4);
	if(strncmp((char*)block+(len-4),(char*)crc,4)==0){
		free(crc);
		return 1;
	}else{
			
		//fprintf(stderr,"bad crc32!\n");
		free(crc);
		return 0;
	}
}


/*
 * Returns peer list length.
 */

static int numberofpeers(){
	struct peer *iter=list;
	return _peers(iter);
}



struct peer *clean_peerlist(struct peer *sublist)
{
	if(!sublist)
		return NULL;

	if(sublist->state == ST_AUTH && vde_datafd(sublist->plug) < 0){
		struct peer *nxt=sublist->next;
		free(sublist);
		return nxt;
	}

	if(sublist->state == ST_AUTH){
		struct timeval now;
		gettimeofday(&now,NULL);
		
		if(after(now,sublist->expire)){
			struct peer *nxt=sublist->next;
			vde_close(sublist->plug);
			free(sublist);
			return nxt;
		}
	}

	sublist->next=clean_peerlist(sublist->next);
	return sublist;
}


void
autocleaner(int signo)
{
	struct itimerval *old=NULL;
	list=clean_peerlist(list);
	setitimer(ITIMER_REAL, &TIMER, old);
}

/*
 * Returns a list of all the peer in the peer list, adding their 
 * network socket to pollfd.
 * This is called in blowfish_select, to populate the pollfd structure.
 */
static struct peer *populate_peerlist(struct pollfd *pfd)
{
	static struct peer *iter, *peerlist;
	iter=list; //=clean_peerlist(list);
	if(peerlist)
		free(peerlist);
	peerlist=(struct peer *) malloc( (numberofpeers()+1)*sizeof(struct peer) );
	_populatepoll(pfd,iter,1,peerlist);

	return peerlist;
}

/*
 * Get a pointer to the peer in the list which has the given udp address.
 */
struct peer *getpeer(struct sockaddr_in saddr)
{
	struct peer *iter=list;
	return (_getpeer(saddr,iter));
			
}

struct peer *getpeerbynewaddr(struct sockaddr_in saddr)
{
	struct peer *iter=list;
	return (_getpeerbna(saddr,iter));
			
}


/*
 * Get a pointer to the peer in the list which key filename is the same of that in the login datagram. 
 */
struct peer *getpeerbyid(struct datagram *pkt)
{
	struct peer *iter=list;
	return (_getpeerbyid(pkt,iter));
			
}

/*
 * Send a plain "access denied" message to the specified peer.
 */
void
deny_access(struct peer *p)
{
	send_udp((unsigned char *)"Access Denied.\0",15,p,CMD_DENY);
}

/*
 * Main select routine.
 * A poll will wake up whenever a new packet is available to read, either from one 
 * of the vde_plug attached, or from udp socket.
 * Returns a struct datagram aware of its own source.
 * Also discriminate commands from data, by first byte.
 */
struct datagram *blowfish_select (int timeout)
{
   unsigned peerlen;
   int pollret;
   static struct pollfd *pfd = NULL;
   static struct datagram *ret = NULL;
   static struct peer *peerlist = NULL;
   static int i=1;

   if (pfd)
	free(pfd);
   pfd=malloc((1+numberofpeers())*sizeof(struct pollfd));
   
   pfd[0].fd=nfd;
   pfd[0].events=POLLIN|POLLHUP;
   peerlist = populate_peerlist(pfd);

  do{
	  pollret=poll(pfd,1+numberofpeers(),1000);
	  if(pollret<0){
		  if(errno==EINTR)
			  return NULL;
		  perror("poll");
		  exit(1);
	  }
	  if (!ret){
		  ret = malloc(sizeof(struct datagram));
		  bzero(ret,sizeof(struct datagram));
		  ret->orig = malloc(sizeof (struct peer));
		  bzero(ret->orig,sizeof(struct peer));
	  }
  } while (pollret==0);

  
for(;;){
  if (pfd[0].revents&POLLIN) {
	unsigned char inpkt[MAXPKT];
	unsigned char *inbuff=inpkt+1;
	int ilen,tlen;
	struct sockaddr_in ipaddress;
	peerlen = sizeof(struct sockaddr_in);
	ilen = recvfrom(nfd, inpkt, MAXPKT, 0,
		(struct sockaddr *) &ipaddress, &peerlen);
  
        ret->orig=getpeer(ipaddress);
	if(!ret->orig){
		ret->orig=malloc(sizeof(struct peer));
	  	bzero(ret->orig,sizeof(struct peer));
		ret->orig->in_a.sin_family = AF_INET;
		ret->orig->in_a.sin_port = ipaddress.sin_port;
		ret->orig->in_a.sin_addr.s_addr= ipaddress.sin_addr.s_addr;
		ret->orig->state=ST_CLOSED;
	}
	
		
	if((inpkt[0]==PKT_DATA)&&	  
		 (ret->orig->state==ST_AUTH || ret->orig->state==ST_SERVER))
	{
		
		ret->src = SRC_BF;
		ilen--;
		
		EVP_DecryptInit (&ctx, EVP_bf_cbc (), ret->orig->key, ret->orig->iv);
		 
		if (EVP_DecryptUpdate (&ctx, ret->data, &ret->len, inbuff, ilen) != 1)
		  {
			fprintf (stderr,"error in decrypt update\n");
			return NULL;
		  }
		if (EVP_DecryptFinal (&ctx, ret->data + ret->len, &tlen) != 1)
		  {
			fprintf (stderr,"error in decrypt final\n");
			return NULL;
		  }
		EVP_CIPHER_CTX_cleanup(&ctx);
		  ret->len += tlen;
		  if( isvalid_crc32(ret->data,ret->len) && isvalid_timestamp(ret->data,ret->len,ret->orig) ){
			ret->len-=12;
			if(ret->orig->state==ST_AUTH)
				set_expire(ret->orig);
			return ret;
		}else{		
//			deny_access(ret->orig);
			return NULL;
		}
	}else if((inpkt[0]==CMD_HANDOVER)){
		ret->src = SRC_CTL;
		ilen--;
		
		//fprintf (stderr,"Recived Handover datagram.:   ");
		EVP_DecryptInit (&ctx, EVP_bf_cbc (), ret->orig->key, ret->orig->iv);
		 
		if (EVP_DecryptUpdate (&ctx, ret->data+1, &ret->len, inbuff, ilen) != 1)
		  {
			fprintf (stderr,"error in decrypt update\n");
			return NULL;
		  }
		if (EVP_DecryptFinal (&ctx, ret->data + 1 + ret->len, &tlen) != 1)
		  {
			fprintf (stderr,"error in decrypt final\n");
			return NULL;
		  }
		EVP_CIPHER_CTX_cleanup(&ctx);
		  ret->len += tlen;
		  ret->len +=1;
		  if( isvalid_crc32(ret->data+1,ret->len-1) && isvalid_timestamp(ret->data,ret->len,ret->orig) ){
			ret->len-=12;
			ret->data[0]=CMD_HANDOVER;
			//fprintf (stderr,"Valid Handover. Resending key.\n");
			return ret;
		}else{		
			fprintf (stderr,"Invalid Handover packet. crc32?%d, timestamp?%d \n",isvalid_crc32(ret->data+1,ret->len-1), isvalid_timestamp(ret->data,ret->len,ret->orig));
			deny_access(ret->orig);
			return NULL;
		}
		
  	}else if(inpkt[0]&PKT_CTL){
		ret->src = SRC_CTL;
		memcpy(ret->data,inpkt,ilen);
		ret->len=ilen;
		return ret;
	}else{	
	deny_access(ret->orig);
	return NULL;
			
	
	}
	
  }

  // This increment comes with "static int i" def, to ensure fairness among peers.
  i++;	  
  if(i>numberofpeers())
	  i=1;
  
  if (pfd[i].revents&POLLIN) {
/*	  c=read(pfd[i].fd,ret->data,2);
	  if(c<2) 
		  return NULL;
	  vde_len=0;
	  vde_len+=((unsigned char)(ret->data[0]))<<8;
	  vde_len+=(unsigned char)(ret->data[1]);
	  
	  ret->len=2;
	  while(ret->len < (vde_len + 2)){
		ret->len += read(pfd[i].fd, ret->data+ret->len, ((vde_len+2) - ret->len));
	  }
	// fprintf(stderr,"Read %d.\n",vde_len);
	  
*/ 
	ret->len = vde_recv(peerlist[i].plug, ret->data, MAXPKT,0);
	
	if(ret->len<1)
		return NULL;
	
	ret->src = SRC_VDE;
	ret->orig = &(peerlist[i]);

	//set_expire(&(peerlist[i]));
	  
	  
	return ret;
		
  }
// list=clean_peerlist(list); 
}
  return NULL;
}


/*
 * Send a virtual frame to the vde_plug process associated 
 * with the peer
 */
void
send_vdeplug(const char *data, size_t len, struct peer *p)
{
	static unsigned int outbuf[MAXPKT];
	static int outp=0;
	static u_int16_t outlen;
	if(len<=0)
		return;
	
	if(outp==0 && (len >=2) ){
		outlen=2;
		outlen+=(unsigned char)data[1];
		outlen+=((unsigned char)(data[0]))<<8;
	}
	
	if(len>=outlen){
		vde_send(p->plug,data,outlen,0);
		send_vdeplug(data+outlen,len-outlen, p);
		return;
	}
		
	memcpy(outbuf+outp,data,len);
	outp+=len;
	if(outp>=outlen){
		vde_send(p->plug,(char *)outbuf,outlen,0);
	}			
}

/*
 * Include a progressive number into outgoing datagram,
 * to prevent packet replication/injection attack.
 * 
 */
void
set_timestamp(unsigned char *block)
{
	int i;
	for(i=0;i<8;i++){
		block[i]=(unsigned char)(mycounter>>(i*8))&(0x00000000000000FF);
	}
	mycounter++;
	
		
}


/*
 * Send an udp datagram to specified peer.
 */
void
send_udp (unsigned char *data, size_t len, struct peer *p, unsigned char flags)
{
		  
	unsigned char outpkt[MAXPKT];
	unsigned char *outbuf=outpkt+1;
	int olen,tlen;
	struct sockaddr_in *destination=&(p->in_a);
	unsigned char *crc;
	if(flags==CMD_CHALLENGE || flags==CMD_LOGIN || flags==CMD_DENY || flags==CMD_AUTH_OK || flags==CMD_IDENTIFY){
		memcpy(outbuf,data,len);
		olen=len;
	}else{
		if(flags==PKT_DATA||flags==CMD_HANDOVER){
			set_timestamp(data+len);
			len+=8;
			
			crc = crc32(data,len);
			memcpy(data+len,crc32(data,len),4);
			free(crc);
			len+=4;
			
		}
		if(flags==CMD_HANDOVER){

			destination=&(p->handover_a);
		}
		
		EVP_EncryptInit (&ctx, EVP_bf_cbc (), p->key, p->iv);
		  if (EVP_EncryptUpdate (&ctx, outbuf, &olen, data, len) != 1)
		    {
			    fprintf (stderr,"error in encrypt update\n");
			    return;
		    }
	
		 
		  if (EVP_EncryptFinal (&ctx, outbuf + olen, &tlen) != 1)
		    {
			    fprintf (stderr,"error in encrypt final\n");
			    return;
		    }
		EVP_CIPHER_CTX_cleanup(&ctx);
		olen += tlen;
	}
	
	outpkt[0]=flags;
	sendto(nfd, outpkt, olen+1, 0, (struct sockaddr *) destination,
	    	sizeof(struct sockaddr_in));
}

/*
 * Generate a new blowfish key, store it in a local file and fill the fields
 * of peer structure.
 * Client only.
 */
struct peer
*generate_key (struct peer *ret, char *pre_shared)
{
	int i, fd=-1, od=-1, createnow=0;
	unsigned char key[16];
	unsigned char iv[8];
	unsigned char c;
	char *path;
	char random[]="/dev/urandom";
	if (pre_shared)
		path=pre_shared;
	else
		path=random;
	
	if(!ret){
		ret=malloc(sizeof(struct peer));
		bzero(ret,sizeof(struct peer));
		createnow=1;
	}
	if ( ((fd = open (path, O_RDONLY)) == -1)||
			 ((read (fd, key, 16)) == -1) ||
			 ((read (fd, iv, 8)) == -1) )
	{

		perror ("Error Creating key.\n");
		goto failure;
	}
	
	//fprintf(stderr,"128 bit key stored.\n");

	//fprintf(stderr,"64 bit Initialization vector stored.\n");
	
	for(i=0; i<FILENAMESIZE-1;i++){
		read(fd,&c,1);
		c=(c%25);
		//fprintf(stderr,"c=%u\n",c);
		ret->id[i]=(char)('a' + c);
	}
	ret->id[FILENAMESIZE-1]='\0';
	
	close (fd);
	
	if ((od = creat ("/tmp/.blowfish.key",0600)) == -1){
		perror ("blowfish.key creat error");
		goto failure;
	}
	memcpy(ret->key,key,16);
	memcpy(ret->iv,iv,8);
	write(od,key,16);
	write(od,iv,8);
	close (od);
	return ret;
	
failure:
	if (createnow)
		free(ret);
	if (fd != -1)
		close(fd);
	if (od != -1)
		close(od);
	return NULL;
}


/*
 * Send a "Challenge" 4WHS packet.
 */
static void
send_challenge(struct peer *p)
{
	int fd;
	if ( ((fd = open ("/dev/urandom", O_RDONLY)) == -1)||
			 ((read (fd, p->challenge, 128)) != -1))
	{	
		send_udp((unsigned char *)p->challenge,128,p,PKT_CTL|CMD_CHALLENGE);
	}		
	p->state=ST_CHALLENGE;
	close(fd);
}

/*
 * Send a "Auth OK" 4WHS packet.
 */
static void
send_auth_ok(struct peer *p, void (*callback)(struct peer*))
{
	send_udp(NULL,0,p,CMD_AUTH_OK);
	p->state=ST_AUTH;
	callback(p);
	set_expire(p);
}

/*
 * Receive a challenge. Try to send response encrypted with local blowfish key.
 */
void 
rcv_challenge(struct datagram *pkt, struct peer *p)
{
	send_udp(pkt->data+1,pkt->len-1,p,CMD_RESPONSE);
	p->state=ST_WAIT_AUTH;
}


/*
 * Receive a login request. Send challenge.
 */
void
rcv_login(struct datagram *pkt, struct peer *p, char *pre_shared)
{
	int fd;
	char filename[128];
	if(!pre_shared)
		snprintf(filename,127,"/tmp/.%s.key",pkt->data+1);
	else
		snprintf(filename,127,"%s",pre_shared);

		
	fprintf(stderr,"Filename:%s\n",filename);
	if (((fd = open (filename, O_RDONLY)) == -1)||
 			((read (fd, p->key, 16)) == -1) ||
			((read (fd, p->iv, 8)) == -1) ){
		perror ("blowfish.key open error");
		deny_access(p);
		return;
	}
	close(fd);
	memcpy(p->id,pkt->data+1,FILENAMESIZE);
	fprintf(stderr,"Sending challenge... ");
	send_challenge(p);
	fprintf(stderr,"OK.\n");

}

/*
 * Receive a response from challenge. Validate encryption and send "ok auth"
 * or "access denied"
 */
void
rcv_response(struct datagram *pkt, struct peer *p, void (*callback)(struct peer*))
{
	unsigned char response[MAXPKT];
	int rlen, tlen;
	
	EVP_DecryptInit (&ctx, EVP_bf_cbc (), p->key, p->iv);
	 
	if (EVP_DecryptUpdate (&ctx, response, &rlen, pkt->data+1, pkt->len-1) != 1)
	  {
		fprintf (stderr,"error in decrypt update\n");
		return;
	  }

	  if (EVP_DecryptFinal (&ctx, response + rlen, &tlen) != 1)
	  {
		fprintf (stderr,"error in decrypt final\n");
		return;
	  }
	EVP_CIPHER_CTX_cleanup(&ctx);

	  if (strncmp((char *)response,p->challenge,128)==0){
		  p->state=ST_AUTH;
		  send_auth_ok(p, callback);
	  }
		  
	  else{
		  p->state=ST_CLOSED;
		  deny_access(p);
	  }

}

/*
 * Send a login packet. This is the first phase of 4WHS
 */
void
blowfish_login(struct peer *p)
{
	send_udp((unsigned char*)p->id,FILENAMESIZE,p,CMD_LOGIN);
}

/*
 * Initialize blowfish module.
 * Set udp socket and initialize crypto engine & CRC32.
 */
void
blowfish_init(int socketfd)
{
	nfd=socketfd;
	EVP_CIPHER_CTX_init (&ctx);	
	chksum_crc32gentab ();
}


