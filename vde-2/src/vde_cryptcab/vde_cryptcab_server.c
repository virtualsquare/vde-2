/*
 * VDE Cryptcab
 * Copyright © 2006-2008 Daniele Lacamera
 * from an idea by Renzo Davoli
 *
 * Released under the terms of GNU GPL v.2
 * (http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
 * with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 */

#include "cryptcab.h"

static struct peer *list = NULL;
static char *plugname;
static enum e_enc_type enc_type = ENC_SSH;

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

static void addpeer(struct peer *np)
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
	if(iter->plug){
		datafd=vde_datafd(iter->plug);
		pfd[index].fd=datafd;
		pfd[index++].events=POLLIN|POLLHUP|POLLNVAL;
	} else if(iter->state == ST_AUTH) {
		vde_plug(iter, plugname);
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


/*
 * Returns peer list length.
 */

static int numberofpeers(){
	struct peer *iter=list;
	return _peers(iter);
}

static void remove_peerlist(struct peer *sublist)
{
	char filename[128];
	if(!sublist)
		return;
	vde_close(sublist->plug);
	sublist->plug=NULL;
	if (sublist->state == ST_AUTH && enc_type == ENC_SSH){
		snprintf(filename,127,"/tmp/.%s.key",sublist->id);
		if (unlink(filename) == 0){
			vc_printlog(2,"Successfully removed key file %s", filename);
		}else{
			vc_printlog(2,"Could not remove key file %s", filename);
		}
	}
	remove_peerlist(sublist->next);
}
	


static struct peer *clean_peerlist(struct peer *sublist)
{
	struct timeval now;
	char filename[128];
	struct peer *nxt;

	if(!sublist)
		return NULL;
	nxt=sublist->next;
	gettimeofday(&now,NULL);
	if(after(now,sublist->expire) 
//	  || (sublist->state == ST_AUTH && sublist->plug) 
		){
		vc_printlog(1,"Client %s : expired.",inet_ntoa(sublist->in_a.sin_addr));
		vc_printlog(4,"Client %s : expire time: %lu, now= %lu.",inet_ntoa(sublist->in_a.sin_addr),sublist->expire.tv_sec,now.tv_sec);
		if (sublist->plug){
			vde_close(sublist->plug);
			sublist->plug=NULL;
		}
		if (sublist->state == ST_AUTH && enc_type == ENC_SSH){
			snprintf(filename,127,"/tmp/.%s.key",sublist->id);
			if (unlink(filename) == 0){
				vc_printlog(2,"Successfully removed key file %s", filename);
			}else{
				vc_printlog(2,"Could not remove key file %s", filename);
			}
		}
		free(sublist);
		return nxt;
	}
	sublist->next=clean_peerlist(sublist->next);
	return sublist;
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
static struct peer *getpeer(struct sockaddr_in saddr)
{
	struct peer *iter=list;
	return (_getpeer(saddr,iter));
			
}


/*
 * Get a pointer to the peer in the list which key filename is the same of that in the login datagram. 
 */

static void
autocleaner(int signo)
{
	struct itimerval *old=NULL;
	list=clean_peerlist(list);
	setitimer(ITIMER_REAL, &TIMER, old);
}

static void
do_exit(int signo){
	vc_printlog(1,"Caught signal, exiting.");
	remove_peerlist(list);
	exit(0);
}


static void 
set_expire(struct peer *p, unsigned char cmd)
{
	struct timeval now;
	gettimeofday(&now,NULL);
	p->expire.tv_usec = 0;

	switch (cmd){
		case EXPIRE_NOW:
		p->expire.tv_sec = now.tv_sec + PRELOGIN_TIMEOUT;
		break;

		case CMD_CHALLENGE:
		p->expire.tv_sec = now.tv_sec + CHALLENGE_TIMEOUT;
		break;

		case CMD_LOGIN:
		p->expire.tv_sec = now.tv_sec + PRELOGIN_TIMEOUT;
		break;

		default:
		p->expire.tv_sec = now.tv_sec + SESSION_TIMEOUT;
		break;
	}
}
	

static void
deny_access(struct peer *p)
{
	send_udp((unsigned char *)"Access Denied.\0",15,p,CMD_DENY);
	p->state = ST_CLOSED;
	set_expire(p, EXPIRE_NOW);
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
send_auth_ok(struct peer *p)
{
	send_udp(NULL,0,p,CMD_AUTH_OK);
	p->state=ST_AUTH;
	if(!p->plug)
		vde_plug(p, plugname);
	set_expire(p,CMD_AUTH_OK);
}
/*
 * Receive a login request. Send challenge.
 */
static void
rcv_login(struct datagram *pkt, char *pre_shared)
{
	int fd;
	char filename[128];
	if(!pre_shared)
		snprintf(filename,127,"/tmp/.%s.key",pkt->data+1);
	else
		snprintf(filename,127,"%s",pre_shared);
	sync();
	usleep(10000);	
	if (((fd = open (filename, O_RDONLY)) == -1)||
 			((read (fd, pkt->orig->key, 16)) == -1) ||
			((read (fd, pkt->orig->iv, 8)) == -1) ){
		perror ("blowfish.key open error");
		deny_access(pkt->orig);
		return;
	}

	close(fd);
	memcpy(pkt->orig->id,pkt->data+1,FILENAMESIZE);
	vc_printlog(2,"Sending challenge... ");
	send_challenge(pkt->orig);
	set_expire(pkt->orig, CMD_CHALLENGE);
	vc_printlog(2,"OK.\n");

}

/*
 * Receive a response from challenge. Validate encryption and send "ok auth"
 * or "access denied"
 */
static void
rcv_response(struct datagram *pkt)
{
	unsigned char response[MAXPKT];
	int rlen;
	struct peer *p = pkt->orig;
 
	rlen = data_decrypt(pkt->data + 1, response, pkt->len - 1, p);
	
	if (rlen > 0 && strncmp((char *)response, p->challenge,128)==0){
		p->state = ST_AUTH;
		send_auth_ok(p);
	} else {
		deny_access(p);
	}
}
/*
 * Main select routine.
 * A poll will wake up whenever a new packet is available to read, either from one 
 * of the vde_plug attached, or from udp socket.
 * Returns a struct datagram aware of its own source.
 */
static int recv_datagram_srv(struct datagram *pkt, int nfd)
{
	unsigned peerlen;
	int pollret;
	static struct pollfd *pfd = NULL;
	static struct peer *peerlist = NULL;
	static int i=1;

	if (pfd)
	     free(pfd);

	pfd=malloc((1+numberofpeers())*sizeof(struct pollfd));

	pfd[0].fd=nfd;
	pfd[0].events=POLLIN|POLLHUP;
	peerlist = populate_peerlist(pfd);

	 do{
		pollret = poll(pfd,1+numberofpeers(),1000);
		if(pollret<0){
		 	if(errno==EINTR)
		   		return 0;
		 	perror("poll");
		 	exit(1);
		}
   	} while (pollret==0);

  
	for(;;){
		if (pfd[0].revents&POLLIN) {
			struct sockaddr_in ipaddress;
			peerlen = sizeof(struct sockaddr_in);
			pkt->len = recvfrom(nfd, pkt->data, MAXPKT, 0,
				(struct sockaddr *) &ipaddress, &peerlen);
	  
			pkt->orig=getpeer(ipaddress);
			if(!pkt->orig){
				pkt->orig=malloc(sizeof(struct peer));
				memset(pkt->orig,0,sizeof(struct peer));
				pkt->orig->in_a.sin_family = AF_INET;
				pkt->orig->in_a.sin_port = ipaddress.sin_port;
				pkt->orig->in_a.sin_addr.s_addr= ipaddress.sin_addr.s_addr;
				pkt->orig->state=ST_CLOSED;
				addpeer(pkt->orig);
				set_expire(pkt->orig, CMD_LOGIN);
			}
			pkt->src = SRC_UDP;
			return 1;
		}

		// This increment comes with "static int i" def, to ensure fairness among peers.
		i++;	  
		if(i>numberofpeers())
			i=1;

		if (pfd[i].revents&POLLNVAL || pfd[i].revents&POLLHUP){
			usleep(10000);
			return 0;
		}
	  
		if (pfd[i].revents&POLLIN && peerlist[i].plug != NULL ) {
			pkt->len = vde_recv(peerlist[i].plug, pkt->data, MAXPKT,0);
			if(pkt->len<1)
				return 0;
			pkt->src = SRC_VDE;
			pkt->orig = &(peerlist[i]);
			return 1;
		}
		break;
	}
	return 0;
}

void cryptcab_server(char *_plugname, unsigned short udp_port, enum e_enc_type _enc_type, char *pre_shared)
{
	int wire, r;
	struct sockaddr_in myaddr;
	struct datagram pkt, pkt_dec;
	struct sigaction sa_timer;
	struct sigaction sa_exit;
	struct peer *p1;
	
	enc_type = _enc_type;
	plugname = _plugname;


	sigemptyset(&sa_timer.sa_mask);
	sigemptyset(&sa_exit.sa_mask);
	sa_exit.sa_handler = do_exit;
	sa_timer.sa_handler = autocleaner;
	sigaction(SIGALRM, &sa_timer, NULL);
	sigaction(SIGINT, &sa_exit, NULL);
	sigaction(SIGTERM, &sa_exit, NULL);
	kill(getpid(),SIGALRM);
	
	if(enc_type == ENC_PRESHARED && (!pre_shared || access(pre_shared,R_OK)!=0)){
		fprintf(stderr,"Error accessing pre-shared key %s\n",pre_shared);
		perror ("access");
		exit(1);
	}

	if (enc_type == ENC_NOENC)
		disable_encryption();

	memset ((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(udp_port);
	
	wire = socket(PF_INET,SOCK_DGRAM,0);
	if (bind(wire,(struct sockaddr *) &myaddr, sizeof(myaddr))<0)
		        {perror("bind socket"); exit(3);}

	set_nfd(wire);
	
	for(;;){
		r = recv_datagram_srv(&pkt, wire);
		if (r == 0)
			continue;

//		fprintf(stderr,".");
		p1 = pkt.orig;
		if(pkt.src==SRC_VDE){
			if(p1->state==ST_AUTH){
				send_udp(pkt.data, pkt.len, p1, PKT_DATA);
			}
			continue;
		}
		else if(pkt.src==SRC_UDP){
			switch(p1->state + pkt.data[0]) {
				case (ST_AUTH + PKT_DATA):
					vc_printlog(4,"Data pkt received (%d Bytes)",pkt.len); 
					pkt_dec.len = data_decrypt(pkt.data+1, pkt_dec.data, pkt.len-1, p1);
					set_expire(p1, CMD_KEEPALIVE);
					vde_send(p1->plug,pkt_dec.data,pkt_dec.len,0);	
					break;
				case (ST_AUTH + CMD_KEEPALIVE):
					vc_printlog(4,"Keepalive received from %s",inet_ntoa(p1->in_a.sin_addr));
					set_expire(p1, CMD_KEEPALIVE);
					break;

				case ST_AUTH + CMD_LOGIN:
					set_expire(p1, EXPIRE_NOW);
				case ST_CLOSED + CMD_LOGIN:
					vc_printlog(4,"Login pkt received."); 
					p1->state=ST_OPENING;
					p1->counter=0;
					rcv_login(&pkt,pre_shared);
					break;
				
				case ST_CHALLENGE + CMD_RESPONSE:
					vc_printlog(4,"Response pkt received."); 
					//fprintf(stderr, "Receiving response\n");
					rcv_response(&pkt);
					break;

				default:
					vc_printlog(4,"Unknown/undesired pkt received. (state: 0x%X code: 0x%X )", p1->state, (unsigned char)pkt.data[0]); 
					if (p1->state != ST_AUTH)
						deny_access(pkt.orig);					
					else
						send_auth_ok(pkt.orig);
			}	
			
		}
		
	}
	exit (0);
} 
