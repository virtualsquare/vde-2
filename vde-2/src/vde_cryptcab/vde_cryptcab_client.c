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
#define KEEPALIVE_INTERVAL 30

static unsigned char keepalives = 0;
static char *remoteusr, *remotehost;
static unsigned short remoteport;
static char *plugname, *pre_shared;
static struct timeval last_out_time;
static enum e_enc_type enc_type = ENC_SSH;
static char *scp_extra_options = NULL;

static void send_keepalive(struct peer *p){
	if (!keepalives)
		return;
	vc_printlog(4,"Sending keepalive");
	send_udp(NULL,0,p,CMD_KEEPALIVE);
	gettimeofday(&last_out_time, NULL);
}


/*
 * Send a login packet. This is the first phase of 4WHS
 */
static void
blowfish_login(struct peer *p)
{
	send_udp((unsigned char*)p->id,FILENAMESIZE,p,CMD_LOGIN);
}

static void try_to_login(struct peer *p)
{
	static struct timeval last_login_time; 
	struct timeval now;
	gettimeofday(&now, 0);
	if (now.tv_sec < last_login_time.tv_sec  || now.tv_sec - last_login_time.tv_sec < 5) {
		vc_printlog(4,"Attempt to login to  %s (udp port %hu): please wait, login in progress...",remotehost,remoteport);
		return;
	}
		
	vc_printlog(2,"Logging in to %s (udp port %hu)",remotehost,remoteport);
	blowfish_login(p);
	gettimeofday(&last_login_time, 0);
}


/*
 * Receive a challenge. Try to send response encrypted with local blowfish key.
 */
static void 
rcv_challenge(struct datagram *pkt, struct peer *p)
{
	send_udp(pkt->data+1,pkt->len-1,p,CMD_RESPONSE);
	p->state=ST_WAIT_AUTH;
}

/*
 * Generate a new blowfish key, store it in a local file and fill the fields
 * of peer structure.
 * Client only.
 */
static struct peer
*generate_key (struct peer *ret)
{
	int i, fd=-1, od=-1;
	unsigned char key[16];
	unsigned char iv[8];
	unsigned char c;
	char *path;
	char random[]="/dev/urandom";
	if (pre_shared){
		path=pre_shared;
		vc_printlog(2,"Reading pre-shared Blowfish key...");	
	}else{
		path=random;
		vc_printlog(2,"Generating Blowfish key...");	
	}

	if ( ((fd = open (path, O_RDONLY)) == -1)||
			 ((read (fd, key, 16)) == -1) ||
			 ((read (fd, iv, 8)) == -1) )
	{

		perror ("Error Creating key.\n");
		goto failure;
	}
	
	memset(ret,0, sizeof(struct peer));	

	for(i=0; i<FILENAMESIZE-1;i++){
		if (read(fd,&c,1) < 0) {
			perror("could not read filename ");
			goto failure;
		}
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
	if (write(od,key,16) < 0 || write(od,iv,8) < 0) {
		perror("Could not write blowfish key");
		goto failure;
	}
	close (od);
	vc_printlog(2,"Done.");	
	return ret;
	
failure:
	if (fd != -1)
		close(fd);
	if (od != -1)
		close(od);
	return NULL;
}


/*
 * Call the generate_key() and then transmit the key to the server via 
 * OpenSSH secure copy.
 */
static struct peer *generate_and_xmit(struct peer *ret){
	char command[255];
	int res;
	struct hostent *target;

	ret=generate_key(ret);

	if(!ret){
		fprintf(stderr,"Couldn't create the secret key.\n");
		exit(255);
	}
	
	target=gethostbyname(remotehost);
	if (target == NULL)
	{
		fprintf(stderr,"%s not found.\n", remotehost);
		exit(2);
	}
	ret->in_a.sin_family = AF_INET;
	ret->in_a.sin_port = htons(remoteport);
	ret->in_a.sin_addr.s_addr=((struct in_addr *)(target->h_addr))->s_addr;
	if(!pre_shared){		
		vc_printlog(2,"Sending key over ssh channel:");
		if(remoteusr)
			sprintf(command,"scp %s /tmp/.blowfish.key %s@%s:/tmp/.%s.key 2>&1", 
				scp_extra_options?scp_extra_options:"",
				remoteusr, remotehost, ret->id);	
		else
			sprintf(command,"scp %s /tmp/.blowfish.key %s:/tmp/.%s.key 2>&1", 
				scp_extra_options?scp_extra_options:"",
				remotehost, ret->id);

		//fprintf(stderr,"Contacting host: %s ",remotehost);
		res=system(command);
		
		if(res==0){
			vc_printlog(2,"Key successfully transferred using a secure channel.");
		}else{
			fprintf(stderr,"Couldn't transfer the secret key.\n");
			exit(253);
		}
	}
	vc_printlog(2,"Done.");
	return ret;
}

static int recv_datagram(struct datagram *pkt, int nfd, struct peer *p1)
{
	int pollret;
	static struct pollfd pfd[2];
	size_t peerlen;
	int datafd;
	struct timeval now;
	
	datafd = vde_datafd(p1->plug);
	while(datafd < 0) {
		vc_printlog(4,"waiting for vde_libs...");
		vde_plug(p1, plugname);
		sleep(1);
		datafd = vde_datafd(p1->plug);
	}

	pfd[0].fd=nfd;
	pfd[0].events=POLLIN|POLLHUP;
	pfd[1].fd = datafd; 
	pfd[1].events = POLLIN|POLLHUP;

	 do{
		pollret = poll(pfd,2,1000);
		if(pollret<0){
		 	if(errno==EINTR)
		   		return 0;
		 	perror("poll");
		 	exit(1);
		}

		gettimeofday(&now,NULL);
		now.tv_sec -= KEEPALIVE_INTERVAL;
		if (after(now,last_out_time) && p1->state == ST_AUTH){
			send_keepalive(p1);
		}
   	} while (pollret==0);

  
	for(;;){
		if (pfd[0].revents&POLLIN) {
			struct sockaddr_in ipaddress;
			peerlen = sizeof(struct sockaddr_in);
			pkt->len = recvfrom(nfd, pkt->data, MAXPKT, 0,
				(struct sockaddr *) &ipaddress, &peerlen);
			if(ipaddress.sin_addr.s_addr == p1->in_a.sin_addr.s_addr){
				pkt->orig=p1;
				pkt->src = SRC_UDP;
				return 1;
			} else {
				vc_printlog(1,"Warning: received packet from unknown address %s, dropping",inet_ntoa(ipaddress.sin_addr));
				return 0;	
			}
		}

	 	if (pfd[1].revents&POLLHUP){
			vc_printlog(1,"VDE Error");
		} 
		if (pfd[1].revents&POLLIN) {
			vc_printlog(4,"VDE Pkt");
			pkt->len = vde_recv(p1->plug, pkt->data, MAXPKT,0);
			if(pkt->len<1)
				return 0;
			pkt->src = SRC_VDE;
			pkt->orig = p1;
			return 1;
		}
	}
	return 0;
}

void cryptcab_client(char *_plugname, unsigned short udp_port, enum e_enc_type _enc_type, char *_pre_shared, char *_remoteusr, char *_remotehost, unsigned short _remoteport, unsigned char _keepalives, char *_scp_extra_options)
{
	int wire, r;
	struct sockaddr_in myaddr;
	struct datagram pkt, pkt_dec;
	struct peer _peer;
	struct peer *p1 = &_peer;
	
	plugname = _plugname;
	remoteusr = _remoteusr;
	remotehost = _remotehost;
	remoteport = _remoteport;
	pre_shared = _pre_shared;
	keepalives = _keepalives;
	enc_type = _enc_type;
	scp_extra_options = _scp_extra_options;

	memset(&last_out_time,0, sizeof(struct timeval));

	if(enc_type == ENC_PRESHARED && (!pre_shared || access(pre_shared,R_OK)!=0)){
		vc_printlog(0,"Error accessing pre-shared key %s: %s\n",pre_shared,strerror(errno));
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

	p1 = generate_and_xmit(p1);
	p1->state = ST_OPENING;
	p1->next = NULL;
	try_to_login(p1);
	usleep(100000);
	
	for(;;){
		r = recv_datagram(&pkt, wire, p1);
		if (r == 0)
			continue;

		if(pkt.src==SRC_VDE){
			if(p1->state==ST_AUTH){
				vc_printlog(4,"VDE pkt received (%d Bytes)",pkt.len); 
				send_udp(pkt.data, pkt.len, p1, PKT_DATA);
				gettimeofday(&last_out_time,NULL);
			}else{
				try_to_login(p1);
			}
			continue;
		}
		else if(pkt.src==SRC_UDP){
			switch(p1->state + pkt.data[0]) {
				case ST_OPENING + CMD_CHALLENGE:
					vc_printlog(2,"Received Challenge packet, replying:");
					rcv_challenge(&pkt, p1);
					break;
				case ST_WAIT_AUTH + CMD_AUTH_OK:
					p1->state = ST_AUTH;
					vc_printlog(2,"Successfully authenticated.");
					break;
				case ST_AUTH + PKT_DATA:
					vc_printlog(4,"Data pkt received (%d Bytes)",pkt.len); 
					pkt_dec.len = data_decrypt(pkt.data+1, pkt_dec.data, pkt.len-1, p1);
					
					vde_send(p1->plug,pkt_dec.data,pkt_dec.len,0);	
					break;
				case ST_OPENING + CMD_DENY:
				case ST_WAIT_AUTH + CMD_DENY:
				case ST_AUTH + CMD_DENY:
					vc_printlog(2,"Received access denied from server, sending identification.");
					vde_close(p1->plug);
					p1 = (struct peer *)generate_and_xmit(p1);
					p1->state = ST_OPENING;
					try_to_login(p1);
					break;
				default:
					vc_printlog(4,"Unknown/undesired pkt received. (state: 0x%X code: 0x%X )", p1->state, (unsigned char)pkt.data[0]); 
			}
			
		}
		
	}
	exit (0);
} 

