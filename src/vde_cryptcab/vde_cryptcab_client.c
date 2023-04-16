/*
 * VDE Cryptcab
 * Copyright © 2006-2008 Daniele Lacamera
 * from an idea by Renzo Davoli
 *
 * Released under the terms of GNU GPL v.2
 * (http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
 *
 */

#include "config.h"
#include "cryptcab.h"

#define KEEPALIVE_INTERVAL 30

static unsigned char keepalives = 0;
static char *remoteusr, *remotehost;
static unsigned short remoteport;
static char *plugname, *pre_shared;
static struct timeval last_out_time;
static enum e_enc_type enc_type = ENC_SSH;
static char *scp_extra_options = NULL;
static char keyname[] = "/tmp/vde_XXXXXX.key";

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
chacha_login(struct peer *p)
{
	send_udp((unsigned char*)p->id,FILENAMESIZE,p,CMD_LOGIN);
}

static void try_to_login(struct peer *p)
{
	static struct timeval last_login_time;
	struct timeval now;
	gettimeofday(&now, 0);
	if (now.tv_sec < last_login_time.tv_sec || now.tv_sec - last_login_time.tv_sec < 5) {
		vc_printlog(4,"Attempt to login to %s (udp port %hu): please wait, login in progress...",remotehost,remoteport);
		return;
	}

	vc_printlog(2,"Logging in to %s (udp port %hu)",remotehost,remoteport);
	chacha_login(p);
	gettimeofday(&last_login_time, 0);
}


/*
 * Receive a challenge. Try to send response encrypted with local chacha key.
 */
	static void
rcv_challenge(struct datagram *pkt, struct peer *p)
{
	send_udp(pkt->data+1,pkt->len-1,p,CMD_RESPONSE);
	p->state=ST_WAIT_AUTH;
}

/*
 * Generate a new chacha key, store it in a local file and fill the fields
 * of peer structure.
 * Client only.
 */
	static struct peer
*generate_key (struct peer *ret)
{
	int fd=-1, od=-1;
	unsigned char key[CHACHA_MAX_KEY_SZ];
	unsigned char iv[CHACHA_IV_BYTES];
	char *path;
	char random[]="/dev/urandom";
	if (pre_shared){
		path=pre_shared;
		vc_printlog(2,"Reading pre-shared Chacha key...");	
	}else{
		path=random;
		vc_printlog(2,"Generating ChaCha key...");	
	}


	if ( ((fd = open (path, O_RDONLY)) == -1)||
			((read (fd, key, CHACHA_MAX_KEY_SZ)) == -1) ||
			((read (fd, iv, CHACHA_IV_BYTES)) == -1) )
	{

		perror ("Error Creating key.\n");
		goto failure;
	}

	close (fd);
	memset(keyname + strlen(keyname) - 10, 'X', 6);
#ifdef VDE_DARWIN
    od = mkostemps(keyname, 4, O_EXLOCK);
#else
    od = mkostemps(keyname, 4, O_RDWR | O_CREAT | O_TRUNC);
#endif
	if (od < 0){
		perror ("chacha.key mktemp error");
		goto failure;
	}
	memset(ret,0, sizeof(struct peer));

	strncpy(ret->id,
			keyname + strlen("/tmp/"),
			strlen(keyname) - strlen("/tmp/") - strlen(".key"));

	memcpy(ret->key,key,CHACHA_MAX_KEY_SZ);
	memcpy(ret->iv,iv,CHACHA_IV_BYTES);
	if (write(od,key,CHACHA_MAX_KEY_SZ) < 0 || write(od,iv,CHACHA_IV_BYTES) < 0) {
		perror("Could not write chacha key");
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
	char source[PATH_MAX], dest[PATH_MAX];
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
		char *cmd[]={"scp",NULL, NULL, NULL,0};
		pid_t pid;
		int status;
		int cmd_idx = 1;
		vc_printlog(2,"Sending key over ssh channel:");
		if (scp_extra_options)
			cmd[cmd_idx++] = scp_extra_options;
		if(remoteusr)
			snprintf(dest,PATH_MAX,"%s@%s:/tmp/.%s.key",remoteusr, remotehost, ret->id);
		else
			snprintf(dest,PATH_MAX,"%s:/tmp/.%s.key", remotehost, ret->id);
		snprintf(source, PATH_MAX, "/tmp/%s.key", ret->id);
		cmd[cmd_idx++] = source;
		cmd[cmd_idx++] = dest;


		if ((pid=fork()) == 0) {
			dup2(1,2);
			execvp(cmd[0],cmd);
		}
		waitpid(pid,&status,0);

		if(WEXITSTATUS(status)==0){
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
	socklen_t peerlen;
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
					{
						unsigned int len = pkt.len - 1;
						unsigned char *p = (pkt.data + 1);
						unsigned char *tail = (p + len - 12);
						uint32_t crc;

						crc = tail[0] + (tail[1] << 8) +
							(tail[2] << 16) + (tail[3] << 24);
						len -= 12;
						pkt_dec.len = data_encrypt_decrypt(p, pkt_dec.data, len, p1->key, tail);
						if (crc == chksum_crc32(pkt_dec.data,pkt_dec.len)) {
							vc_printlog(4,"Data pkt received (%d Bytes)",pkt.len);
							vde_send(p1->plug,pkt_dec.data,pkt_dec.len,0);	
						} else {
							vc_printlog(4,"CRC error, incoming data packet discarded (%d Bytes)",pkt.len);
						}
					}
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

