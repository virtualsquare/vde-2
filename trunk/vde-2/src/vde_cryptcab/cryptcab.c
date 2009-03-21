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

/*
 * Usage implies exit.
 */
static void Usage(char *programname)
{

	fprintf(stderr,"Usage: %s [-s socketname] [-c [remoteuser@]remotehost[:remoteport]] [-p localport] [-P pre-shared/key/path] [-d] [-x] [-v]\n",programname);
	exit(1);
}
	
static EVP_CIPHER_CTX ctx;
static int ctx_initialized = 0;
static int encryption_disabled = 0;
static int nfd;
static unsigned long long mycounter=1;
static struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
static int verbose = 0;

void vc_printlog(int priority, const char *format, ...)
{
	va_list arg;
	if(verbose >= priority){
		va_start (arg, format);

		fprintf(stderr,"vde_cryptcab: ");
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
		va_end (arg);
	}
}

void disable_encryption(void) {
	encryption_disabled = 1;
	vc_printlog(3,"Encryption Disabled.");
}

void set_nfd(int fd){
	nfd = fd;
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

int data_encrypt(unsigned char *src, unsigned char *dst, int len, struct peer *p)
{
	int tlen, olen;
	
	if (encryption_disabled){
		memcpy(dst,src,len);
		return len;
	}

	if (!ctx_initialized) {
		EVP_CIPHER_CTX_init (&ctx);
		ctx_initialized = 1;
	}
	
	EVP_EncryptInit (&ctx, EVP_bf_cbc (), p->key, p->iv);
	if (EVP_EncryptUpdate (&ctx, dst, &olen, src, len) != 1)
	{
		fprintf (stderr,"error in encrypt update\n");
		olen = -1;
		goto cleanup;
	}

	if (EVP_EncryptFinal (&ctx, dst + olen, &tlen) != 1)
	{
		fprintf (stderr,"error in encrypt final\n");
		olen = -1;
		goto cleanup;
	}
	olen += tlen;

cleanup:
	EVP_CIPHER_CTX_cleanup(&ctx);	
	return olen;
}

int data_decrypt(unsigned char *src, unsigned char *dst, int len, struct peer *p)
{
	int tlen, olen;

	if (encryption_disabled){
		memcpy(dst,src,len);
		return len;
	}
	
	if (!ctx_initialized) {
		EVP_CIPHER_CTX_init (&ctx);
		ctx_initialized = 1;
	}

	EVP_DecryptInit (&ctx, EVP_bf_cbc (), p->key, p->iv);
	if (EVP_DecryptUpdate (&ctx, dst, &olen, src, len) != 1)
	{
		fprintf (stderr,"error in decrypt update\n");
		olen = -1;
		goto cleanup;
	}

	if (EVP_DecryptFinal (&ctx, dst + olen, &tlen) != 1)
	{
		fprintf (stderr,"error in decrypt final\n");
		olen = -1;
		goto cleanup;
	}
	olen += tlen;

cleanup:
	EVP_CIPHER_CTX_cleanup(&ctx);	
	return olen;
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
	int olen;
	struct sockaddr_in *destination=&(p->in_a);
	unsigned char *crc;
	if (encryption_disabled || (flags==CMD_CHALLENGE || flags==CMD_LOGIN || flags==CMD_DENY || flags==CMD_AUTH_OK || flags == CMD_KEEPALIVE)){
		memcpy(outbuf,data,len);
		olen=len;
	}else{
		if(flags==PKT_DATA){
			set_timestamp(data+len);
			len+=8;
			
			crc = crc32(data,len);
			memcpy(data+len,crc,4);
			free(crc);
			len+=4;
			
		}
		olen = data_encrypt(data,outbuf,len,p);
	}
	outpkt[0]=flags;
	sendto(nfd, outpkt, olen + 1, 0, (struct sockaddr *) destination,
	    	sizeof(struct sockaddr_in));
	vc_printlog(4,"UDP Sent %dB datagram.",olen+1);
}

void
vde_plug(struct peer *p, char *plugname)
{
	p->plug=vde_open(plugname,"vde_cryptcab",&open_args);
	if(!p->plug)
	{
		perror ("libvdeplug");
		exit(1);
	}
	vc_printlog(3,"Socket to local switch created: fd=%d",vde_datafd(p->plug));
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
	vc_printlog(3,"VDE - Sent a %dB datagram.",outlen);
}

/*
 * Main.
 */
int main(int argc, char **argv, char **env)
{
	int c;
	char *programname=argv[0];		
	char *plugname="/tmp/vde.ctl";
	char *remotehost = NULL;
	char *remoteusr = NULL;
	char *pre_shared = NULL;
	enum e_enc_type enc_type = ENC_SSH;
	unsigned short udp_port = PORTNO;
	unsigned short remoteport = PORTNO;
	unsigned char keepalives=0;
	char *scp_extra_options;
	int daemonize = 0;

	scp_extra_options=getenv("SCP_EXTRA_OPTIONS");
	

	while (1) {
		int option_index = 0;
		char *ctl_socket;
		const char sepusr='@';
		const char sepport=':';
		char *pusr,*pport, *vvv=NULL;

		static struct option long_options[] = {
		        {"sock", 1, 0, 's'},
		        {"vdesock", 1, 0, 's'},
		        {"unix", 1, 0, 's'},
		        {"localport", 1, 0, 'p'},
		        {"connect",1,0,'c'},
		        {"preshared ",1,0,'P'},
			{"noencrypt",0,0,'x'},
			{"keepalive",0,0,'k'},
			{"verbose",optional_argument,0,'v'},
		        {"help",0,0,'h'},
		        {"daemon",0,0,'d'},
		        {0, 0, 0, 0}
		};
		c = GETOPT_LONG (argc, argv, "s:p:c:P:hv::xkd",
		      	  long_options, &option_index);
		if (c == -1)
		        break;
		switch (c) {
		        case 's':
		      	  plugname=strdup(optarg);
		      	  break;
			case 'v':
			  verbose=1;
			  if(optarg)
		      	  	vvv=strdup(optarg);
			  while(vvv && *vvv++ == 'v')
			  	verbose++;
			  break;
			case 'x':
			  enc_type = ENC_NOENC;
			  break;
		        case 'c':
		      	  ctl_socket=strdup(optarg);

		      	  pusr=strchr(ctl_socket,sepusr);
		      	  pport=strchr(ctl_socket,sepport);
		      	  
		      	  if( ( pusr != strrchr(ctl_socket,sepusr)) || 
		      		(pport != strrchr(ctl_socket,sepport)) ||
		      			(pport && pusr>pport) )
		      		  Usage(programname);
		      	  
		      	  if(!pusr && !pport){
		      		  remoteusr=NULL;
		      		  remoteport=PORTNO;
		      		  remotehost=strdup(ctl_socket);
		      		  break;
		      	  }
		      	  if(!pport){
		      	  	  remoteusr=(char *)strndup(ctl_socket,pusr-ctl_socket);
		      		  remotehost=(char *)strndup(pusr+1,strlen(ctl_socket)-strlen(remoteusr)-1);
		      		  remoteport=PORTNO;
		      		  break;
		      	  }
				  if(!pusr){
		      		  remoteusr=NULL;
		      	  	  remotehost=(char *)strndup(ctl_socket,pport-ctl_socket);
		      		  remoteport=atoi((char *)strndup(pport+1,strlen(ctl_socket)-strlen(remotehost)-1));
		      		  break;
		      	  }
		      	  remoteusr=(char *)strndup(ctl_socket,pusr-ctl_socket);
		      	  remotehost=(char *)strndup(pusr+1,pport-pusr-1);
		      	  remoteport=atoi((char *)strndup(pport+1,strlen(ctl_socket)-strlen(remotehost)-strlen(remoteusr)-2));
		      	  break;

		        case 'p':
		      	udp_port=atoi(optarg);
		      	break;
		      	
		        case 'P': 
		      	pre_shared=strdup(optarg);
		      	fprintf(stderr,"Using pre-shared key %s\n",pre_shared);
			enc_type = ENC_PRESHARED;
		      	break;
			case 'k':
			keepalives=1;
			break;
			case 'd':
			daemonize=1;
			break;

		        case 'h':
		        default:
		      	  Usage(programname);
		}
	}
	if(optind < argc) 
		  Usage(programname);
	if (keepalives && remotehost==NULL){
		fprintf(stderr,"\nkeepalive option is valid in client mode only.\n\n");
		Usage(programname);
	}
	if (pre_shared && enc_type == ENC_NOENC){
		fprintf(stderr,"\nWarning: Not using pre-shared key mode, encryption disabled.\n\n");
		pre_shared = NULL;
	}
		
	
	vc_printlog(1,"Verbosity: %d", verbose);
	chksum_crc32gentab();	
	
	switch(enc_type){
		case ENC_NOENC:
			vc_printlog(1,"Encryption Disabled.");
			break;
		case ENC_PRESHARED:
			vc_printlog(1,"Using pre-shared key %s",pre_shared);
			break;
		case ENC_SSH:
			vc_printlog(1,"Using ssh key exchange for authentication");
			break;
	}

	if (daemonize) {
		if (fork() == 0) {
			setsid();
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			if (fork() > 0)
				exit(0); 
		} else exit(0);
	}
	  
	if(!remotehost){
		cryptcab_server(plugname, udp_port, enc_type, pre_shared);
	} else {
		cryptcab_client(plugname, udp_port, enc_type, pre_shared, remoteusr, remotehost, remoteport, keepalives, scp_extra_options);
	}
	exit(0);
}

