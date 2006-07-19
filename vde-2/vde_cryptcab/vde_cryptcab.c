/* vde_cryptcab.c
 * Copyright © 2006 Daniele Lacamera <root@danielinux.net>
 * From an idea by Renzo Davoli <renzo@cs.unibo.it>
 * 
 * Released under the terms of GNU GPL v.2
 * 
 * see:
 * http://www.gnu.org/copyleft/gpl.html
 */

#include "config.h"
#include "blowfish.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include "vde.h"

#define PORTNO 7667
static char *plugname;
static char *programname;
static char *remoteusr;
static char *remotehost;
static int localport;
static int remoteport;


#ifndef HAVE_STRNDUP
/*
 * This could be written in a more efficient way. No time to do it now.
 */
static char *strndup(const char *s, size_t n)
{
	size_t len = MIN(n, strlen(s));
	char *new = (char *) malloc (len + 1);

	if (new == NULL)
		return NULL;

	new[len] = '\0';
	return (char *) memcpy (new, s, len);
}
#endif


/*
 * Manage dead children, avoid zombies.
 */
void zombie_carnage(int signo)
{
	int pid;
	wait(&pid);
}

/*
 * Call the generate_key() and then transmit the key to the server via 
 * OpenSSH secure copy.
 */
static struct peer *generate_and_xmit(struct peer *ret){
	char command[255];
	int i,res;
	struct hostent *target;

	fprintf(stderr,"Generating new key..\n");
	ret=generate_key(ret);
	/*fprintf(stderr,"Key:");
	for(i=0;i<16;i++)
		fprintf(stderr,"%02X",ret->key[i]);
	fprintf(stderr,"\n");
	*/

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
		
	if(remoteusr)
		sprintf(command,"scp /tmp/.blowfish.key %s@%s:/tmp/.%s.key\0", remoteusr, remotehost, ret->id);
	else
		sprintf(command,"scp /tmp/.blowfish.key %s:/tmp/.%s.key\0", remotehost, ret->id);
	//fprintf(stderr,"Contacting host: %s ",remotehost);
	res=system(command);
	
	if(res==0){
	//	fprintf(stderr,"Key successfully transferred using a secure channel.\n");
	}else{
		fprintf(stderr,"Couldn't transfer the secret key.\n");
		exit(253);
	}
	return ret;
}

/*
 * Manage dynamic address changing, client side.
 */
static void handover(struct peer *p)
{
	fprintf(stderr,"Doing handover.\n");
	vde_close(p->plug);
	usleep(1000000);
	p=(struct peer *)generate_and_xmit(p);
	p->state=ST_OPENING;
	p->next=NULL;
	p->counter=0;
	login(p);
}

/*
 * Send an identification packet, similar to login packet, if server
 * doesn't remind us for any reason (typically server restart or device handover)
 */
static void send_id(struct peer *p)
{
	send_udp(p->id,FILENAMESIZE,p,CMD_IDENTIFY);
}

/*
 * Request an handover to the client. We remind it, but its key is no more valid.
 */
static void send_handover(struct peer *p)
{
	send_udp(p->id,FILENAMESIZE,p,CMD_HANDOVER);
}

/*
 * Handover packet is crypted. Check its validity, i.e. it is coming from the server.
 * Avoid "handover storm" DoS attack to the client.
 */
static int valid_handover(struct datagram *pkt, struct peer *p)
{
	return (pkt->len!=16)||(strncmp(pkt->data,p->id,FILENAMESIZE))?0:1;
}

/*
 * Execute a naif vde_plug process, attach it to the two peer pipes to exchange data 
 * with cable in both directions.
void
old_vde_plug(struct peer *p){
int r;
	pipe(p->toplug);
	pipe(p->tocable);
	p->pid=fork();
	if(p->pid==0){
		close (STDIN_FILENO);
		dup(p->toplug[0]);
		close (STDOUT_FILENO);
		dup(p->tocable[1]);
		close(p->toplug[1]);
		close(p->tocable[0]);
		r=execl("/usr/bin/vde_plug","vde_plug",plugname,(char*)(0));
		if(r==-1)
			r=execl("/usr/local/bin/vde_plug","vde_plug",plugname,(char*)(0));
		if (r==-1)
		perror ("vde_plug executable not found.\n");
		exit(0);
	}	
		close(p->toplug[0]);
		close(p->tocable[1]);
}

*/


void
vde_plug(struct peer *p)
{
	int r;
	p->plug=vde_open(plugname,"vde_cryptcab",NULL);
	if(!p->plug)
	{
		perror ("libvdeplug");
		exit(1);
	}
}



/*
 * Usage implies exit.
 */
static void Usage(void)
{

	fprintf(stderr,"Usage: %s [-s socketname] [-c [remoteuser@]remotehost[:remoteport]] [-p localport] [-d] \n",programname);
	exit(1);
}

/*
 * Main.
 */
int main(int argc, char **argv)
{
	int wire;
	struct sockaddr_in myaddr;
	struct sockaddr_in to;
	struct datagram *pkt;
	struct peer *p1;
	programname=argv[0];		
	plugname="/tmp/vde.ctl";
	localport=PORTNO;
	sigset(SIGCHLD,zombie_carnage);
  {
	  int c;
	  while (1) {
		  int option_index = 0;
		  char *ctl_socket;
		  const char sepusr='@';
		  const char sepport=':';
		  char *pusr,*pport;

		  static struct option long_options[] = {
			  {"sock", 1, 0, 's'},
			  {"vdesock", 1, 0, 's'},
			  {"unix", 1, 0, 's'},
			  {"localport", 1, 0, 'p'},
			  {"connect",1,0,'c'},
			  {"help",0,0,'h'},
			  {0, 0, 0, 0}
		  };
		  c = GETOPT_LONG (argc, argv, "s:p:c:h",
				  long_options, &option_index);
		  if (c == -1)
			  break;
		  switch (c) {
			  case 's':
				  plugname=strdup(optarg);
				  break;
			  case 'c':
				  ctl_socket=strdup(optarg);

				  pusr=strchr(ctl_socket,sepusr);
				  pport=strchr(ctl_socket,sepport);
				  
				  if( ( pusr != strrchr(ctl_socket,sepusr)) || 
					(pport != strrchr(ctl_socket,sepport)) ||
						(pport && pusr>pport) )
					  Usage();
				  
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
				localport=atoi(optarg);
				break;
				
			  case 'h':
			  default:
				  Usage();
		  }
	  }
	  if(optind < argc)
		  Usage();
  }

	memset ((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(localport);
	
	wire=socket(PF_INET,SOCK_DGRAM,0);
	if (bind(wire,(struct sockaddr *) &myaddr, sizeof(myaddr))<0)
		        {perror("bind socket"); exit(3);}
	
	blowfish_init(wire);
	if( (remotehost) && strlen(remotehost)>0 ) {
		p1=generate_and_xmit(NULL);
		p1->state=ST_OPENING;
		p1->next=NULL;
		login(p1);
		addpeer(p1);
	}
	
	for(;;){
		pkt=blowfish_select(0);
//		fprintf(stderr,".");
		if(pkt!=NULL){
			p1=getpeer(pkt->orig->in_a);
			if(pkt->src==SRC_VDE){
				if(p1 && (p1->state==ST_AUTH || p1->state==ST_SERVER)){
					send_udp(pkt->data,pkt->len,p1,PKT_DATA);
				}
				continue;
			}
			else if(pkt->src==SRC_BF){
				if(p1 && (p1->state==ST_AUTH || p1->state==ST_SERVER)){
					vde_send(p1->plug,pkt->data,pkt->len,0);	
				}else if(p1 && p1->state==ST_IDSENT){
					p1->state==ST_SERVER;
				}else{
					
					deny_access(pkt->orig);
				}
			}
			else if(pkt->src==SRC_CTL){
				switch(pkt->data[0]){
					case CMD_LOGIN:
						if(p1 && p1->state==ST_SERVER)
							break;
						if(!p1){
							p1=malloc(sizeof(struct peer));
							bzero(p1,sizeof(struct peer));
							memcpy(&(p1->in_a),&(pkt->orig->in_a),sizeof(struct sockaddr_in));
							addpeer(p1);
							p1->state=ST_OPENING;
						}
						p1->counter=0;
						rcv_login(pkt,p1);
						break;
						
					case CMD_RESPONSE:
						if(!p1){
							p1=(struct peer*)getpeerbynewaddr(pkt->orig);
							if(p1){
							  memcpy(&p1->in_a,&pkt->orig->in_a, sizeof(struct sockaddr_in));
							  bzero(&p1->handover_a,sizeof(struct sockaddr_in));
							}	
						}
						if(p1){
							rcv_response(pkt, p1);
						}
						break;
						
					case CMD_CHALLENGE:
						if(p1 && (p1->state==ST_OPENING || p1->state==ST_IDSENT)){
							rcv_challenge(pkt, p1);
						}
						break;
						
					case CMD_AUTH_OK:
						if(p1 && p1->state==ST_WAIT_AUTH){
							p1->state=ST_SERVER;
							p1->counter=0;
							vde_plug(p1);
						}
						break;
						
					case CMD_HANDOVER:
						if(p1 && valid_handover(pkt,p1));
							handover(p1);			
						break;
						
					case CMD_IDENTIFY:
						fprintf(stderr,"ID received...");
						p1=(struct peer*)getpeerbyid(pkt);
						if(p1){
							fprintf(stderr,"Client is known. Sending handover.\n");
							// case 0: client changed transport address
							memcpy(&p1->handover_a,&pkt->orig->in_a, sizeof(struct sockaddr_in));
							send_handover(p1);
						}else{
							fprintf(stderr,"Client is not known. Sending challenge.\n");
							// case 1: server restarted
							p1=malloc(sizeof(struct peer));
							bzero(p1,sizeof(struct peer));
							memcpy(&(p1->in_a),&(pkt->orig->in_a),sizeof(struct sockaddr_in));
							addpeer(p1);
							p1->state=ST_OPENING;
							p1->counter=0;
							rcv_login(pkt,p1);
						}
						break;
						
					case CMD_DENY:
						if(p1 &&  (remotehost!=NULL) ){
							p1->state=ST_OPENING;
							send_id(p1);
						}
						break;
					default:
						deny_access(pkt->orig);
				}	
				
			}
			
		}
		
	}
	
	exit (0);
}

	
	
