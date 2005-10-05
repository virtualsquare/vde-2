/* Copyright 2004 Renzo Davoli
 * Reseased under the GPLv2 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define MAXDESCR 128

enum request_type { REQ_NEW_CONTROL };
struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
};

static unsigned char bufin[BUFSIZE];

static struct sockaddr_un inpath;

static int send_fd(char *name, int fddata, struct sockaddr_un *datasock, int intno, int port)
{
	int pid = getpid();
	struct request_v3 req;
	int fdctl;
	struct passwd *callerpwd;

	struct sockaddr_un sock;

	callerpwd=getpwuid(getuid());

	if((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit(1);
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
	if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
		snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name); /* FALLBACK TO VDE v1 */
		if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
			perror("connect");
			exit(1);
		}
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=REQ_NEW_CONTROL+((port > 0)?port << 8:0);

	req.sock.sun_family=AF_UNIX;
	snprintf(req.sock.sun_path, sizeof(req.sock.sun_path), "%s_%05d", name, pid);
	memcpy(&inpath,&req.sock,sizeof(req.sock));

	snprintf(req.description,MAXDESCR,"tuntaplib user=%s PID=%d SOCK=%s",
			callerpwd->pw_name,pid,req.sock.sun_path);


  if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0){
		perror("bind");
		exit(1);
	}

	if (send(fdctl,&req,sizeof(req)-MAXDESCR+strlen(req.description),0) < 0) {
		perror("send");
		exit(1);
	}

	if (recv(fdctl,datasock,sizeof(struct sockaddr_un),0)<0) {
		perror("recv");
		exit(1);
	}

	return fdctl;
}

static struct pollfd pollv[]={{0,POLLIN|POLLHUP,0},{0,POLLIN|POLLHUP,0}};

main(int argc,char *argv[])
{
	int fd,fddata;
	struct sockaddr_un dataout,datain;
	int datainsize,result,nx;
	register int i;
	/*printf("argc = %d\n",argc);
	for (i=0;i<argc;i++)
		printf("argv %d -%s-\n",i,argv[i]);*/
	if (argc != 3 && argv[0][0] != '-') {
		fprintf(stderr,"vdetap must be activated by libvdetap e.g.\n"
				"   sh%% export LD_PRELOAD=/usr/local/lib/libvdetap.so\n"
				"   csh%% setenv LD_PRELOAD /usr/local/lib/libvdetap.so\n");
		exit (-1);
	}

	fd = atoi(argv[1]);
	for (i=3;i<FD_SETSIZE;i++)
		if (i != fd)
			close(i);
	if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(1);
	}
	send_fd(argv[2],fddata,&dataout,0,0);
	pollv[0].fd=fd;
	pollv[1].fd=fddata;
	for(;;) {
		result=poll(pollv,2,-1);
		if (pollv[0].revents & POLLHUP || pollv[1].revents & POLLHUP)
			break;
		if (pollv[0].revents & POLLIN) {
			nx=read(fd,bufin,sizeof(bufin));
			/*fprintf(stderr,"RX from pgm %d\n",nx);*/
			//send(connected_fd,bufin,nx,0);
			sendto(fddata,bufin,nx,0,(struct sockaddr *) &dataout, sizeof(struct sockaddr_un));
		}
		if (pollv[1].revents & POLLIN) {
			datainsize=sizeof(datain);
			nx=recvfrom(fddata,bufin,BUFSIZE,0,(struct sockaddr *) &datain, &datainsize);
			/*fprintf(stderr,"TX to pgm %d\n",nx);*/
			write(fd,bufin,nx);
		}
	}
}

