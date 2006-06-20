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
#include <vde.h>
#include <libvdeplug/libvdeplug.h>
#include <pwd.h>

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define MAXDESCR 128

VDECONN *conn;

static unsigned char bufin[BUFSIZE];

static struct pollfd pollv[]={{0,POLLIN|POLLHUP,0},{0,POLLIN|POLLHUP,0}};

main(int argc,char *argv[])
{
	int fd,fddata;
	struct sockaddr_un dataout,datain;
	socklen_t datainsize;
	int result,nx;
	register int i;
	/*printf("argc = %d\n",argc);
	for (i=0;i<argc;i++)
		printf("argv %d -%s-\n",i,argv[i]);*/
	if (argc != 4 && argv[0][0] != '-') {
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
	/* TODO insert argv[3] in descr */
	conn=vde_open(argv[2],"tuntaplib",NULL);
	pollv[0].fd=fd;
	pollv[1].fd=vde_datafd(conn);
	for(;;) {
		result=poll(pollv,2,-1);
		if (pollv[0].revents & POLLHUP || pollv[1].revents & POLLHUP)
			break;
		if (pollv[0].revents & POLLIN) {
			nx=read(fd,bufin,sizeof(bufin));
			/*fprintf(stderr,"RX from pgm %d\n",nx);*/
			//send(connected_fd,bufin,nx,0);
			vde_send(conn,bufin,nx,0);
		}
		if (pollv[1].revents & POLLIN) {
			datainsize=sizeof(datain);
			nx=vde_recv(conn,bufin,BUFSIZE,0);
			/*fprintf(stderr,"TX to pgm %d\n",nx);*/
			write(fd,bufin,nx);
		}
	}
	vde_close(conn);
}

