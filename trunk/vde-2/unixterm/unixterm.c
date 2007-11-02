/* Copyright 2005 Renzo Davoli VDE-2
 * Licensed under the GPLv2
 *
 * Minimal terminal emulator on a UNIX stream socket
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>
#ifndef HAVE_POLL
#include <utils/poll.h>
#endif
#include <sys/socket.h>
#include <sys/un.h>

#include <config.h>

#include <vde.h>

#define BUFSIZE 1024
char buf[BUFSIZE];

int main(int argc,char *argv[])
{
	struct sockaddr_un sun;
	int fd;
	int rv;
	static struct pollfd pfd[]={
		{STDIN_FILENO,POLLIN | POLLHUP,0},
		{STDIN_FILENO,POLLIN | POLLHUP,0}};
	static int fileout[]={STDOUT_FILENO,STDOUT_FILENO};
	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",argv[1]);
	if((fd=socket(PF_UNIX,SOCK_STREAM,0))<0) {
		perror("Socket opening error");
		exit(-1);
	}
	if ((rv=connect(fd,(struct sockaddr *)(&sun),sizeof(sun))) < 0) {
		perror("Socket connecting error");
		exit(-1);
	}
	pfd[1].fd=fileout[0]=fd;
	while(1) {
		int m,i,n=poll(pfd,2,-1);
		for(i=0;n>0;i++) {
			if(pfd[i].revents & POLLHUP)
				exit(0);
			if(pfd[i].revents & POLLIN) {
				n--;
				if((m=read(pfd[i].fd,buf,BUFSIZE)) == 0)
					exit(0);
				write(fileout[i],buf,m);
			} 
		}
	}
}
