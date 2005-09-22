#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include<sys/poll.h>
#include<sys/socket.h>
#include <linux/un.h>

#define BUFSIZE 1024
char buf[BUFSIZE];

main(int argc,char *argv[])
{
	struct sockaddr_un sun;
	int fd;
	int rv;
	static struct pollfd pfd[]={
		{STDIN_FILENO,POLLIN | POLLHUP,0},
		{STDIN_FILENO,POLLIN | POLLHUP,0}};
	static int fileout[]={STDOUT_FILENO,STDOUT_FILENO};
	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",argv[1]);
	fd=socket(PF_UNIX,SOCK_STREAM,0);
	rv=connect(fd,(struct sockaddr *)(&sun),sizeof(sun));
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
