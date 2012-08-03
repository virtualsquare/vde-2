/* Copyright 2005 Renzo Davoli VDE-2
 * Licensed under the GPLv2
 *
 * Minimal terminal emulator on a UNIX stream socket
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <libvdehist.h>

char *prompt;
static struct termios tiop;

static void cleanup(void)
{
	fprintf(stderr,"\n");
	tcsetattr(STDIN_FILENO,TCSAFLUSH,&tiop);
}

static void sig_handler(int sig)
{ 
	cleanup();
	signal(sig, SIG_DFL);
	if (sig == SIGTERM)
		_exit(0);
	else
		kill(getpid(), sig);
} 

static void setsighandlers()
{
	/* setting signal handlers.
	 * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 * ignores all the others signals which could cause termination. */
	struct { int sig; const char *name; int ignore; } signals[] = {
		{ SIGHUP, "SIGHUP", 0 },
		{ SIGINT, "SIGINT", 0 },
		{ SIGPIPE, "SIGPIPE", 1 },
		{ SIGALRM, "SIGALRM", 1 },
		{ SIGTERM, "SIGTERM", 0 },
		{ SIGUSR1, "SIGUSR1", 1 },
		{ SIGUSR2, "SIGUSR2", 1 },
		{ SIGPROF, "SIGPROF", 1 },
		{ SIGVTALRM, "SIGVTALRM", 1 },
#ifdef VDE_LINUX
		{ SIGPOLL, "SIGPOLL", 1 },
#ifdef SIGSTKFLT
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
#endif
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
#ifdef SIGUNUSED
		{ SIGUNUSED, "SIGUNUSED", 1 },
#endif
#endif
#ifdef VDE_DARWIN
		{ SIGXCPU, "SIGXCPU", 1 },
		{ SIGXFSZ, "SIGXFSZ", 1 },
#endif
		{ 0, NULL, 0 }
	};

	int i;
	for(i = 0; signals[i].sig != 0; i++)
		if(signal(signals[i].sig,
					signals[i].ignore ? SIG_IGN : sig_handler) < 0)
			fprintf(stderr,"Error setting handler for %s: %s\n", signals[i].name,
					strerror(errno));
}

#define BUFSIZE 1024
static char *copy_header_prompt (int vdefd,int termfd,char *sock)
{
	char buf[BUFSIZE];
	int n;
	char *prompt;
	while (1) {
		struct pollfd wfd={vdefd,POLLIN|POLLHUP,0};
		poll(&wfd,1,-1);
		while ((n=read(vdefd,buf,BUFSIZE))>0) {
			if (buf[n-2]=='$' &&
					buf[n-1]==' ') {
				n-=2;
				buf[n]=0;
				while (n>0 && buf[n] !='\n')
					n--;
				write(termfd,buf,n+1);
				asprintf(&prompt,"%s[%s]: ",buf+n+1,sock);
				return prompt;
			} else
				write(termfd,buf,n);
		}
	}
}

int main(int argc,char *argv[])
{
	struct sockaddr_un sun;
	int fd;
	int rv;
	int flags;
	struct termios newtiop;
	static struct pollfd pfd[]={
		{STDIN_FILENO,POLLIN | POLLHUP,0},
		{STDIN_FILENO,POLLIN | POLLHUP,0}};
	//static int fileout[]={STDOUT_FILENO,STDOUT_FILENO};
	struct vdehiststat *vdehst;
	setsighandlers();
	tcgetattr(STDIN_FILENO,&tiop);
	atexit(cleanup);
	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",argv[1]);
	//asprintf(&prompt,"vdterm[%s]: ",argv[1]);
	if((fd=socket(PF_UNIX,SOCK_STREAM,0))<0) {
		perror("Socket opening error");
		exit(-1);
	}
	if ((rv=connect(fd,(struct sockaddr *)(&sun),sizeof(sun))) < 0) {
		perror("Socket connecting error");
		exit(-1);
	}
	newtiop=tiop;
	newtiop.c_cc[VMIN]=1;
	newtiop.c_cc[VTIME]=0;
	newtiop.c_lflag &= ~ICANON;
	newtiop.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO,TCSAFLUSH,&newtiop);
	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
	pfd[1].fd=fd;
	prompt=copy_header_prompt(fd,STDOUT_FILENO,argv[1]);
	vdehst=vdehist_new(STDIN_FILENO,fd);
	write(STDOUT_FILENO,prompt,strlen(prompt)+1);
	while(1) {
		poll(pfd,2,-1);
		//printf("POLL %d %d\n",pfd[0].revents,pfd[1].revents);
		if(pfd[0].revents & POLLHUP ||
				pfd[1].revents & POLLHUP)
			exit(0);
		if(pfd[0].revents & POLLIN) {
			if (vdehist_term_to_mgmt(vdehst) != 0)
				exit(0);
		}
		if(pfd[1].revents & POLLIN)
			vdehist_mgmt_to_term(vdehst);
		//printf("POLL RETURN!\n");
	}
}
