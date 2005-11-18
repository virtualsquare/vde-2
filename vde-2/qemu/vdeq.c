/* Copyright 2003 Renzo Davoli 
 * TNX: 2005.11.18 new syntax mgmt patch by Iain McFarlane <imcfarla@tiscali.co.uk>
 * Licensed under the GPL
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <pwd.h>

#include <vde.h>

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define ETH_ALEN 6
#define MAXDESCR 128

enum request_type { REQ_NEW_CONTROL };

struct request_v3 {
  uint32_t magic;
  uint32_t version;
  enum request_type type;
  struct sockaddr_un sock;
	char description[MAXDESCR];
};

static struct passwd *callerpwd;

static char** inpath;

static int send_fd(char *name, int fddata, struct sockaddr_un *datasock, int intno)
{
  int pid = getpid();
  struct request_v3 req;
  int fdctl;
	int port=0;
  struct sockaddr_un sock;

  if((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }

	if (name == NULL)
		name=VDESTDSOCK;
	else {
		char *split;
		if(name[strlen(name)-1] == ']' && (split=rindex(name,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (*name==0) name=VDESTDSOCK;
		}
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
	if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
		if (name == VDESTDSOCK) {
			name=VDETMPSOCK;
			snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
			if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
				snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name);
				if(connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))){
					perror("connect");
					exit(1);
				}
			}
		}
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=REQ_NEW_CONTROL+(port << 8);
	req.sock.sun_family=AF_UNIX;

	/* First choice, return socket from the switch close to the control dir*/
	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	sprintf(req.sock.sun_path, "%s.%05d-%02d", name, pid, 0);
	if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0){
		/* if it is not possible -> /tmp */
		memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
		sprintf(req.sock.sun_path, "/tmp/vde.%05d-%02d", pid, 0);
		if(bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0) {
			perror("bind");
			exit(1);
		}
	}

	snprintf(req.description,MAXDESCR,"vdeqemu user=%s PID=%d SOCK=%s INT=%d",
			callerpwd->pw_name,pid,req.sock.sun_path,intno);

	inpath[intno]=strdup(req.sock.sun_path);

  if (send(fdctl,&req,sizeof(req),0) < 0) {
    perror("send");
    exit(1);
  }

  if (recv(fdctl,datasock,sizeof(struct sockaddr_un),0)<0) {
	  perror("recv");
	  exit(1);
  }

  return fdctl;
}

unsigned char bufin[BUFSIZE];

struct pollfd *pollv;

char *filename;
char *vdeqname;
#define NUMW 10

static int countnics(const char *s)
{
	register int nics=1;
	while (*s) {
		if (*s==',') nics++;
		s++;
	}
	return nics;
}

static void usage() 
{
	if (strcmp(vdeqname,"vdeq") != 0 && strncmp(vdeqname,"vde",3)==0) 
		fprintf(stderr,"Usage: %s [-h]\n"
				"\t %s  [-sock sock1 [,sock2...]] qemu_options\n"
				"\t (%s executes a qemu machine named %s)\n", vdeqname,vdeqname,vdeqname,filename);
	else 
		fprintf(stderr,"Usage: %s [-h]\n"
				"\t %s qemu_executable [-sock sock1 [,sock2...]] qemu_options\n", vdeqname, vdeqname);
	exit(0);
}

static void leave()
{
	fprintf(stderr,"qemu exited: %s quits\n", vdeqname);
	exit(0);
}

int main(int argc, char **argv)
{
  int *fddata;
  char *argsock,**sockname;
  struct sockaddr_un *dataout,datain;
  socklen_t datainsize;
  int result;
  int *connected_fd;
  register ssize_t nx;
  int args;
  int newargc;
  char **newargv;
  typedef int pair[2];
  pair *sp;
  register int i;
  int nb_nics;
	int oldsyntax=0;

  vdeqname=basename(argv[0]);
	callerpwd=getpwuid(getuid());
	/* OLD SYNTAX MGMT */
	if (strncmp(vdeqname,"vdeo",4) == 0) {
		oldsyntax=1;
		if (strcmp(vdeqname,"vdeoq") != 0) {
			filename=vdeqname+4;
			args=1;
		}
	}
	else if (strcmp(vdeqname,"vdeq") != 0 && strncmp(vdeqname,"vde",3)==0) {
		filename=vdeqname+3;
		args=1;
	}
	else if (argc > 1) {
	  filename=argv[1];
	  args=2;
  } else {
	  usage();
  }
  if ((argc > args && (
			  strcmp(argv[args],"-h")==0 ||
			  strcmp(argv[args],"-help")==0 ||
			  strcmp(argv[args],"--help")==0
			  )) || (
			  strcmp(filename,"-h")==0 ||
			  strcmp(filename,"-help")==0 ||
			  strcmp(filename,"--help")==0
		  )) {
	  usage();
  } else if (argc > args+1 && 
		  (strcmp(argv[args],"-vdesock")==0) ||
		  (strcmp(argv[args],"-sock")==0) ||
		  (strcmp(argv[args],"-unix")==0) ||
		  (strcmp(argv[args],"-s")==0)
	    ){
	  argsock=argv[args+1];
	  args+=2;
  } else
	  argsock=strdup(VDESTDSOCK);

  nb_nics=countnics(argsock);
  if ((sp= (pair *) malloc(nb_nics * 2 * sizeof (int)))<0) {
	  perror("malloc nics");
	  exit(1);
  }
  if ((inpath=(char **) malloc (nb_nics * sizeof(char *))) <0) {
	  perror("malloc inpath");
	  exit(1);
  }
	memset(inpath,0,(nb_nics * sizeof(char *)));

  for (i=0; i<nb_nics; i++) {
  	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp[i]) < 0){
	  	perror("socketpair");
	  	exit(1);
		}
  }

  if ((sockname= (char **) malloc(sizeof(char *) * nb_nics))<0) {
	  perror("malloc sockname");
	  exit(1);
  }

  {
	  register char *s=argsock;
	  register char oldch;
	  i=0;
	  do {
		sockname[i++]=s;
		while (*s != ',' && *s != '\0')
			s++;
		oldch=*s;
		*s=0;
		s++;
	  } while (oldch != 0);
  }

/*  printf("-- %s --\n",numfd);
  printf("as %s\n",argsock);
	    for (i=0; i<nb_nics; i++)
		    printf("%d -> %s\n",i,sockname[i]); */
  newargc=argc+1+(2*oldsyntax)+(2*nb_nics)-args;
  if ((newargv=(char **) malloc ((newargc+1)* sizeof(char *))) <0) {
	  perror("malloc");
	  exit(1);
  }

  newargv[0]=filename;
	if (oldsyntax) {
		for (i=0; i<nb_nics; i++) {
			char numfd[10];
			sprintf(numfd,"%d",sp[i][0]);
			newargv[2*i+1]="-tun-fd";
			newargv[2*i+2]=strdup(numfd);
		}
		{
			char nnics[10];
			sprintf(nnics,"%d",nb_nics);
			newargv[2*nb_nics+1]="-nics";
			newargv[2*nb_nics+2]=strdup(nnics);
		}
		for (i=(2*nb_nics)+3;args<argc;i++,args++) newargv[i]=argv[args];
	} else {
		for (i=0; i<nb_nics; i++) {
			char numfd[30];
			sprintf(numfd,"tap,vlan=0,fd=%d",sp[i][0]);
			newargv[2*i+1]="-net";
			newargv[2*i+2]=strdup(numfd);
		}
		for (i=(2*nb_nics)+1;args<argc;i++,args++) newargv[i]=argv[args];
	}

  newargv[i]=0;

  if ((fddata= (int *) malloc(sizeof(int) * nb_nics))<0) {
	  perror("malloc fddata");
	  exit(1);
  }
  if ((connected_fd= (int *) malloc(sizeof(int) * nb_nics))<0) {
	  perror("malloc connected_fd");
	  exit(1);
  }
  if ((dataout= (struct sockaddr_un *) malloc(sizeof(struct sockaddr_un) * nb_nics))<0) {
	  perror("malloc dataout");
	  exit(1);
  }

  if ((pollv= (struct pollfd *) malloc(sizeof(struct pollfd) * 2 * nb_nics))<0) {
	  perror("malloc fddata");
	  exit(1);
  }
  for (i=0; i<nb_nics; i++) {
	  if((fddata[i] = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
		  perror("socket");
		  exit(1);
	  }
	  connected_fd[i]=send_fd(sockname[i], fddata[i], &(dataout[i]), i);
	  pollv[2*i+1].fd=fddata[i];
	  pollv[2*i].fd=sp[i][1];
	  pollv[2*i].events= pollv[2*i+1].events=POLLIN|POLLHUP;
  }

  if (fork()) {
	  close(0); 
	  signal(SIGCHLD, leave);
	  for (i=0; i<nb_nics; i++) 
		  close(sp[i][0]);
	  for(;;) {
		  result=poll(pollv,2*nb_nics,-1);
		  for (i=0; i<nb_nics; i++) {
			  if (pollv[2*i].revents & POLLHUP || pollv[2*i+1].revents & POLLHUP)
				  break;
			  if (pollv[2*i].revents & POLLIN) {
				  nx=read(sp[i][1],bufin,sizeof(bufin));
				  //fprintf(stderr,"RX from qemu %d\n",nx);
				  //send(connected_fd,bufin,nx,0);
				  sendto(fddata[i],bufin,nx,0,(struct sockaddr *) &(dataout[i]), sizeof(struct sockaddr_un));
			  }
			  if (pollv[2*i+1].revents & POLLIN) {
				  datainsize=sizeof(datain);
				  nx=recvfrom(fddata[i],bufin,BUFSIZE,0,(struct sockaddr *) &datain, &datainsize);
				  //fprintf(stderr,"TX to qemu %d\n",nx);
				  write(sp[i][1],bufin,nx);
			  }
		  }
	  }
  } else {
	  for (i=0; i<nb_nics; i++) {
		  close(sp[i][1]);
		  close(fddata[i]);
		  close(connected_fd[i]);
	  }
	  execvp(filename,newargv);
  }  
	for (i=0; i<nb_nics; i++) {
		if (inpath[i] != NULL)
			unlink(inpath[i]);
	}
  return(0);
}
