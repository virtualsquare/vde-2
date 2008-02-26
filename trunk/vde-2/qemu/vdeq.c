/* Copyright 2003 Renzo Davoli 
 * TNX: 2005.11.18 new syntax mgmt patch by Iain McFarlane <imcfarla@tiscali.co.uk>
 * Licensed under the GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include "compat/poll.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include <config.h>
#include <vde.h>
#include <libvdeplug/libvdeplug.h>

#define SWITCH_MAGIC 0xfeedface
#define BUFSIZE 2048
#define ETH_ALEN 6
#define MAXDESCR 128

int exit_value = 256; /* out of range for exit status possible values */
static int nb_nics;
VDECONN **conn;

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

static int countnewnics(int argc,char *argv[])
{
	register int nics=0;
	register int netflag=0;
	while (argc > 0) {
		if (strcmp(argv[0],"-net")==0)
			netflag=1;
		else {
			if (netflag && (strncmp(argv[0],"vde",3)==0))
				nics++;
			netflag=0;
		}
		argv++;
		argc--;
	}
	return nics;
}

static int isdaemonize(int argc,char *argv[])
{
	register int daemonize=0;
	if(strcmp(filename,"qemu")==0){
		int daemonadds=0;
		while (argc > 0) {
			if (strcmp(argv[0],"-daemonize")==0)
				daemonize=1;
			if ((strcmp(argv[0],"-vnc")==0) || (strcmp(argv[0],"-nographic")==0))
				daemonadds=1;
			argv++;
			argc--;
		}
		if(daemonize && !daemonadds) daemonize = 0;
	}
	else {
		while (argc > 0 && !daemonize) {
			if (strcmp(argv[0],"-daemonize")==0)
				daemonize=1;
			else {
				argv++;
				argc--;
			}
		}
	}
	return daemonize;
}


static void usage(void) 
{
	if (strcmp(vdeqname,"vdeq") != 0 && strncmp(vdeqname,"vde",3)==0) {
		fprintf(stderr,"Usage: %s [-h]\n"
				"\t %s ...qemu options... -net vde[,vlan=n][,sock=sock] ... \n"
				"Old syntax:\n"
				"\t %s  [-sock sock1 [,sock2...]] qemu_options\n"
				"\t (%s executes a qemu machine named %s, \n\t  output of \"%s -h\" follows)\n\n", vdeqname,vdeqname,vdeqname,vdeqname,filename,filename);
		execlp(filename,filename,"-h",(char *) 0);
	} else {
		fprintf(stderr,"Usage: %s [-h]\n"
				"\t %s qemu_executable ...qemu options... -net vde[,vlan=n][,sock=sock] ... \n"
				"Old syntax:\n"
				"\t %s qemu_executable [-sock sock1 [,sock2...]] qemu_options\n", vdeqname,vdeqname, vdeqname);
		exit(0);
	}
}

static void cleanup()
{
	register int i;
	for (i=0; i<nb_nics; i++) {
		if (conn[i] != NULL)
			vde_close(conn[i]);
	}
}

static void sig_handler(int sig)
{
	fprintf(stderr,"%s: Caught signal %d, cleaning up and exiting\n", vdeqname, sig);
	cleanup();
	signal(sig, SIG_DFL);
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
			fprintf(stderr,"Setting handler for %s: %s\n", signals[i].name,
					strerror(errno));
}

static void sigchld_handler(int sig)
{
	int ev;
	wait(&ev);
	if (WIFEXITED(ev))
		exit_value=WEXITSTATUS(ev);
	else
		exit_value=255;
}

static int checkver(char *prog)
{
	char *newargv[3];
	int fd[2];
	int f,len,version=0;
	char buf[257];
	newargv[0]=prog;
	newargv[1]="-h";
	newargv[2]=0;
	buf[256]=0;
	if (pipe(fd) < 0) {
	  perror("pipe");
	  exit(1);
	}
	if ((f=fork()) > 0) {
		int status;
		close(fd[1]);
		len=read(fd[0],buf,256);
		if (len>0) {
			int i;
			for(i=0;i<len && version==0;i++) {
				if(strncmp(buf+i,"version ",8)==0) {
					int v1,v2,v3;
					sscanf(buf+i+8,"%d.%d.%d",&v1,&v2,&v3);
					version=(v1 << 16) + (v2 << 8) + v3;
				}
			}
		}
		close(fd[0]);
		waitpid(f,&status,0);
	}
	else if (f==0) {
		close(fd[0]);
		dup2(fd[1],1);
		dup2(fd[1],2);
		close(fd[1]);
		if (execvp(prog,newargv) < 0) {
			exit(1);
		}
	}
	return version;
}

static char *parsevdearg(char *arg,char **sock,int *pport, int fd)
{
	char newarg[128];
	int vlan=0;
	*sock=VDESTDSOCK;
	*pport=0;
	printf("arg %s\n", arg);
	while(*arg){
		while (*arg==',') arg++;
		if (strncmp(arg,"vlan=",5)==0) {
			vlan=atoi(arg+5);
			while (*arg != 0 && *arg != ',')
				arg++;
		}
		else if (strncmp(arg,"sock=",5)==0) {
			arg+=5;
			if (*arg=='\"') {
				arg++;
				*sock=arg;
				while (*arg != 0 && *arg != '\"')
					arg++;
			} else {
				*sock=arg;
				while (*arg != 0 && *arg != ',')
					arg++;
			}
			if (*arg != 0) {
				*arg=0; arg++;
			}
		}
		else if (strncmp(arg,"port=",5)==0) {
			*pport=atoi(arg+5);
			while (*arg != 0 && *arg != ',')
				arg++;
		}
	}

	snprintf(newarg,128,"tap,vlan=%d,fd=%d%s%s",vlan,fd,(*arg == 0)?"":",",arg);
	return strdup(newarg);
}

int main(int argc, char **argv)
{
  char *argsock=NULL,**sockname;
	int *ports;
  int result;
  register ssize_t nx;
  int newargc;
	int daemonize;
  char **newargv;
  typedef int pair[2];
  pair *sp;
  register int i,j;
	int oldsyntax=0;
	int newsyntax=0;
	int ver;
  mode_t mode = 0700;

  vdeqname=basename(argv[0]);
	//callerpwd=getpwuid(getuid());
	/* OLD SYNTAX MGMT */
	if (strncmp(vdeqname,"vdeo",4) == 0) {
		oldsyntax=1;
		if (strcmp(vdeqname,"vdeoq") != 0) {
			filename=vdeqname+4;
		}
	}
	else if (strcmp(vdeqname,"vdeq") != 0 && strncmp(vdeqname,"vde",3)==0) {
		filename=vdeqname+3;
	}
	else if (argc > 1) {
	  filename=argv[1];
		argc--;
		argv++;
  } else {
	  usage();
  }
	daemonize=isdaemonize(argc-1,argv+1);
	if ((ver=checkver(filename)) < 0x800) 
		oldsyntax=1;
	if (!oldsyntax) {
		nb_nics=countnewnics(argc-1,argv+1);
		if (nb_nics > 0)
			newsyntax=1;
	}
  if ((argc > 1 && (
			  strcmp(argv[1],"-h")==0 ||
			  strcmp(argv[1],"-help")==0 ||
			  strcmp(argv[1],"--help")==0
			  )) || (
			  strcmp(filename,"-h")==0 ||
			  strcmp(filename,"-help")==0 ||
			  strcmp(filename,"--help")==0
		  )) {
	  usage();
  } else if (argc > 2 && (
		  (strcmp(argv[1],"-vdesock")==0) ||
		  (strcmp(argv[1],"-sock")==0) ||
		  (strcmp(argv[1],"-unix")==0))
	    ){
	  argsock=argv[2];
	  argv+=2;
	  argc-=2;
  } else
	  argsock=NULL;

    if (argc > 2 && ((strcmp(argv[1],"--mod")==0))
	    ){
	sscanf(argv[2],"%o",&mode);
	argv+=2;
	argc-=2;
    }

	if (!newsyntax) {
		if (argsock == NULL)
			nb_nics=1;
		else
			nb_nics=countnics(argsock);
		if (!oldsyntax && nb_nics > 1)
			fprintf(stderr,
					"Warning: all the vde connections will be connected to one net interface\n"
					"         to configure several interface use the new syntax -net vde\n");
	}

	if ((sp= (pair *) malloc(nb_nics * 2 * sizeof (int)))<0) {
		perror("malloc nics");
		exit(1);
	}

	if ((conn=(VDECONN **) calloc (nb_nics,sizeof(VDECONN *))) <0) {
	  perror("calloc conn");
	  exit(1);
  }

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
  if ((ports= (int *) calloc(nb_nics, sizeof(int)))<0) {
	  perror("malloc ports");
	  exit(1);
  }

	if (newsyntax)
	{
		int netflag;
		int vdeint;
		newargv=argv;
		newargc=argc;
		for (i=1,netflag=0,vdeint=0;i<argc;i++) {
			if (strcmp(argv[i],"-net")==0)
				netflag=1;
			else {
				if (netflag && strncmp(argv[i],"vde",3) == 0)
				{
					argv[i]=parsevdearg(argv[i]+3,&sockname[vdeint],&ports[vdeint],sp[vdeint][0]);
					vdeint++;
				}
				netflag=0;
			}
		}
	} else
  {
		if (argsock==NULL)
			sockname[0]=VDESTDSOCK;
		else
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
		newargc=argc+2+(2*nb_nics);
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
		} else {
			for (i=0; i<nb_nics; i++) {
				char numfd[30];
				sprintf(numfd,"tap,vlan=0,fd=%d",sp[i][0]);
				newargv[2*i+1]="-net";
				newargv[2*i+2]=strdup(numfd);
			}
			newargv[2*nb_nics+1]="-net";
			newargv[2*nb_nics+2]="nic";
		}
		for (i=(2*nb_nics)+3,j=1;j<argc;i++,j++) newargv[i]=argv[j];

		newargv[i]=0;
	}

  if ((pollv= (struct pollfd *) malloc(sizeof(struct pollfd) * 2 * nb_nics))<0) {
		perror("malloc pollfd");
	  exit(1);
  }
	setsighandlers();
  for (i=0; i<nb_nics; i++) {
		struct vde_open_args vdearg={ports[i],NULL,mode};
		conn[i]=vde_open(sockname[i],"vdeqemu",&vdearg);
	  pollv[2*i+1].fd=vde_datafd(conn[i]);
	  pollv[2*i].fd=sp[i][1];
	  pollv[2*i].events= pollv[2*i+1].events=POLLIN|POLLHUP;
  }

#if 0
  {
	  int i=0;
	  while(newargv[i])
		  printf("%s ", newargv[i++]);
	  printf("\n");
  }
#endif

  if (fork()) {
	  close(0); 
	  signal(SIGCHLD, sigchld_handler);
	  for (i=0; i<nb_nics; i++) 
		  close(sp[i][0]);
		if (daemonize)
			daemon(1,1);
	  for(;;) {
			if ((result=poll(pollv,2*nb_nics,-1)) < 0) {
				if (errno != EINTR) {
					perror("poll");
					cleanup();
					exit(1);
				} else {
					if ((exit_value < 256) || !daemonize)
						exit(exit_value);
				}
			} else {
				for (i=0; i<nb_nics; i++) {
					if (pollv[2*i].revents & POLLHUP || pollv[2*i+1].revents & POLLHUP)
						break;
					if (pollv[2*i].revents & POLLIN) {
						if ((nx=read(sp[i][1],bufin,sizeof(bufin))) <= 0) {
							if (nx < 0) 
								perror("read");
							cleanup();
							exit(nx < 0);
						}
						//fprintf(stderr,"RX from qemu %d\n",nx);
						if (vde_send(conn[i],bufin,nx,0) < 0) {
							perror("sendto");
							cleanup();
							exit(1);
						}
					}
					if (pollv[2*i+1].revents & POLLIN) {
						if ((nx=vde_recv(conn[i],bufin,BUFSIZE,0)) < 0) {
							perror("recvfrom");
							cleanup();
							exit(1);
						}
						//fprintf(stderr,"TX to qemu %d\n",nx);
						if (write(sp[i][1],bufin,nx) < 0) {
							if (errno != ECONNREFUSED)
								perror("write");
							cleanup();
							exit(errno != ECONNREFUSED);
						}
					}
				}
			}
		}
	} else {
		for (i=0; i<nb_nics; i++) {
			close(sp[i][1]);
			close(vde_datafd(conn[i]));
			close(vde_ctlfd(conn[i]));
		}
		execvp(filename,newargv);
	}  
	cleanup();
	return(0);
}
