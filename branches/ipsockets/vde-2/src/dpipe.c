/* Copyright 2003 Renzo Davoli 
 * Licensed under the GPL
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#if 0
#define execvp(X,Y) \
	({ char **y; \
	 fprintf(stderr,"execvp \"%s\" -",(X)); \
	 for (y=(Y); *y != NULL; y++) \
	 fprintf(stderr,"\"%s\"",*y); \
	 fprintf(stderr,"\n"); \
	 sleep (10); \
	 })
#endif

static char *progname;

int splitindex(int argc, char *argv[], int *dirchar) 
{
	register int i;

	for (i=0; i<argc; i++) {
		if (*dirchar == argv[i][0] && argv[i][1] == '=' ) {
			(argv[i])++;*dirchar=0;
		}
		if (argv[i][0] == '=') {
			if (argv[i][1] == '}' || argv[i][1] == '{')
				*dirchar=argv[i][1];
			break;
		}
	}
	return i;
}

void usage()
{
	fprintf(stderr,"Usage:\n\t%s cmd1 [arg1...] = cmd2 [arg2...]\n\n",progname);
	kill(getpgrp(),SIGTERM);
	exit (-1);
}

static int alternate_stdin;
static int alternate_stdout;
static void alternate_fd()
{
	char numstr[10];
	alternate_stdin=open("/dev/null",O_RDONLY);
	alternate_stdout=open("/dev/null",O_RDONLY);
	close(alternate_stdin);
	close(alternate_stdout);
	snprintf(numstr,10,"%d",alternate_stdin);
	setenv("ALTERNATE_STDIN",numstr,1);
	snprintf(numstr,10,"%d",alternate_stdout);
	setenv("ALTERNATE_STDOUT",numstr,1);
}

int recmain(int argc, char *argv[],int olddirchar) 
{
	int split;
	int newdirchar=olddirchar;

	split=splitindex(argc,argv,&newdirchar);
	if (split >= argc) {
		if (newdirchar != 0)
			usage();
		execvp(argv[0],argv);
	}
	else {
		char **argv1,**argv2;
		int p1[2],p2[2];

		if (argc < 3 || split == 0 || split == argc-1) 
			usage();

		pipe(p1);
		if (olddirchar == 0) pipe(p2);
		argv[split]=NULL;
		argv1=argv;
		argv2=argv+(split+1);

		if (fork()) {
			switch (olddirchar) {
				case 0:
					close(p1[1]); close(p2[0]);
					if (p1[0] != alternate_stdin){
						dup2(p1[0],alternate_stdin);
						close(p1[0]);
					}
					if (p1[0] != alternate_stdout){
						dup2(p2[1],alternate_stdout);
						close(p2[1]);
					}
					break;
				case '}':
					close(p1[0]);
					dup2(p1[1],STDOUT_FILENO);
					close(p1[1]);
					break;
				case '{':
					close(p1[1]);
					dup2(p1[0],STDIN_FILENO);
					close(p1[0]);
					break;
				default:
					fprintf(stderr,"Error\n");
			}
			execvp(argv1[0],argv1);
		} else {
			switch (olddirchar) {
				case 0:
					close(p2[1]); close(p1[0]);
					dup2(p2[0],STDIN_FILENO);
					dup2(p1[1],STDOUT_FILENO);
					close(p2[0]); close(p1[1]);
					break;
				case '}':
					close(p1[1]);
					dup2(p1[0],STDIN_FILENO);
					close(p1[0]);
					break;
				case '{':
					close(p1[0]);
					dup2(p1[1],STDOUT_FILENO);
					close(p1[1]);
					break;
				default:
					fprintf(stderr,"Error\n");
			}
			recmain(argc-split-1,argv2,newdirchar);
		}
	}
	return 0;
}

int main(int argc, char *argv[]) 
{

	int split;
	char **argv1,**argv2;
	int p1[2],p2[2];
	int dirchar=0;
	int daemonize=0;
	char *pidfile=NULL;
	int pgrp;
	int argflag;
	int err=0;

	progname=argv[0];
	argv++;
	argc--;

	do {
		argflag=0;
		if (argv[0] && *argv[0] == '-') {
			argflag++;
			argv[0]++;
			if (*argv[0] == '-') {
				argv[0]++;
				if (strcmp(argv[0],"daemon") == 0)
					daemonize = 1;
				else if (strcmp(argv[0],"pidfile") == 0) {
					pidfile = argv[argflag];
					argflag++;
				} else {
					fprintf(stderr,"unknown option --%s\n",argv[0]);
					err++;
				}
			} else {
				while (*argv[0] != 0) {
					switch (*argv[0]) {
						case 0: break;
						case 'd': daemonize = 1; break;
						case 'p': pidfile = argv[argflag];
											argflag++;
											break;
						default: fprintf(stderr,"unknown option -%c\n",*argv[0]);
										 err++;
					}
					if (*argv[0] != 0) argv[0]++;
				}
			}
			argv += argflag;
			argc -= argflag;
		}
	} while (argflag);

	if (err)
		exit(1);

	if (daemonize != 0)
		daemon(0,0);
	else if (setpgrp() != 0) {
		fprintf(stderr,"Err: cannot create pgrp\n");
		exit(1);
	}

	pgrp = getpgrp();

	if (pidfile != NULL) {
		FILE *f=fopen(pidfile, "w");
		if (f != NULL) {
			fprintf(f,"-%d\n",pgrp);
			fclose(f);
		}
	}

	alternate_fd();
	split=splitindex(argc,argv,&dirchar);

	if (argc < 3 || split == 0 || split >= argc-1) 
		usage();

	pipe(p1);
	pipe(p2);
	argv[split]=NULL;
	argv1=argv;
	argv2=argv+(split+1);

	if (fork()) {
		close(p1[1]); close(p2[0]);
		dup2(p1[0],STDIN_FILENO);
		dup2(p2[1],STDOUT_FILENO);
		close(p1[0]); close(p2[1]);
		execvp(argv1[0],argv1);
	} else {
		close(p2[1]); close(p1[0]);
		dup2(p2[0],STDIN_FILENO);
		dup2(p1[1],STDOUT_FILENO);
		close(p1[1]); close(p2[0]);
		recmain(argc-split-1,argv2,dirchar);
	}
	return (0);
}
