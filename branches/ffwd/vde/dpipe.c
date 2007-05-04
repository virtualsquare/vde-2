/* Copyright 2003 Renzo Davoli 
 * Licensed under the GPL
 */

#include <config.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

int p1[2],p2[2];

int splitindex(int argc, char *argv[]) {
	register int i;

	for (i=1; i<argc && strcmp(argv[i],"=") != 0; i++)
		;
	if (i>=argc)
		return (-1);
	else
		return i;
}
		

int main(int argc, char *argv[]) {

	int split;
	char **argv1,**argv2;
	
	split=splitindex(argc,argv);

	if (argc < 4 || split < 0 || split == argc-1) {
		fprintf(stderr,"Usage: %s cmd1 [arg1...] = cmd2 [arg2...]\n",argv[0]);
		exit (-1);
	}
	
	pipe(p1);
	pipe(p2);
	argv[split]=NULL;
	argv1=argv+1;
	argv2=argv+(split+1);

	if (fork()) {
		close(p1[1]); close(p2[0]);
		dup2(p1[0],STDIN_FILENO);
		dup2(p2[1],STDOUT_FILENO);
		execvp(argv1[0],argv1);
	} else {
		close(p2[1]); close(p1[0]);
		dup2(p2[0],STDIN_FILENO);
		dup2(p1[1],STDOUT_FILENO);
		execvp(argv2[0],argv2);
	}
	return (0);
}
