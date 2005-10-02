/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __TUNTAP_H__
#define __TUNTAP_H__


struct comlist {
	char *path;
	char *syntax;
	char *help;
	int (*doit)();
	unsigned char type;
	struct comlist *next;
};
	

#define NOARG 0
#define INTARG 1
#define STRARG 2
#define WITHFD 0x80

void printlog(int priority, const char *format, ...);
void loadrcfile(void);
void setmgmtperm(char *path);

void printoutc(int fd, const char *format, ...);
void addcl(int ncl,struct comlist *cl);
#define ADDCL(CL) addcl(sizeof(CL)/sizeof(struct comlist),(CL))

#endif
