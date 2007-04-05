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
#define WITHFILE 0x40
#define WITHFD 0x80

void printlog(int priority, const char *format, ...);
void loadrcfile(void);
void setmgmtperm(char *path);

void printoutc(FILE *fd, const char *format, ...);
void addcl(int ncl,struct comlist *cl);
#define ADDCL(CL) addcl(sizeof(CL)/sizeof(struct comlist),(CL))

#ifdef DEBUGOPT
struct dbgcl {
	char *path;
	char *help;
	int *fds; 
	struct dbgcl *next;
};
void adddbgcl(int ncl, struct dbgcl* cl);
#define ADDDBGCL(CL) adddbgcl(sizeof(CL)/sizeof(struct dbgcl),(CL))
void debugout(struct dbgcl* cl, const char *format, ...);
#define DBGOUT(CL, ...) \
	if (__builtin_expect(*((CL)->fds) >= 0, 0)) debugout((CL), __VA_ARGS__)
#else
#define DBGOUT(CL, ...) 
#endif

#endif
