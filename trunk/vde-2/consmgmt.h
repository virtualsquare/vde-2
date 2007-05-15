/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __CONSMGMT_H__
#define __CONSMGMT_H__
#include <stdarg.h>

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

typedef int (*intfun)();
#ifdef DEBUGOPT
#define D_PACKET 01000
#define D_MGMT 02000
#define D_IN 01
#define D_OUT 02
#define D_PLUS 01
#define D_MINUS 02
#define D_DESCR 03
#define D_STATUS 04
#define D_ROOT 05
#define D_HASH 010
#define D_PORT 020
#define D_EP 030
#define D_FSTP 040
struct dbgcl {
	char *path; /* debug path for add/del */
	char *help; /* help string. just event mgmt when NULL */
	int tag;    /* tag for event mgmt and simple parsing */
	int *fds;   /* file descriptors for debug */
	intfun (*fun); /* function call dor plugin events */
	void **funarg; /* arg for function calls */
	unsigned short nfds; /* number of active fds */
	unsigned short nfun; /* number of active fun */
	unsigned short maxfds; /* current size of fds */
	unsigned short maxfun; /* current size of both fun and funarg */
	struct dbgcl *next;
};
void adddbgcl(int ncl, struct dbgcl* cl);
#define ADDDBGCL(CL) adddbgcl(sizeof(CL)/sizeof(struct dbgcl),(CL))
void debugout(struct dbgcl* cl, const char *format, ...);
void eventout(struct dbgcl* cl, ...);
int packetfilter(struct dbgcl* cl, ...);
#define DBGOUT(CL, ...) \
	if (__builtin_expect(((CL)->nfds) > 0, 0)) debugout((CL), __VA_ARGS__)
#define EVENTOUT(CL, ...) \
	if (__builtin_expect(((CL)->nfun) > 0, 0)) eventout((CL), __VA_ARGS__)
#define PACKETFILTER(CL, PORT, BUF, LEN) \
	(__builtin_expect((((CL)->nfun) == 0 || ((LEN)=packetfilter((CL), (PORT), (BUF), (LEN)))), 1))
	/*
#define PACKETFILTER(CL, PORT, BUF, LEN)  (LEN)
	*/
#else
#define DBGOUT(CL, ...) 
#define EVENTOUT(CL, ...) 
#define PACKETFILTER(CL, PORT, BUF, LEN)  (LEN)  
#endif

#endif

#ifdef VDEPLUGIN
struct plugin {
	char *name;
	char *help;
	void *handle;
	struct plugin *next;
};
#endif
