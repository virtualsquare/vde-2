#ifndef _VDEPLUGIN_H
#define _VDEPLUGIN_H
#include <stdarg.h>
#include <stdio.h>

/* command type constants */
/* doit signature:
 * int doit (
 *            FILE *f,        *** only when WITHFILE
 *            int fd,         *** only when WITHFD
 *            int|char *arg)  *** when INTARG or STRARG */
/* if type==NOARG  int doit(void)
 * if type==INTARG   int doit(int arg)
 * if type==WITHFILE|WITHFD|STRARG int doit(FILE *f,int fd,char *arg)
 * doit returns 0 on success otherwise it returns a valid errno code */
#define NOARG 0 /*the command require no args */
#define INTARG 1 /* arg is an integer */
#define STRARG 2 /* arg is a string */
#define WITHFILE 0x40 /* command needs to return text output.
												 (the output will be sent to the user using
												 "0000 DATA END WITH '.'") */
#define WITHFD 0x80 /* fd is the identifier of the mgmt connection issuing
											 the command. fd== -1 when the command is executed by
											 an rc file. Fd should not be considered a file
											 descriptor, */

typedef int (*intfun)();

/* command structure */
struct comlist {
	char *path; /*pathname of the command: pathname structured */
	char *syntax; /*description of the syntax */
	char *help; /*description of the command for help listings */
	int (*doit)(); /* the call back to the command code */
	unsigned char type; /* types of command: see constants above */
	/* the following field is for management. never set or change it*/
	struct comlist *next;
};

/* pre-defined TAGs */
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
/* debug/event structure */
struct dbgcl {
	char *path; /* pathname structured debug/event request */
	char *help; /* description for debug options listing
								 if help==NULL the entry will be used only for 
								 plugin event publish/subscribe not directly accessible
								 from the user interface */
	int tag;    /* numerical tag of the debug/event */
	/* the following fields are for management. never set or change them*/
	int *fds;
	intfun (*fun);
	void **funarg;
	unsigned short nfds;
	unsigned short nfun;
	unsigned short maxfds;
	unsigned short maxfun;
	struct dbgcl *next;
};

/* plugin element: one element named "vde_plugin_data" must
 * be defined otherwise the dynamic library will not be recognized
 * as a vde plugin module */
struct plugin {
	/* name of the plugin, it should be unique, maybe pathname structured.
	 * it identifies the plugin for listing and unloading plugins */
	char *name;
	/* description of the plugin for listings */
	char *help;
	/* the following fields should never be set or changed by
	 * plugin modules */
	void *handle;
	struct plugin *next;
};

/* this adds a new management fd */
void mgmtnewfd(int new);

#define ADDCL(CL) addcl(sizeof(CL)/sizeof(struct comlist),(CL))
#define ADDDBGCL(CL) adddbgcl(sizeof(CL)/sizeof(struct dbgcl),(CL))
#define DELCL(CL) delcl(sizeof(CL)/sizeof(struct comlist),(CL))
#define DELDBGCL(CL) deldbgcl(sizeof(CL)/sizeof(struct dbgcl),(CL))
#define DBGOUT(CL, FORMAT, ...) \
	  if (__builtin_expect(((CL)->nfds) > 0, 0)) debugout((CL), (FORMAT), __VA_ARGS__)
#define EVENTOUT(CL, ...) \
	  if (__builtin_expect(((CL)->nfun) > 0, 0)) eventout((CL), __VA_ARGS__)


int eventadd(int (*fun)(struct dbgcl *event,void *arg,va_list v),char *path,void *arg);
int eventdel(int (*fun)(struct dbgcl *event,void *arg,va_list v),char *path,void *arg);

void debugout(struct dbgcl* cl, const char *format, ...);

void addcl(int ncl,struct comlist *cl);
void delcl(int ncl,struct comlist *cl);

#ifdef DEBUGOPT
void adddbgcl(int ncl,struct dbgcl *cl);
void deldbgcl(int ncl,struct dbgcl *cl);
#endif

void printoutc(FILE *f, const char *format, ...);


#endif
