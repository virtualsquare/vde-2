/* Copyright 2005 Renzo davoli VDE-2
 * Some code from vde_switch Copyright 2002 Jeff Dike
 * Licensed under the GPLv2
 */

#ifndef __SWITCH_H__
#define __SWITCH_H__

typedef unsigned char uchar;
/* FAST SPANNING TREE PROTOCOL (experimental)*/
#define FSTP
/* POLL Main LOOP Optimization */
#define OPTPOLL

#ifdef _MALLOC_DEBUG
#define free(X) ({ printf("MDBG-FREE %x %s %d\n",(X),__FILE__,__LINE__); \
		    free(X); })
#define malloc(X) ({ void *x; x=malloc(X); \
		    printf("MDBG-MALLOC %x %s %d\n",x,__FILE__,__LINE__); \
		    x; })
#define strdup(X) ({ void *x; x=strdup(X); \
		    printf("MDBG-STRDUP %x %s %d\n",x,__FILE__,__LINE__); \
		    x; })
#define realloc(Y,X) ({ void *x,*old; \
		    old=(Y);\
		    x=realloc(old,(X)); \
		    printf("MDBG-REALLOC %x->%x %s %d\n",old,x,__FILE__,__LINE__); \
		    x; })
#endif

struct swmodule {
	char *swmname; /* module name */
	char swmtag;   /* module tag - computer by the load sequence */
	char swmnopts; /* number of options for getopt */
	struct option *swmopts; /* options for getopt */
	void (*usage)(void); /* usage function: command line opts explanation */
	int (*parseopt)(int parm,char *optarg); /* parse getopt output */
	void (*init)(void); /* init */
	void (*handle_input)(unsigned char type,int fd,int revents,int *arg); /* handle input */
	void (*cleanup)(unsigned char type,int fd,int arg); /*cleanup for files or final if fd == -1 */
	struct swmodule *next;
};

void add_swm(struct swmodule *new);
void del_swm(struct swmodule *old);
unsigned char add_type(struct swmodule *mgr,int prio);
void del_type(unsigned char type);
void add_fd(int fd,unsigned char type,int arg);
void remove_fd(int fd);

#define STDRCFILE "/etc/vde.rc"

#define ETH_ALEN 6

#define INIT_HASH_SIZE 128
#define DEFAULT_PRIORITY 0x8000
#define INIT_NUMPORTS 32
#define DEFAULT_COST 20000000 /* 1Mbit line */

extern char *prog;
extern unsigned char switchmac[];
extern unsigned int  priority;

#define NUMOFVLAN 4095
#define NOVLAN 0xfff

#endif
