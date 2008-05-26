/* Copyright 2005 Renzo Davoli VDE-2
 * Licensed under the GPL
 * --pidfile/-p and cleanup management by Mattia Belletti.
 * some code remains from uml_switch Copyright 2001, 2002 Jeff Dike and others
 * Modified by Ludovico Gardenghi 2005
 */

#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "../vde_switch/switch.h"
#include "consmgmt.h"
#undef VDE_PQ
#undef OPTPOLL
#ifdef VDE_PQ
#include <packetq.h>
#endif

time_t starting_time;
static struct swmodule *swmh;

char *prog;
unsigned char switchmac[ETH_ALEN];
unsigned int priority=DEFAULT_PRIORITY;

static int hash_size=INIT_HASH_SIZE;
static int numports=INIT_NUMPORTS;


static void recaddswm(struct swmodule **p,struct swmodule *new)
{
	struct swmodule *this=*p;
	if (this == NULL)
		*p=new;
	else 
		recaddswm(&(this->next),new);
}

void add_swm(struct swmodule *new)
{
	static int lastlwmtag;
	new->swmtag= ++lastlwmtag;
	if (new != NULL && new->swmtag != 0) {
		new->next=NULL;
		recaddswm(&swmh,new);
	}
}

static void recdelswm(struct swmodule **p,struct swmodule *old)
{
	struct swmodule *this=*p;
	if (this != NULL) {
		if(this == old)
			*p=this->next;
		else
			recdelswm(&(this->next),old);
	}
}

void del_swm(struct swmodule *old)
{
	if (old != NULL) {
		recdelswm(&swmh,old);
	}
}

/* FD MGMT */
struct pollplus {
	unsigned char type;
	int arg;
	time_t timestamp;
};

static int nfds = 0;
static int nprio =0;
static struct pollfd *fds = NULL;
static struct pollplus **fdpp = NULL;

static int maxfds = 0;

static struct swmodule **fdtypes;
static int ntypes;
static int maxtypes;

#define PRIOFLAG 0x80
#define TYPEMASK 0x7f
#define ISPRIO(X) ((X) & PRIOFLAG)

#define TYPE2MGR(X) (fdtypes[((X) & TYPEMASK)])

unsigned char add_type(struct swmodule *mgr,int prio)
{
	register int i;
	if(ntypes==maxtypes) {
		maxtypes = maxtypes ? 2 * maxtypes : 8;
		if (maxtypes > PRIOFLAG) {
			printlog(LOG_ERR,"too many file types");
			exit(1);
		}
		if((fdtypes = realloc(fdtypes, maxtypes * sizeof(struct swmodule *))) == NULL){
			printlog(LOG_ERR,"realloc fdtypes %s",strerror(errno));
			exit(1);
		}
		memset(fdtypes+ntypes,0,sizeof(struct swmodule *) * maxtypes-ntypes);
		i=ntypes;
	} else
		for(i=0; fdtypes[i] != NULL; i++)
			;
	fdtypes[i]=mgr;
	ntypes++;
	return i | ((prio != 0)?PRIOFLAG:0);
}

void del_type(unsigned char type)
{
	type &= TYPEMASK;
	if (type < maxtypes)
		fdtypes[type]=NULL;
	ntypes--;
}

void add_fd(int fd,unsigned char type,int arg)
{
	struct pollfd *p;
	int index;
	/* enlarge fds and g_fdsdata array if needed */
	if(nfds == maxfds){
		maxfds = maxfds ? 2 * maxfds : 8;
		if((fds = realloc(fds, maxfds * sizeof(struct pollfd))) == NULL){
			printlog(LOG_ERR,"realloc fds %s",strerror(errno));
			exit(1);
		}
		if((fdpp = realloc(fdpp, maxfds * sizeof(struct pollplus *))) == NULL){
			printlog(LOG_ERR,"realloc pollplus %s",strerror(errno));
			exit(1);
		}
	}
	if (ISPRIO(type)) {
		fds[nfds]=fds[nprio];
		fdpp[nfds]=fdpp[nprio];
		index=nprio;
		nprio++;
	} else
		index=nfds;
	if((fdpp[index]=malloc(sizeof(struct pollplus))) == NULL) {
		printlog(LOG_ERR,"realloc pollplus elem %s",strerror(errno));
		exit(1);
	}
	p = &fds[index];
	p->fd = fd;
	p->events = POLLIN | POLLHUP;
	fdpp[index]->type=type;
	fdpp[index]->arg=arg;
	nfds++;
}

static void file_cleanup(void)
{
	register int i;
	for(i = 0; i < nfds; i++)
		TYPE2MGR(fdpp[i]->type)->cleanup(fdpp[i]->type,fds[i].fd,fdpp[i]->arg);
}

void remove_fd(int fd)
{
	register int i;

	for(i = 0; i < nfds; i++){
		if(fds[i].fd == fd) break;
	}
	if(i == nfds){
		printlog(LOG_WARNING,"remove_fd : Couldn't find descriptor %d", fd);
	} else {
		struct pollplus *old=fdpp[i];
		TYPE2MGR(fdpp[i]->type)->cleanup(fdpp[i]->type,fds[i].fd,fdpp[i]->arg);
		if (ISPRIO(fdpp[i]->type)) nprio--;
		memmove(&fds[i], &fds[i + 1], (maxfds - i - 1) * sizeof(struct pollfd));
		memmove(&fdpp[i], &fdpp[i + 1], (maxfds - i - 1) * sizeof(struct pollplus *));
		free(old);
		nfds--;
	}
}

static void main_loop()
{
	time_t now;
	register int n,i;
	while(1) {
#ifdef VDE_PQ
		n=poll(fds,nfds,packetq_timeout);
#else
		n=poll(fds,nfds,-1);
#endif
		now=time(NULL);
		if(n < 0){ 
			if(errno != EINTR)
				printlog(LOG_WARNING,"poll %s",strerror(errno));
		} else {
			for(i = 0; /*i < nfds &&*/ n>0; i++){
				if(fds[i].revents != 0) {
					register int prenfds=nfds;
					n--;
					fdpp[i]->timestamp=now;
					TYPE2MGR(fdpp[i]->type)->handle_input(fdpp[i]->type,fds[i].fd,fds[i].revents,&(fdpp[i]->arg));
					if (nfds!=prenfds) /* the current fd has been deleted */
						break; /* PERFORMANCE it is faster returning to poll */
				}	
/* optimization: most used descriptors migrate to the head of the poll array */
#ifdef OPTPOLL
				else
				{
					if (i < nfds && i > 0 && i != nprio) {
						register int i_1=i-1;
						if (fdpp[i]->timestamp > fdpp[i_1]->timestamp) {
							struct pollfd tfds;
							struct pollplus *tfdpp;
							tfds=fds[i];fds[i]=fds[i_1];fds[i_1]=tfds;
							tfdpp=fdpp[i];fdpp[i]=fdpp[i_1];fdpp[i_1]=tfdpp;
						}
					}
				}
#endif
			}
#ifdef VDE_PQ
			if (packetq_timeout > 0)
				packetq_try();
#endif
		}
	}
}

/* starting/ending routines, main_loop, main*/
#define HASH_TABLE_SIZE_ARG 0x100
#define MACADDR_ARG         0x101
#define PRIORITY_ARG        0x102

static void Usage(void) {
	struct swmodule *p;
	printf(
			"Usage: vde_switch [OPTIONS]\n"
			"Runs a VDE switch.\n"
			"(global opts)\n"
			"  -h, --help                 Display this help and exit\n"
			"  -v, --version              Display informations on version and exit\n"
			);
	for(p=swmh;p != NULL;p=p->next)
		if (p->usage != NULL)
			p->usage();
	printf(
			"\n"
			"Report bugs to "PACKAGE_BUGREPORT "\n"
			);
	exit(1);
}

static void version(void)
{ 
	printf(
			"VDE " PACKAGE_VERSION "\n"
			"Copyright 2003,2004,2005,2006,2007,2008 Renzo Davoli\n"
			"VDE comes with NO WARRANTY, to the extent permitted by law.\n"
			"You may redistribute copies of VDE under the terms of the\n"
			"GNU General Public License v2.\n"
			"For more information about these matters, see the files\n"
			"named COPYING.\n");
	exit(0);
} 

static struct option *optcpy(struct option *tgt, struct option *src, int n, int tag)
{
	register int i;
	memcpy(tgt,src,sizeof(struct option) * n);
	for (i=0;i<n;i++) {
		tgt[i].val=(tgt[i].val & 0xffff) | tag << 16;
	}
	return tgt+n;
}

static int parse_globopt(int c, char *optarg)
{
	int outc=0;
	switch (c) {
		case 'v':
			version();
			break;
		case 'h':
			Usage();
			break;
		default:
			outc=c;
	}
	return outc;
}

static void parse_args(int argc, char **argv)
{
	struct swmodule *swmp;
	struct option *long_options;
	char *optstring;
	static struct option global_options[] = {
		{"help",0 , 0, 'h'},
		{"version", 0, 0, 'v'},
	};
	static struct option optail = {0,0,0,0};
#define N_global_options (sizeof(global_options)/sizeof(struct option))
	prog = argv[0];
	int totopts=N_global_options+1;

	for(swmp=swmh;swmp != NULL;swmp=swmp->next)
		totopts += swmp->swmnopts;
	long_options=malloc(totopts * sizeof(struct option));
	optstring=malloc(2 * totopts * sizeof(char));
	if (long_options == NULL || optstring==NULL)
		exit(2);
	{ /* fill-in the long_options fields */
		register int i;
		char *os=optstring;
		char last=0;
		struct option *opp=long_options;
		opp=optcpy(opp,global_options,N_global_options,0);
		for(swmp=swmh;swmp != NULL;swmp=swmp->next)
			opp=optcpy(opp,swmp->swmopts,swmp->swmnopts,swmp->swmtag);
		optcpy(opp,&optail,1,0);
		for (i=0;i<totopts-1;i++)
		{
			int val=long_options[i].val & 0xffff;
			if(val > ' ' && val <= '~' && val != last)
			{
				*os++=val;
				if(long_options[i].has_arg) *os++=':';
			}
		}
		*os=0;
	}
	{
		/* Parse args */
		int option_index = 0;
		int c;
		while (1) {
			c = GETOPT_LONG (argc, argv, optstring,
					long_options, &option_index);
			if (c == -1)
				break;
			c=parse_globopt(c,optarg);
			for(swmp=swmh;swmp != NULL && c!=0;swmp=swmp->next) {
				if (swmp->parseopt != NULL) {
					if((c >> 7) == 0)
						c=swmp->parseopt(c,optarg);
					else if ((c >> 16) == swmp->swmtag)
						swmp->parseopt(c & 0xffff,optarg),c=0;
				}
			}
		}
	}
	if(optind < argc)
		Usage();
	free(long_options);
	free(optstring);
}

static void init_mods(void)
{
	struct swmodule *swmp;
	for(swmp=swmh;swmp != NULL;swmp=swmp->next)
		if (swmp->init != NULL)
			swmp->init();
}

static void cleanup(void)
{
	struct swmodule *swmp;
	file_cleanup();
	for(swmp=swmh;swmp != NULL;swmp=swmp->next)
		if (swmp->cleanup != NULL)
			swmp->cleanup(0,-1,-1);
}

static void sig_handler(int sig)
{
	printlog(LOG_ERR,"Caught signal %d, cleaning up and exiting", sig);
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
			printlog(LOG_ERR,"Setting handler for %s: %s", signals[i].name,
					strerror(errno));
}

static void start_modules(void);

int main(int argc, char **argv)
{
	starting_time=time(NULL);
	start_modules();
	parse_args(argc,argv);
	atexit(cleanup);
	setsighandlers();
	init_mods();
	loadrcfile();
	main_loop();
	return 0;
}

/* modules: module references are only here! */
static void start_modules(void)
{
	void start_datasock(void);
	void start_consmgmt(void);
	start_datasock();
	start_consmgmt();
}
