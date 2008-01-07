/* Copyright 2008 Renzo Davoli VDE-2
 * co-authors Ludovico Gardenghi, Filippo Giunchedi, Luca Bigliardi
 * Kernel VDE switch: requires ipn and kvde_switch modules in the kernel
 * Licensed under the GPLv2
 */

#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <grp.h>
#include <linux/if.h>
#include <config.h>
#include <vde.h>

/* will be inserted in a af_ipn.h include */
#ifndef AF_IPN
#define AF_IPN    34  /* IPN sockets      */
#define PF_IPN    AF_IPN
#endif
#define AF_IPN_STOLEN    33  /* IPN temporary sockets      */
#define PF_IPN_STOLEN    AF_IPN_STOLEN

#define IPN_ANY 0
#define IPN_BROADCAST 1
#define IPN_HUB 1
#define IPN_VDESWITCH 2
#define IPN_VDESWITCH_L3 3

#define IPN_SO_PREBIND 0x80
#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#define IPN_SO_CHANGE_NUMNODES 2
#define IPN_SO_HANDLE_OOB 3
#define IPN_SO_WANT_OOB_NUMNODES 4
#define IPN_SO_MTU (IPN_SO_PREBIND | 0)
#define IPN_SO_NUMNODES (IPN_SO_PREBIND | 1)
#define IPN_SO_MSGPOOLSIZE (IPN_SO_PREBIND | 2)
#define IPN_SO_FLAGS (IPN_SO_PREBIND | 3)
#define IPN_SO_MODE (IPN_SO_PREBIND | 4)

#define IPN_PORTNO_ANY -1

#define IPN_DESCRLEN 128

#define IPN_FLAG_LOSSLESS 1
#define IPN_FLAG_TERMINATED 0x1000

#define IPN_NODEFLAG_TAP   0x10    /* This is a tap interface */
#define IPN_NODEFLAG_GRAB  0x20    /* This is a grab of a real interface */

/* Ioctl defines */
#define IPN_SETPERSIST_NETDEV   _IOW('I', 200, int) 
#define IPN_CLRPERSIST_NETDEV   _IOW('I', 201, int) 
#define IPN_CONN_NETDEV          _IOW('I', 202, int) 
#define IPN_JOIN_NETDEV          _IOW('I', 203, int) 
#define IPN_SETPERSIST           _IOW('I', 204, int) 

static int kvdefd;
static char *prog="kde_switch";
static char *vdesocket;
static char *pidfile;
static char pidfile_path[PATH_MAX];
static int logok=0;

static struct option global_options[] = {
	{"help", 0 , 0, 'h'},
	{"version", 0, 0, 'v'},
	{"numports", 1, 0, 'n'},
	{"sock", 1, 0, 's'},
	{"mod", 1, 0, 'm'},
	{"group", 1, 0, 'g'},
	{"daemon", 0, 0, 'd'},
	{"pidfile", 1, 0, 'p'},
	{"tap", 1, 0, 't'},
	{"grab", 1, 0, 'g'},
};

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",prog);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, PATH_MAX - strlen(pidfile_path));
	else
		strcpy(pidfile_path, pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

static void cleanup(void)
{
	if (vdesocket)
		unlink(vdesocket);
	if (pidfile)
		unlink(pidfile_path);
}

static void Usage(int module) {
	if (module)
		printf(
				"%s\n"
				"Runs a kernel VDE switch (it requires ipn and kvde_switch modules loaded).\n",prog);
	else
		printf(
				"Usage: %s [OPTIONS]\n"
				"Runs a kernel VDE switch.\n"
				"  -h, --help              Display this help and exit\n"
				"  -v, --version           Display informations on version and exit\n"
				"  -n  --numports          Number of ports (default 32)\n"
				"  -s, --sock SOCK         switch socket pathname\n"
				"  -m, --mod MODE          Standard access mode for comm sockets (octal)\n"
				"  -g, --group GROUP       Group owner for comm sockets\n"
				"  -d, --daemon            Daemonize vde_switch once run\n"
				"  -p, --pidfile PIDFILE   Write pid of daemon to PIDFILE\n"
				//"  -f, --rcfile            Configuration file (overrides /etc/vde2/vde_switch.\n"
				"  -t, --tap TAP           Enable routing through TAP tap interface\n"
				"  -G, --grab INT          Enable routing grabbing an existing interface\n",prog);
	printf(
			"\n"
			"Report bugs to "PACKAGE_BUGREPORT "\n");

	exit(1);
}

static void version(void)
{
	printf(
			"VDE " PACKAGE_VERSION "\n"
			"Kernel VDE switch\n"
			"Copyright 2003,2004,2005,2006,2007,2008 Renzo Davoli\n"
			"VDE comes with NO WARRANTY, to the extent permitted by law.\n"
			"You may redistribute copies of VDE under the terms of the\n"
			"GNU General Public License v2.\n"
			"For more information about these matters, see the files\n"
			"named COPYING.\n");
	exit(0);
}

static void sig_handler(int sig)
{
	printlog(LOG_ERR,"Caught signal %d, cleaning up and exiting", sig);
	cleanup();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

static void setsighandlers(void)
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

struct extinterface {
	char type;
	char *name;
	struct extinterface *next;
};

static struct extinterface *extifhead;
static struct extinterface **extiftail=&extifhead;

static void addextinterface(char type,char *name)
{
	struct extinterface *new=malloc(sizeof (struct extinterface));
	if (new) {
		new->type=type;
		new->name=strdup(name);
		new->next=NULL;
		*extiftail=new;
		extiftail=&(new->next);
	}
}

static void runextinterfaces(void)
{
	struct extinterface *iface,*oldiface;
	struct ifreq ifr;
	for (iface=extifhead;iface != NULL;iface=oldiface)
	{
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name,iface->name,IFNAMSIZ);
		if (iface->type == 't')
			ifr.ifr_flags=IPN_NODEFLAG_TAP;
		else
			ifr.ifr_flags=IPN_NODEFLAG_GRAB;
	//	printf("ioctl\n");
		if (ioctl(kvdefd, IPN_CONN_NETDEV, (void *) &ifr) < 0) {
			printlog(LOG_ERR, "%s interface %s error: %s", iface->name,
					(iface->type == 't')?"tap":"grab",strerror(errno));
			exit(-1);
		}
		free(iface->name);
		oldiface=iface->next;
		free(iface);
	}
	extifhead=NULL;
}

int main(int argc,char *argv[])
{
	struct sockaddr_un sun;
	gid_t grp_owner = -1;
	int option_index = 0;
	int c;
	int daemonize=0;
	int sockmode = -1;
	int family = AF_IPN;
	kvdefd = socket(AF_IPN,SOCK_RAW,IPN_BROADCAST);
	if (kvdefd < 0) {
		family=AF_IPN_STOLEN;
		kvdefd = socket(AF_IPN_STOLEN,SOCK_RAW,IPN_BROADCAST);
		if (kvdefd < 0) {
			Usage(1);
		}
	}
	atexit(cleanup);
	while (1) {
		int value;
		c = GETOPT_LONG (argc, argv, "hvn:s:m:g:dp:t:g:",
				global_options, &option_index);
		if (c == -1)
			        break;
		switch (c) {
			case 'h':
				Usage(0);
				break;
			case 'v':
				version();
				break;
			case 'n':
				value=atoi(optarg);
				if (setsockopt(kvdefd,0,IPN_SO_NUMNODES,&value,sizeof(value)) < 0)
					printlog(LOG_ERR,"set numnodes %d",value);
				break;
			case 's':
				vdesocket=strdup(optarg);
				break;
			case 'm':
				sscanf(optarg,"%o",&value);
				sockmode=value;
				if (setsockopt(kvdefd,0,IPN_SO_MODE,&value,sizeof(value)) < 0)
					printlog(LOG_ERR,"set mode %o",value);
				break;
			case 'g': {
									struct group *grp;
									if (!(grp = getgrnam(optarg))) {
										printlog(LOG_ERR,"No such group '%s'\n", optarg);
										exit(1);
									}
									grp_owner=grp->gr_gid;
								}
				break;
			case 'd':
				daemonize=1;
				break;
			case 'p':
				pidfile=strdup(optarg);
				break;
			case 't':
			case 'G':
				addextinterface(c,optarg);
				break;
		}
	}
	if(optind < argc)
		Usage(0);
	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize) {
		openlog(basename(prog), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"VDE_SWITCH started");
	}
	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();

	if (!vdesocket)
		vdesocket=VDESTDSOCK;
	sun.sun_family = family;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",vdesocket);
	if(bind(kvdefd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		if (strcmp(vdesocket,VDESTDSOCK)==0) {
			vdesocket=VDETMPSOCK;
			snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",vdesocket);
			if(bind(kvdefd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
				printlog(LOG_ERR,"cannot bind socket %s",vdesocket);
				vdesocket=NULL;
				exit(-1);
			}
		} else {
			printlog(LOG_ERR,"cannot bind socket %s",vdesocket);
			vdesocket=NULL;
			exit(-1);
		}
	}
	if(sockmode >= 0 && chmod(vdesocket, sockmode) <0) {
		printlog(LOG_ERR, "chmod: %s", strerror(errno));
		exit(1);
	}
	runextinterfaces();
	setsighandlers();
	while ((c=getchar()) != EOF)
		;
	return 0;
}
