/* Copyright 2006 Renzo Davoli 
 * from vde_plug Davoli Gardenghi
 */

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <libgen.h>
#include <libvdeplug/libvdeplug.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <vde.h>

#define BUFSIZE 2048

#ifdef VDE_LINUX
#include <net/if.h>
#include <linux/if_tun.h>
#endif

#ifdef VDE_DARWIN
#define TAP_PREFIX "/dev/"
#endif

VDECONN *conn;

char *prog;
int logok;
static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];

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

static void cleanup(void)
{
	if((pidfile != NULL) && unlink(pidfile_path) < 0) {
		printlog(LOG_WARNING,"Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
	}

	vde_close(conn);
}

static void sig_handler(int sig)
{
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
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
		{ SIGUNUSED, "SIGUNUSED", 1 },
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
			perror("Setting handler");
}

struct pollfd pollv[]={{0,POLLIN|POLLHUP},{0,POLLIN|POLLHUP},{0,POLLIN|POLLHUP}};

static void usage(void) {
	fprintf (stderr,"Usage: %s [-p portnum] [-g group] [-m mod] [-s sock] -daemon tap_name\n\n",prog);
	exit(-1);
}

#ifdef VDE_LINUX
int open_tap(char *dev)
{
	struct ifreq ifr;
	int fd;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0){
		printlog(LOG_ERR,"Failed to open /dev/net/tun %s",strerror(errno));
		return(-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
	/*printf("dev=\"%s\", ifr.ifr_name=\"%s\"\n", ifr.ifr_name, dev);*/
	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0){
		printlog(LOG_ERR,"TUNSETIFF failed %s",strerror(errno));
		close(fd);
		return(-1);
	}
	return(fd);
}
#endif

#ifdef VDE_DARWIN
int open_tap(char *dev)
{
	int fd;
	int prefixlen = strlen(TAP_PREFIX);
	char *path = NULL;
	if (*dev == '/')
		fd=open(dev, O_RDWR);
	else
	{
		path = malloc(strlen(dev) + prefixlen + 1);
		if (path != NULL)
		{
			snprintf(path, strlen(dev) + prefixlen + 1, "%s%s", TAP_PREFIX, dev);
			fd=open(path, O_RDWR);
			free(path);
		}
		else
			fd = -1;
	}

	if (fd < 0)
	{
		printlog(LOG_ERR,"Failed to open tap device %s: %s", (*dev == '/') ? dev : path, strerror(errno));
		return(-1);
	}
	return fd;
}
#endif

unsigned char bufin[BUFSIZE];

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

int main(int argc, char **argv)
{
	static char *sockname=NULL;
	static char *tapname=NULL;
	int daemonize=0;
	int result;
	int tapfd;
	register ssize_t nx;
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
	int c;
	prog=argv[0];
	while (1) {
		int option_index = 0;

		static struct option long_options[] = {
			{"sock", 1, 0, 's'},
			{"port", 1, 0, 'p'},
			{"help",0,0,'h'},
			{"mod",1,0,'m'},
			{"group",1,0,'g'},
			{"daemon",0,0,'d'},
			{"pidfile", 1, 0, 'P'},
			{0, 0, 0, 0}
		};
		c = GETOPT_LONG (argc, argv, "hdPp:s:m:g:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'p':
				open_args.port=atoi(optarg);
				if (open_args.port <= 0 || open_args.port > 255 )
					usage(); //implies exit
				break;

			case 'h':
				usage(); //implies exit
				break;

			case 's':
				sockname=strdup(optarg);
				break;

			case 'm':
				sscanf(optarg,"%o",&(open_args.mode));
				break;

			case 'g':
				open_args.group=strdup(optarg);
				break;

			case 'd':
				daemonize=1;
				break;

			case 'P':
				pidfile=strdup(optarg);
				break;

			default:
				usage(); //implies exit
		}
	}

	if (daemonize) {
		openlog(basename(prog), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"VDE_PLUG2TAP started");
	}
	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 1)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();

	if (optind < argc)
		tapname=argv[optind];
	atexit(cleanup);
	setsighandlers();

	tapfd=open_tap(tapname);
	if(tapfd<0)
		exit(1);
	conn=vde_open(sockname,"vde_plug:",&open_args);
	if (conn == NULL)
		exit(1);

	pollv[0].fd=tapfd;
	pollv[1].fd=vde_datafd(conn);
	pollv[2].fd=vde_ctlfd(conn);

	for(;;) {
		result=poll(pollv,3,-1);
		if ((pollv[0].revents | pollv[1].revents | pollv[2].revents) & POLLHUP ||
				pollv[2].revents & POLLIN) 
			break;
		if (pollv[0].revents & POLLIN) {
			nx=read(tapfd,bufin,sizeof(bufin));
			/* if POLLIN but not data it means that the stream has been
			 * closed at the other end */
			//fprintf(stderr,"%s: RECV %d %x %x \n",prog,nx,bufin[0],bufin[1]);
			if (nx<=0)
				break;
			vde_send(conn,bufin,nx,0);
		}
		if (pollv[1].revents & POLLIN) {
			nx=vde_recv(conn,bufin,sizeof(bufin),0);
			if (nx<=0)
				break;
			write(tapfd,bufin,nx);
			//fprintf(stderr,"%s: SENT %d %x %x \n",prog,nx,bufin[0],bufin[1]);
		}

	}
	return(0);
}
