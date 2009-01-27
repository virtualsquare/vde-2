/*
 * Copyright (C) 2008 - Luca Bigliardi
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <syslog.h>
#include <libgen.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <pcap.h>
#include <limits.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>
#include <libvdeplug.h>

#ifdef VDE_FREEBSD
#include <sys/socket.h>
#endif

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
#	if defined HAVE_SYSLIMITS_H
#		include <syslimits.h>
#	elif defined HAVE_SYS_SYSLIMITS_H
#		include <sys/syslimits.h>
#	else
#		error "No syslimits.h found"
#	endif
#endif

#define BUFSIZE 2048

static VDECONN *conn = NULL;
static pcap_t *pcap = NULL;

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

	if (pcap)
		pcap_close(pcap);
	if (conn)
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
			perror("Setting handler");
}

struct pollfd pollv[]={{0,POLLIN|POLLHUP},{0,POLLIN|POLLHUP},{0,POLLIN|POLLHUP}};

static void usage(void) {
	fprintf(stderr, "Usage: %s [OPTION]... interface\n\n", prog);
	fprintf(stderr, "  -p, --port=portnum          Port number in the VDE switch\n"
			        "  -g, --group=group           Group for the socket\n"
					"  -m, --mode=mode             Octal mode for the socket\n"
					"  -s, --sock=socket           VDE switch control socket or dir\n"
					"  -d, --daemon                Launch in background\n"
					"  -P, --pidfile=pidfile       Create pidfile with our PID\n"
					"  -h, --help                  This help\n");
	exit(-1);
}

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

void pcap_callback(u_char *u, const struct pcap_pkthdr *h, const u_char *data)
{
	vde_send(conn, data, h->len, 0);
}

void setup_fd(int fd)
{
/* FreeBSD settings */
#if defined(VDE_FREEBSD)
	/*
	 * Tell the kernel that the header is fully-formed when it gets it.
	 * This is required in order to fake the src address.
	 */
	{ unsigned int i = 1; ioctl(fd, BIOCSHDRCMPLT, &i); }
	/*                    
	 * Tell the kernel that the packet has to be processed immediately.
	 */
	{ unsigned int i = 1; ioctl(fd, BIOCIMMEDIATE, &i); }
	/*
	 * Allow guest-host communication.
	 */
	{ unsigned int i = 1; ioctl(fd, BIOCFEEDBACK, &i); }
#endif
/* 
 * BIG TODO(shammash):
 * let host and guest communicate under linux
 */
/*
 * Most important parts of libpcap with PF_PACKET on Linux:
	rawfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	iface_get_id(int fd, const char *device, char *ebuf)
	{
		struct ifreq    ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

		if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
					"SIOCGIFINDEX: %s", pcap_strerror(errno));
			return -1;
		}       

		return ifr.ifr_ifindex;
	}

	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = handle->md.ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "setsockopt: %s", pcap_strerror(errno));
        }
*
*/
#if defined(VDE_LINUX)
	{
		unsigned int i = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i)) == -1) {
			printlog(LOG_ERR, "SO_BROADCAST: %s\n", strerror(errno));
			exit(1);
		}
	}
#endif
}

int main(int argc, char **argv)
{
	static char *sockname=NULL;
	static char *ifname=NULL;
	int daemonize=0;
	int result;
	char errbuf[PCAP_ERRBUF_SIZE];
	int pcapfd;
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
		c = GETOPT_LONG (argc, argv, "hdP:p:s:m:g:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'p':
				open_args.port=atoi(optarg);
				if (open_args.port <= 0)
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
		syslog(LOG_INFO,"VDE_PCAPPLUG started");
	}
	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();

	if (optind < argc)
		ifname=argv[optind];
	else
		usage(); // implies exit
	
	atexit(cleanup);
	setsighandlers();

	pcap = pcap_open_live(ifname, BUFSIZE, 1, 0, errbuf);
	if (pcap == NULL) {
		printlog(LOG_ERR, "Open %s: %s\n", ifname, errbuf);
		exit(1);
	}
	if (pcap_datalink(pcap) != DLT_EN10MB ) {
		printlog(LOG_ERR, "Given interface is not ethernet\n");
		exit(1);
	}
	pcapfd=pcap_get_selectable_fd(pcap);
	if (pcapfd == -1) {
		printlog(LOG_ERR, "pcap has no fd for poll()\n");
		exit(1);
	}
	setup_fd(pcapfd);

	conn=vde_open(sockname,"vde_pcapplug:",&open_args);
	if (conn == NULL)
		exit(1);

	pollv[0].fd=pcapfd;
	pollv[1].fd=vde_datafd(conn);
	pollv[2].fd=vde_ctlfd(conn);

	for(;;) {
		result=poll(pollv,3,-1);
		if ((pollv[0].revents | pollv[1].revents | pollv[2].revents) & POLLHUP ||
				pollv[2].revents & POLLIN) 
			break;
		if (pollv[0].revents & POLLIN) {
			nx = pcap_dispatch(pcap, 1, &pcap_callback, NULL);
			if (nx<=0)
				break;
		}
		if (pollv[1].revents & POLLIN) {
			nx=vde_recv(conn,bufin,sizeof(bufin),0);
			if (nx<=0)
				break;
			nx = pcap_inject(pcap, bufin, nx);
			if (nx<=0)
				break;
		}
	}
	return(0);
}
