/* Copyright 2005 Renzo Davoli - VDE-2
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 */

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <net/if.h>
#include <stdarg.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <port.h>
#include <switch.h>
#include <sockutils.h>
#include <consmgmt.h>
#include <qtimer.h>

#define MAXCMD 128

static struct swmodule swmi;

static int logok=0;
static char *rcfile;
static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];
static int daemonize = 0;
static unsigned int console_type=-1;
static unsigned int mgmt_ctl=-1;
static unsigned int mgmt_data=-1;
static int mgmt_mode = 0600;
static char *mgmt_socket = NULL;
static char header[]="VDE switch V.%s\n(C) R.Davoli 2005 - GPLv2\n";
static char prompt[]="\nvde: ";

static struct comlist *clh=NULL;

void addcl(int ncl,struct comlist *cl)
{
	register int i;
	static struct comlist **clt=&clh;
	for (i=0;i<ncl;i++,cl++) {
		cl->next=NULL;
		(*clt)=cl;
		clt=(&cl->next);
	}
}

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

void printoutc(int fd, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);
	if (fd < 0)
		printlog(LOG_INFO,format,arg);
	else {
		char outbuf[MAXCMD+1];
		vsnprintf(outbuf,MAXCMD,format,arg);
		strcat(outbuf,"\n");
		write(fd,outbuf,strlen(outbuf));
	}
}

void setmgmtperm(char *path)
{
	chmod(path,mgmt_mode);
}

static int help(int fd,char *arg)
{
	struct comlist *p;
	int n=strlen(arg);
	printoutc(fd,"%-18s %-15s %s","COMMAND PATH","SYNTAX","HELP");
	printoutc(fd,"%-18s %-15s %s","------------","--------------","------------");
	for (p=clh;p!=NULL;p=p->next)
		if (strncmp(p->path,arg,n) == 0) 
			printoutc(fd,"%-18s %-15s %s",p->path,p->syntax,p->help);
	return 0;
}

static int handle_cmd(int type,int fd,char *inbuf)
{
	struct comlist *p;
	int rv=ENOSYS;
	while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
	if (*inbuf != '\0' && *inbuf != '#') {
		for (p=clh;p!=NULL && (p->doit==NULL || strncmp(p->path,inbuf,strlen(p->path))!=0); p=p->next)
			;
		if (p!=NULL)
		{
			inbuf += strlen(p->path);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (p->type & WITHFD) {
				printoutc(fd,"0000 DATA END WITH '.'");
				switch(p->type & ~WITHFD){
					case NOARG: rv=p->doit(fd); break;
					case INTARG: rv=p->doit(fd,atoi(inbuf)); break;
					case STRARG: rv=p->doit(fd,inbuf); break;
				}
				printoutc(fd,".");
			} else {
				switch(p->type){
					case NOARG: rv=p->doit(); break;
					case INTARG: rv=p->doit(atoi(inbuf)); break;
					case STRARG: rv=p->doit(inbuf); break;
				}
			}
		}
		if (rv >= 0 && (rv > 0 || fd >= 0))
			printoutc(fd,"1%03d %s",rv,strerror(rv));
	}
	return rv;
}

static int runscript(int fd,char *path) 
{
	FILE *f=fopen(path,"r");
	char buf[MAXCMD];
	if (f==NULL)
		return ENOENT;
	else {
		while (fgets(buf,MAXCMD,f) != NULL) {
			if (strlen(buf) > 1 && buf[strlen(buf)-1]=='\n') buf[strlen(buf)-1]= '\0';
			if (fd >= 0) printoutc(fd,"vde[%s]: %s",path,buf);
			handle_cmd(mgmt_data, fd, buf);
		}
		return 0;
	}
}

void loadrcfile(void)
{
	if (rcfile != NULL)
		runscript(-1,rcfile);
	else {
		char path[PATH_MAX];
		snprintf(path,PATH_MAX,"%s/.vderc",getenv("HOME"));
		if (access(path,R_OK) == 0)
			runscript(-1,path);
		else {
			if (access(STDRCFILE,R_OK) == 0)
				runscript(-1,STDRCFILE);
		}
	}
}

static void handle_input(unsigned char type,int fd,int revents,int *unused)
{
	char buf[MAXCMD];
	if (type != mgmt_ctl) {
		int n=0;

		if (revents & POLLIN) {
			n = read(fd, buf, sizeof(buf));
			if(n < 0){
				printlog(LOG_WARNING,"Reading from mgmt %s",strerror(errno));
			}
		}
		if (n==0) { /*EOF*/
			if (type == console_type) {
				printlog(LOG_WARNING,"EOF on stdin, cleaning up and exiting");
				exit(0);
			} else {
				remove_fd(fd);
			}
		} else {
			int cmdout;
			buf[n]=0;
			if (n>0 && buf[n-1] == '\n') buf[n-1] = 0;
			cmdout=handle_cmd(type,(type==console_type)?STDOUT_FILENO:fd,buf);
			if (cmdout >= 0)
				write(fd,prompt,strlen(prompt));
			else {
				if(type==mgmt_data) {
					printoutc(fd,"9999 END OF SESSION");
					remove_fd(fd);
				}
				if (cmdout == -2)
					exit(0);
			}
		}
	} else  {/* mgmt ctl */
		struct sockaddr addr;
		int new;
		socklen_t len;

		len = sizeof(addr);
		new = accept(fd, &addr, &len);
		if(new < 0){
			printlog(LOG_WARNING,"mgmt accept %s",strerror(errno));
			return;
		}
		if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
			printlog(LOG_WARNING,"mgmt fcntl - setting O_NONBLOCK %s",strerror(errno));
			close(new);
			return;
		}

		add_fd(new,mgmt_data,-1);
		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
	}
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

static void cleanup(unsigned char type,int fd,int arg)
{
	if (fd < 0) {
		if((pidfile != NULL) && unlink(pidfile_path) < 0) {
			printlog(LOG_WARNING,"Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
		}
	} else {
		close(fd);
		if (type == mgmt_ctl && mgmt_socket != NULL) {
			unlink(mgmt_socket);
		}
	}
}

#define MGMTMODEARG 0x100

static struct option long_options[] = {
	{"daemon", 0, 0, 'd'},
	{"pidfile", 1, 0, 'p'},
	{"rcfile", 1, 0, 'f'},
	{"mgmt", 1, 0, 'M'},
	{"mgmtmode", 1, 0, MGMTMODEARG}
};

#define Nlong_options (sizeof(long_options)/sizeof(struct option));

static void usage(void)
{
	printf(
			"(opts from consmgmt module)\n"
			"  -d, --daemon               Daemonize vde_switch once run\n"
			"  -p, --pidfile PIDFILE      Write pid of daemon to PIDFILE\n"
			"  -f, --rcfile               Configuration file (overrides %s and ~/.vderc)\n"
			"  -M, --mgmt SOCK            path of the management UNIX socket\n"
			"      --mgmtmode MODE        management UNIX socket access mode (octal)\n"
			,STDRCFILE);
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	switch (c) {
		case 'd':
			daemonize=1;
			break;
		case 'p':
			pidfile=strdup(optarg);
			break;
		case 'f':
			rcfile=strdup(optarg);
			break;
		case 'M':
			mgmt_socket=strdup(optarg);
			break;
		case MGMTMODEARG:
			sscanf(optarg,"%o",&mgmt_mode);
			break;
		default:
			outc=c;
	}
	return outc;
}

static void init(void)
{
	if (daemonize) {
		openlog(basename(prog), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"VDE_SWITCH started");
	}
	/* add stdin (if tty), connect and data fds to the set of fds we wait for
	 *    * input */
	if(isatty(0) && !daemonize)
	{
		console_type=add_type(&swmi,0);
		add_fd(0,console_type,-1);
	}

	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 *    * forget it */
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
	 *    * server: save PID file if needed */
	if(pidfile) save_pidfile();

	if(mgmt_socket != NULL) {
		int mgmtconnfd;
		struct sockaddr_un sun;
		int one = 1;

		if((mgmtconnfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
			printlog(LOG_ERR,"mgmt socket: %s",strerror(errno));
			return;
		}
		if(setsockopt(mgmtconnfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
					sizeof(one)) < 0){
			printlog(LOG_ERR,"mgmt setsockopt: %s",strerror(errno));
			return;
		}
		if(fcntl(mgmtconnfd, F_SETFL, O_NONBLOCK) < 0){
			printlog(LOG_ERR,"Setting O_NONBLOCK on mgmt fd: %s",strerror(errno));
			return;
		}
		sun.sun_family = PF_UNIX;
		snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",mgmt_socket);
		if(bind(mgmtconnfd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
			if((errno == EADDRINUSE) && still_used(&sun)) return;
			else if(bind(mgmtconnfd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
				printlog(LOG_ERR,"mgmt bind %s",strerror(errno));
				return;
			}
		}
		chmod(sun.sun_path,mgmt_mode);
		if(listen(mgmtconnfd, 15) < 0){
			printlog(LOG_ERR,"mgmt listen: %s",strerror(errno));
			return;
		}
		mgmt_ctl=add_type(&swmi,0);
		mgmt_data=add_type(&swmi,0);
		add_fd(mgmtconnfd,mgmt_ctl,-1);
	}
}

static int vde_logout() 
{ 
	return -1; 
}

static int vde_shutdown() 
{ 
	printlog(LOG_WARNING,"Shutdown from mgmt command");
	return -2; 
}

static int showinfo(int fd) 
{
	printoutc(fd,header,PACKAGE_VERSION);
	printoutc(fd,"pid %d MAC %02x:%02x:%02x:%02x:%02x:%02x uptime %d",getpid(),
			switchmac[0], switchmac[1], switchmac[2], switchmac[3], switchmac[4], switchmac[5],
			qtime());
	if (mgmt_socket)
		printoutc(fd,"mgmt %s perm 0%03o",mgmt_socket,mgmt_mode);
	return 0;
}

static struct comlist cl[]={
	{"help","[arg]","Help (limited to arg when specified)",help,STRARG | WITHFD},
	{"logout","","logout from this mgmt terminal",vde_logout,NOARG},
	{"shutdown","","shutdown of the switch",vde_shutdown,NOARG},
	{"showinfo","","show switch version and info",showinfo,NOARG|WITHFD},
	{"load","path","load a configuration script",runscript,STRARG|WITHFD},
};

void start_consmgmt(void)
{
	swmi.swmname="console-mgmt";
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_input=handle_input;
	swmi.cleanup=cleanup;
	ADDCL(cl);
	add_swm(&swmi);
}
