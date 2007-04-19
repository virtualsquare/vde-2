/* Copyright 2005,2006,2007 Renzo Davoli - VDE-2
 * 2007 co-authors Ludovico Gardenghi, Filippo Giunchedi, Luca Bigliardi
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 */

#define _GNU_SOURCE
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
#include <sys/uio.h>
#include <net/if.h>
#include <stdarg.h>
#include <getopt.h>

#include <vde.h>
#include <port.h>
#include <switch.h>
#include <sockutils.h>
#include <consmgmt.h>
#include <qtimer.h>
#include <packetq.h>

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
#ifdef DEBUGOPT
static int ndebugclients=8;
static struct dbgcl *dbgclh=NULL;
#endif

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

#ifdef DEBUGOPT
void adddbgcl(int ncl,struct dbgcl *cl)
{
	int i, j;
	static struct dbgcl **clt=&dbgclh;
	for (i=0;i<ncl;i++,cl++) {
		if ((cl->fds=malloc(ndebugclients * sizeof(int))) != NULL) {
			cl->next=NULL;
			for(j=0; j<ndebugclients; j++) cl->fds[j]= -1;
			(*clt)=cl;
			clt=(&cl->next);
		}
	}
}
#endif

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

#if 0
void printoutc(int fd, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);
#if 0
	if (fd < 0)
		printlog(LOG_INFO,format,arg);
	else {
#endif
		char outbuf[MAXCMD+1];
		vsnprintf(outbuf,MAXCMD,format,arg);
		strcat(outbuf,"\n");
		write(fd,outbuf,strlen(outbuf));
#if 0
	}
#endif
}
#endif

void printoutc(FILE *f, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);
	if (f) {
		vfprintf(f,format,arg);
		fprintf(f,"\n");
	} else
		printlog(LOG_INFO,format,arg);
	va_end(arg);
}

#ifdef DEBUGOPT
static char _dbgnl='\n';
void debugout(struct dbgcl* cl, const char *format, ...)
{
	va_list arg;
	char *msg;
	int i;
	char *header;
	struct iovec iov[]={{NULL,0},{NULL,0},{&_dbgnl,1}};

	va_start (arg, format);
	iov[0].iov_len=asprintf(&header,"%d %s ",3000+0,cl->path);
	iov[0].iov_base=header;
	iov[1].iov_len=vasprintf(&msg,format,arg);
	iov[1].iov_base=msg;
	va_end (arg);

	for (i=0; i<ndebugclients && cl->fds[i] >=0; i++)
		writev(cl->fds[i],iov,3);
	free(header);
	free(msg);
}
#endif

void setmgmtperm(char *path)
{
	chmod(path,mgmt_mode);
}

static int help(FILE *fd,char *arg)
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
		char *outbuf;
		size_t outbufsize;
		FILE *f;
		if (fd >= 0)
			f=open_memstream(&outbuf,&outbufsize);
		else
			f=NULL;
		for (p=clh;p!=NULL && (p->doit==NULL || strncmp(p->path,inbuf,strlen(p->path))!=0); p=p->next)
			;
		if (p!=NULL)
		{
			inbuf += strlen(p->path);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (p->type & WITHFD) {
				if (p->type & WITHFILE) {
					printoutc(f,"0000 DATA END WITH '.'");
					switch(p->type & ~(WITHFILE | WITHFD)){
						case NOARG: rv=p->doit(f,fd); break;
						case INTARG: rv=p->doit(f,fd,atoi(inbuf)); break;
						case STRARG: rv=p->doit(f,fd,inbuf); break;
					}
					printoutc(f,".");
				} else {
					switch(p->type & ~WITHFD){
						case NOARG: rv=p->doit(fd); break;
						case INTARG: rv=p->doit(fd,atoi(inbuf)); break;
						case STRARG: rv=p->doit(fd,inbuf); break;
					}
				}
			} else if (p->type & WITHFILE) {
				printoutc(f,"0000 DATA END WITH '.'");
				switch(p->type & ~WITHFILE){
					case NOARG: rv=p->doit(f); break;
					case INTARG: rv=p->doit(f,atoi(inbuf)); break;
					case STRARG: rv=p->doit(f,inbuf); break;
				}
				printoutc(f,".");
			} else {
				switch(p->type){
					case NOARG: rv=p->doit(); break;
					case INTARG: rv=p->doit(atoi(inbuf)); break;
					case STRARG: rv=p->doit(inbuf); break;
				}
			}
		}
		if (rv >= 0 && (rv > 0 || fd >= 0))
			printoutc(f,"1%03d %s",rv,strerror(rv));
		if (f) {
			fclose(f);
			write(fd,outbuf,outbufsize);
			free(outbuf);
		}
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
			if (fd >= 0) {
				char *scriptprompt=NULL;
				asprintf(&scriptprompt,"vde[%s]: %s",path,buf);
				write(fd,scriptprompt,strlen(scriptprompt));
				free(scriptprompt);
			}
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

#ifdef DEBUGOPT
static int debugdel(int fd,char *arg);
#endif
static char *EOS="9999 END OF SESSION";
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
#ifdef DEBUGOPT
				debugdel(fd,"");
#endif
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
					write(fd,EOS,strlen(EOS));
#ifdef DEBUGOPT
					debugdel(fd,"");
#endif
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
	{"mgmtmode", 1, 0, MGMTMODEARG},
#ifdef DEBUGOPT
	{"debugclients",1,0,'D'},
#endif
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
#ifdef DEBUGOPT
			"  -D, --debugclients #        number of debug clients allowed\n"
#endif
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
#ifdef DEBUGOPT
		case 'D':
			ndebugclients = atoi(optarg);
			break;
#endif
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
	if (daemonize && daemon(0, 0)) {
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

static int showinfo(FILE *fd) 
{
	printoutc(fd,header,PACKAGE_VERSION);
	printoutc(fd,"pid %d MAC %02x:%02x:%02x:%02x:%02x:%02x uptime %d",getpid(),
			switchmac[0], switchmac[1], switchmac[2], switchmac[3], switchmac[4], switchmac[5],
			qtime());
	if (mgmt_socket)
		printoutc(fd,"mgmt %s perm 0%03o",mgmt_socket,mgmt_mode);
	printoutc(fd,"unsent_pktq_len %d",packetq_count());
	return 0;
}

#ifdef DEBUGOPT
static int debuglist(FILE *f,int fd,char *arg)
{
#define DEBUGFORMAT "%-22s %-6s %s"
	struct dbgcl *p;
	int i;
	int rv=ENOENT;
	printoutc(f,DEBUGFORMAT,"CATEGORY", "STATUS", "HELP");
	printoutc(f,DEBUGFORMAT,"------------","------", "----");
	for (p=dbgclh; p!=NULL; p=p->next){
		if (strncmp(p->path, arg, strlen(arg)) == 0) {
			for (i=0; i<ndebugclients && p->fds[i] != fd; i++)
				;
			rv=0;
			printoutc(f, DEBUGFORMAT, p->path,  i<ndebugclients ? "ON" : "OFF", p->help);
		}
	}
	return rv;
}

/* EINVAL -> no matches
 * EEXIST -> all the matches already include fd
 * EMFILE -> fd buffer averflow in at least one match 
 * 0 otherwise */
static int debugadd(int fd,char *arg) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next) {
		if (strncmp(p->path, arg, strlen(arg)) == 0) {
			int i;
			if (rv==EINVAL) rv=EEXIST;
			for(i=0;i<ndebugclients && (p->fds[i] != -1) && (p->fds[i] != fd); i++)
				;
			if (i<ndebugclients) {
				if ( p->fds[i] == -1 ) {
					p->fds[i] = fd;
					if (rv!=EMFILE) rv=0;
				} 
			} else
				rv=EMFILE;
		} 
	}
	return rv;
}

/* EINVAL -> no matches
 * ENOENT -> all the matches do not include fd
 * 0 otherwise */
static int debugdel(int fd,char *arg) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next){
		if (strncmp(p->path, arg, strlen(arg)) == 0) {
			int i;
			if (rv==EINVAL) rv=ENOENT;
			for(i=0;i<ndebugclients && (p->fds[i] != -1) && (p->fds[i] != fd); i++)
				;
			if (i<ndebugclients && p->fds[i] == fd) {
				int j;
				for (j=i;j<ndebugclients && p->fds[i] >= 0; j++)
					;
				j--; /* the last one */
				p->fds[i]=p->fds[j]; /* swap it with the deleted element*/
				p->fds[j] = -1; /* null the last one, if deleting the last one
													 null itself */
				rv=0;
			} 
		}
	}
	return rv;
}

#endif

static struct comlist cl[]={
	{"help","[arg]","Help (limited to arg when specified)",help,STRARG | WITHFILE},
	{"logout","","logout from this mgmt terminal",vde_logout,NOARG},
	{"shutdown","","shutdown of the switch",vde_shutdown,NOARG},
	{"showinfo","","show switch version and info",showinfo,NOARG|WITHFILE},
	{"load","path","load a configuration script",runscript,STRARG|WITHFD},
#ifdef DEBUGOPT
	{"debug","============","DEBUG MENU",NULL,NOARG},
	{"debug/list","","list debug categories",debuglist,STRARG|WITHFILE|WITHFD},
	{"debug/add","dbgpath","enable debug info for a given category",debugadd,WITHFD|STRARG},
	{"debug/del","dbgpath","disable debug info for a given category",debugdel,WITHFD|STRARG},
#endif
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
