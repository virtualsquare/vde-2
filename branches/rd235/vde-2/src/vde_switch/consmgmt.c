/* Copyright 2005,2006,2007 Renzo Davoli - VDE-2
 * 2007 co-authors Ludovico Gardenghi, Filippo Giunchedi, Luca Bigliardi
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>
#include <grp.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <net/if.h>
#include <stdarg.h>
#include <getopt.h>
#include <dlfcn.h>
#include <limits.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "port.h"
#include "switch.h"
#include "sockutils.h"
#include "consmgmt.h"
#include "qtimer.h"
#include "packetq.h"

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
static gid_t mgmt_group = -1;

static char *mgmt_socket = NULL;
static char header[]="VDE switch V.%s\n(C) Virtual Square Team (coord. R. Davoli) 2005,2006,2007 - GPLv2\n";
static char prompt[]="\nvde$ ";

static struct comlist *clh=NULL;
static struct comlist **clt=&clh;
#ifdef DEBUGOPT
#define DBGCLSTEP 8
static struct dbgcl *dbgclh=NULL;
static struct dbgcl **dbgclt=&dbgclh;
#define MGMTPORTNEW (dl) 
#define MGMTPORTDEL (dl+1) 
#define MGMTSIGHUP (dl+2) 
static struct dbgcl dl[]= {
	{"mgmt/+",NULL,D_MGMT|D_PLUS},
	{"mgmt/-",NULL,D_MGMT|D_MINUS},
	{"sig/hup",NULL,D_SIG|D_HUP}
};
#endif
#ifdef VDEPLUGIN
static struct plugin *pluginh=NULL;
static struct plugin **plugint=&pluginh;
#endif

void addcl(int ncl,struct comlist *cl)
{
	register int i;
	for (i=0;i<ncl;i++,cl++) {
		cl->next=NULL;
		(*clt)=cl;
		clt=(&cl->next);
	}
}

void delcl(int ncl,struct comlist *cl)
{
	register int i;
	for (i=0;i<ncl;i++,cl++) {
		register struct comlist **p=&clh;
		while (*p != NULL) {
			if (*p == cl) 
				*p=cl->next;
			else {
				p=&(*p)->next;
				clt=p;
			}
		}
	}
}

#ifdef DEBUGOPT
void adddbgcl(int ncl,struct dbgcl *cl)
{
	int i;
	for (i=0;i<ncl;i++,cl++) {
		cl->next=NULL;
		(*dbgclt)=cl;
		dbgclt=(&cl->next);
	}
}

void deldbgcl(int ncl,struct dbgcl *cl)
{
	register int i;
	for (i=0;i<ncl;i++,cl++) {
		register struct dbgcl **p=&dbgclh;
		while (*p != NULL) {
			if (*p == cl) {
				if (cl->fds) free(cl->fds);
				if (cl->fun) free(cl->fun);
				*p=cl->next;
			} else {
				p=&(*p)->next;
				dbgclt=p;
			}
		}
	}
}
#endif

#ifdef VDEPLUGIN
void addplugin(struct plugin *cl)
{
	cl->next=NULL;
	(*plugint)=cl;
	plugint=(&cl->next);
}

void delplugin(struct plugin *cl)
{
	register struct plugin **p=plugint=&pluginh;
	while (*p != NULL) {
		if (*p == cl)
			*p=cl->next;
		else {
			p=&(*p)->next;
			plugint=p;
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
	iov[0].iov_len=asprintf(&header,"3%03o %s ",cl->tag & 0777,cl->path);
	iov[0].iov_base=header;
	iov[1].iov_len=vasprintf(&msg,format,arg);
	iov[1].iov_base=msg;
	va_end (arg);

	for (i=0; i<cl->nfds; i++)
		writev(cl->fds[i],iov,3);
	free(header);
	free(msg);
}

void eventout(struct dbgcl* cl, ...)
{
	int i;
	va_list arg;
	for (i=0; i<cl->nfun; i++) {
		va_start (arg, cl);
		(cl->fun[i])(cl,cl->funarg[i],arg);
		va_end(arg);
	}
}

int packetfilter(struct dbgcl* cl, ...)
{
	int i;
	va_list arg;
	int len;
	va_start (arg, cl);
	(void) va_arg(arg,int); /*port*/
	(void) va_arg(arg,char *); /*buf*/
	len=va_arg(arg,int);
	va_end(arg);
	for (i=0; i<cl->nfun && len>0; i++) {
		va_start (arg, cl);
		int rv=(cl->fun[i])(cl,cl->funarg[i],arg);
		va_end (arg);
		if (rv!=0) 
			len=rv;
	}
	if (len < 0)
		return 0;
	else
		return len;
}
#endif

void setmgmtperm(char *path)
{
	chmod(path,mgmt_mode);
	chown(path, -1, mgmt_group);
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
		FILE *f=open_memstream(&outbuf,&outbufsize);
		for (p=clh;p!=NULL && (p->doit==NULL || strncmp(p->path,inbuf,strlen(p->path))!=0); p=p->next)
			;
		if (p!=NULL)
		{
			inbuf += strlen(p->path);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (p->type & WITHFD) {
				if (fd >= 0) {
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
				} else
					rv = EBADF;
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
		if (rv == 0) {
			printoutc(f,"1000 Success");
		} else if (rv > 0) {
			printoutc(f,"1%03d %s",rv,strerror(rv));
		}
		fclose(f);
		if (fd >= 0)
			write(fd,outbuf,outbufsize);
		free(outbuf);
	}
	return rv;
}

static int runscript(int fd,char *path) 
{
	FILE *f=fopen(path,"r");
	char buf[MAXCMD];
	if (f==NULL)
		return errno;
	else {
		while (fgets(buf,MAXCMD,f) != NULL) {
			if (strlen(buf) > 1 && buf[strlen(buf)-1]=='\n') buf[strlen(buf)-1]= '\0';
			if (fd >= 0) {
				char *scriptprompt=NULL;
				asprintf(&scriptprompt,"vde[%s]: %s\n",path,buf);
				write(fd,scriptprompt,strlen(scriptprompt));
				free(scriptprompt);
			}
			handle_cmd(mgmt_data, fd, buf);
		}
		fclose(f);
		return 0;
	}
}

void loadrcfile(void)
{
	if (rcfile != NULL)
		runscript(-1,rcfile);
	else {
		char path[PATH_MAX];
		snprintf(path,PATH_MAX,"%s/.vde2/vde_switch.rc",getenv("HOME"));
		if (access(path,R_OK) == 0)
			runscript(-1,path);
		else {
			if (access(STDRCFILE,R_OK) == 0)
				runscript(-1,STDRCFILE);
		}
	}
}

void mgmtnewfd(int new)
{
	char buf[MAXCMD];
	if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_WARNING,"mgmt fcntl - setting O_NONBLOCK %s",strerror(errno));
		close(new);
		return;
	}

	add_fd(new,mgmt_data,NULL);
	EVENTOUT(MGMTPORTNEW,new);
	snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
	write(new,buf,strlen(buf));
	write(new,prompt,strlen(prompt));
}

#ifdef DEBUGOPT
static int debugdel(int fd,char *arg);
#endif
static char *EOS="9999 END OF SESSION";
static void handle_io(unsigned char type,int fd,int revents,void *private_data)
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
		if (n==0) { /*EOF || POLLHUP*/
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
					EVENTOUT(MGMTPORTDEL,fd);
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

		add_fd(new,mgmt_data,NULL);
		EVENTOUT(MGMTPORTNEW,new);
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

static void cleanup(unsigned char type,int fd,void *private_data)
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
#define MGMTGROUPARG 0x101

static struct option long_options[] = {
	{"daemon", 0, 0, 'd'},
	{"pidfile", 1, 0, 'p'},
	{"rcfile", 1, 0, 'f'},
	{"mgmt", 1, 0, 'M'},
	{"mgmtmode", 1, 0, MGMTMODEARG},
	{"mgmtgroup", 1, 0, MGMTGROUPARG},
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
			"      --mgmtgroup GROUP      management UNIX socket group name\n"
#ifdef DEBUGOPT
			"  -D, --debugclients #       number of debug clients allowed\n"
#endif
			,STDRCFILE);
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	struct group *grp;
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
		case MGMTGROUPARG:
			if (!(grp = getgrnam(optarg)))
			{
				fprintf(stderr, "No such group '%s'\n", optarg);
				exit(1);
			}
			mgmt_group = grp->gr_gid;
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
		add_fd(0,console_type,NULL);
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
		setmgmtperm(sun.sun_path);
		if(listen(mgmtconnfd, 15) < 0){
			printlog(LOG_ERR,"mgmt listen: %s",strerror(errno));
			return;
		}
		mgmt_ctl=add_type(&swmi,0);
		mgmt_data=add_type(&swmi,0);
		add_fd(mgmtconnfd,mgmt_ctl,NULL);
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
	return 0;
}

#ifdef DEBUGOPT
static int debuglist(FILE *f,int fd,char *path)
{
#define DEBUGFORMAT1 "%-22s %-3s %-6s %s"
#define DEBUGFORMAT2 "%-22s %03o %-6s %s"
	struct dbgcl *p;
	int i;
	int rv=ENOENT;
	printoutc(f,DEBUGFORMAT1,"CATEGORY", "TAG", "STATUS", "HELP");
	printoutc(f,DEBUGFORMAT1,"------------","---","------", "----");
	for (p=dbgclh; p!=NULL; p=p->next){
		if (p->help && strncmp(p->path, path, strlen(path)) == 0) {
			for (i=0; i<p->nfds && p->fds[i] != fd; i++)
				;
			rv=0;
			printoutc(f, DEBUGFORMAT2, p->path,  p->tag &0777, i<p->nfds ? "ON" : "OFF", p->help);
		}
	}
	return rv;
}

/* EINVAL -> no matches
 * EEXIST -> all the matches already include fd
 * ENOMEM -> fd buffer realloc failed
 * 0 otherwise */
static int debugadd(int fd,char *path) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next) {
		if (p->help && strncmp(p->path, path, strlen(path)) == 0) {
			int i;
			if (rv==EINVAL) rv=EEXIST;
			for(i=0;i<p->nfds && (p->fds[i] != fd); i++)
				;
			if (i>=p->nfds) {
				if (i>=p->maxfds) {
					int newsize=p->maxfds+DBGCLSTEP;
					p->fds=realloc(p->fds,newsize*sizeof(int));
					if (p->fds) {
						p->maxfds=newsize;
						p->fds[i]=fd;
						p->nfds++;
						if (rv != ENOMEM) rv=0;
					} else
						rv=ENOMEM;
				} else {
					p->fds[i]=fd;
					p->nfds++;
					if (rv != ENOMEM) rv=0;
				} 
			}
		} 
	}
	return rv;
}

/* EINVAL -> no matches
 * ENOENT -> all the matches do not include fd
 * 0 otherwise */
static int debugdel(int fd,char *path) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next){
		if (strncmp(p->path, path, strlen(path)) == 0) {
			int i;
			if (rv==EINVAL) rv=ENOENT;
			for(i=0;i<p->nfds && (p->fds[i] != fd); i++)
				;
			if (i<p->nfds) {
				p->nfds--; /* the last one */
				p->fds[i]=p->fds[p->nfds]; /* swap it with the deleted element*/
				rv=0;
			} 
		}
	}
	return rv;
}

int eventadd(int (*fun)(),char *path,void *arg) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next) {
		if (strncmp(p->path, path, strlen(path)) == 0) {
			int i;
			if (rv==EINVAL) rv=EEXIST;
			for(i=0;i<p->nfun && (p->fun[i] != fun); i++)
				;
			if (i>=p->nfun) {
				if (i>=p->maxfun) {
					int newsize=p->maxfun+DBGCLSTEP;
					p->fun=realloc(p->fun,newsize*sizeof(int));
					p->funarg=realloc(p->funarg,newsize*sizeof(void *));
					if (p->fun && p->funarg) {
						p->maxfun=newsize;
						p->fun[i]=fun;
						p->funarg[i]=arg;
						p->nfun++;
						if (rv != ENOMEM) rv=0;
					} else
						rv=ENOMEM;
				} else {
					p->fun[i]=fun;
					p->nfun++;
					if (rv != ENOMEM) rv=0;
				}
			}
		}
	}
	return rv;
}

/* EINVAL -> no matches
 * ENOENT -> all the matches do not include fun
 * 0 otherwise */
int eventdel(int (*fun)(),char *path,void *arg) {
	struct dbgcl *p;
	int rv=EINVAL;
	for (p=dbgclh; p!=NULL; p=p->next){
		if (strncmp(p->path, path, strlen(path)) == 0) {
			int i;
			if (rv==EINVAL) rv=ENOENT;
			for(i=0;i<p->nfun && (p->fun[i] != fun) && (p->funarg[i] != arg); i++)
				;
			if (i<p->nfun) {
				p->nfun--; /* the last one */
				p->fun[i]=p->fun[p->nfun]; /* swap it with the deleted element*/
				rv=0;
			}
		}
	}
	return rv;
}

#endif

#ifdef VDEPLUGIN
static int pluginlist(FILE *f,char *arg)
{
#define PLUGINFMT "%-22s %s"
	struct plugin *p;
	int rv=ENOENT;
	printoutc(f,PLUGINFMT,"NAME", "HELP");
	printoutc(f,PLUGINFMT,"------------","----");
	for (p=pluginh; p!=NULL; p=p->next){
		if (strncmp(p->name, arg, strlen(arg)) == 0) {
			printoutc(f,PLUGINFMT,p->name,p->help);
			rv=0;
		}
	}
	return rv;
}

/* This will be prefixed with getent("$HOME") */
#define USER_PLUGINS_DIR "/.vde2/plugins"

#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
/*
 * Try to dlopen a plugin trying different names and locations:
 * (code from view-os by Gardenghi)
 * 
 * 1) dlopen(modname)
 * 2) dlopen(modname.so)
 * 3) dlopen(user_umview_plugin_directory/modname)
 * 4) dlopen(user_umview_plugin_directory/modname.so)
 * 5) dlopen(global_umview_plugin_directory/modname)
 * 6) dlopen(global_umview_plugin_directory/modname.so)
 *
 */

#define TRY_DLOPEN(fmt...) \
{ \
	snprintf(testpath, tplen, fmt); \
	if ((handle = dlopen(testpath, flag))) \
	{ \
		free(testpath); \
		return handle; \
	} \
}

void *plugin_dlopen(const char *modname, int flag)
{
	void *handle;
	char *testpath;
	int tplen;
	char *homedir = getenv("HOME");

	if (!modname)
		return NULL;

	if ((handle = dlopen(modname, flag)))
		return handle;

	/* If there is no home directory, use CWD */
	if (!homedir)
		homedir = ".";

	tplen = strlen(modname) +
		strlen(MODULES_EXT) + 2 + // + 1 is for a '/' and + 1 for \0
		MAX(strlen(PLUGINS_DIR),
				strlen(homedir) + strlen(USER_PLUGINS_DIR));

	  testpath = malloc(tplen);

		TRY_DLOPEN("%s%s", modname, MODULES_EXT);
		TRY_DLOPEN("%s%s/%s", homedir, USER_PLUGINS_DIR, modname);
		TRY_DLOPEN("%s%s/%s%s", homedir, USER_PLUGINS_DIR, modname, MODULES_EXT);
		TRY_DLOPEN("%s%s", PLUGINS_DIR, modname);
		TRY_DLOPEN("%s/%s%s", PLUGINS_DIR, modname, MODULES_EXT);

		free(testpath);
		return NULL;
}



static int pluginadd(char *arg) {
	void *handle;
	struct plugin *p;
	int rv=ENOENT;
	if ((handle=plugin_dlopen(arg,RTLD_LAZY)) != NULL) {
		if ((p=(struct plugin *) dlsym(handle,"vde_plugin_data")) != NULL) {
			if (p->handle != NULL) { /* this dyn library is already loaded*/
				dlclose(handle);
				rv=EEXIST;
			} else {
				addplugin(p);
				p->handle=handle;
				rv=0;
			}
		} else {
			rv=EINVAL;
		}
	} 
	return rv;
}

static int plugindel(char *arg) {
	struct plugin **p=&pluginh;
	while (*p!=NULL){
		void *handle;
		if (strncmp((*p)->name, arg, strlen(arg)) == 0
				&& ((*p)->handle != NULL)) {
			struct plugin *this=*p;
			delplugin(this);
			handle=this->handle;
			this->handle=NULL;
			dlclose(handle);
			return 0;
		} else
			p=&(*p)->next;
	}
	return ENOENT;
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
#ifdef VDEPLUGIN
	{"plugin","============","PLUGINS MENU",NULL,NOARG},
	{"plugin/list","","list plugins",pluginlist,STRARG|WITHFILE},
	{"plugin/add","library","load a plugin",pluginadd,STRARG},
	{"plugin/del","name","unload a plugin",plugindel,STRARG},
#endif
};

static void sighupmgmt(int signo)
{
	EVENTOUT(MGMTSIGHUP, signo);
}

void start_consmgmt(void)
{
	swmi.swmname="console-mgmt";
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_io=handle_io;
	swmi.cleanup=cleanup;
	ADDCL(cl);
#ifdef DEBUGOPT
	ADDDBGCL(dl);
#endif
	add_swm(&swmi);
#ifdef DEBUGOPT
	signal(SIGHUP,sighupmgmt);
#endif
}
