/* WIREFILTER (C) 2005 Renzo Davoli
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
 * Modified by Renzo Davoli, Luca Bigliardi 2007
 *
 * This filter can be used for testing network protcols. 
 * It is possible to loose, delay or reorder packets.
 * Options can be set on command line or interactively with a remote interface
 * on a unix socket (see unixterm).
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/poll.h>
#ifndef HAVE_POLL
#include <utils/poll.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <config.h>
#include <libvdeplug/libvdeplug.h>

#include <vde.h>

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
#	include <limits.h>
#	if defined HAVE_SYSLIMITS_H
#		include <syslimits.h>
#	elif defined HAVE_SYS_SYSLIMITS_H
#		include <sys/syslimits.h>
#	else
#		error "No syslimits.h found"
#	endif
#endif

#define NPIPES 2
#define MAXCONN 3
static int alternate_stdin;
static int alternate_stdout;
#define NPFD NPIPES+NPIPES+MAXCONN+1
struct pollfd pfd[NPFD];
int outfd[NPIPES];
char *progname;
char *mgmt;
int mgmtmode=0700;
#define LR 0
#define RL 1
double loss[2],lossplus[2];
double delay[2],delayplus[2];
double ddup[2],ddupplus[2];
double band[2],bandplus[2];
double speed[2],speedplus[2];
double capacity[2],capacityplus[2];
double noise[2],noiseplus[2];
double mtu[2],mtuplus[2];
struct timeval nextband[2];
struct timeval nextspeed[2];
int nofifo; 
int ndirs; //1 mono directional, 2 bi directional filter (always 2 with -v)
int delay_bufsize[2]; //total size of delayed packets
char *vdepath[2]; //path of the directly connected switched (via vde_plug)
VDECONN *vdeplug[2]; //vde_plug connections (if NULL stdin/stdout)
int daemonize; // daemon mode
static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];
static int logok=0;

#define BUFSIZE 2048
#define MAXCMD 128
#define MGMTMODEARG 129
#define DAEMONIZEARG 130
#define PIDFILEARG 131
#define KILO (1<<10)
#define MEGA (1<<20)
#define GIGA (1<<30)

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",progname);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static void readdualvalue(char *s,double *val,double *valplus)
{
	double v=0.0;
	double vplus=0.0;
	int n;
	int mult;
	n=strlen(s)-1;
	while ((s[n] == ' ' || s[n] == '\n' || s[n] == '\t') && n>0)
	{
		s[n]=0;
		n--;
	}
	switch (s[n]) {
		case 'k':
		case 'K':
			mult=KILO;
			break;
		case 'm':
		case 'M':
			mult=MEGA;
			break;
		case 'g':
		case 'G':
			mult=GIGA;
			break;
		default:
			mult=1;
			break;
	}
	if ((n=sscanf(s,"%lf+%lf",&v,&vplus)) > 0) {
		val[LR]=val[RL]=v*mult;
		valplus[LR]=valplus[RL]=vplus*mult;
	} else if ((n=sscanf(s,"LR%lf+%lf",&v,&vplus)) > 0) {
		val[LR]=v*mult;
		valplus[LR]=vplus*mult;
	} else if ((n=sscanf(s,"RL%lf+%lf",&v,&vplus)) > 0) {
		val[RL]=v*mult;
		valplus[RL]=vplus*mult;
	}
}

struct packpq {
	unsigned long long when;
	int dir;
	unsigned char *buf;
	int size;
};

struct packpq **pqh;
struct packpq sentinel={0,0,NULL,0};
int npq,maxpq;
unsigned long long maxwhen;

#define PQCHUNK 100

static int nextms()
{
	if (npq>0) {
		long long deltat;
		struct timeval v;
		gettimeofday(&v,NULL);
		deltat=pqh[1]->when-(v.tv_sec*1000000+v.tv_usec);
		return (deltat>0)?(int)(deltat/1000):0;
	}
	return -1;
}

static inline int outpacket(int dir,const unsigned char *buf,int size)
{
	if (vdeplug[1-dir]) 
		vde_send(vdeplug[1-dir],buf+2,size-2,0);
	else
		write(outfd[dir],buf,size);
}

int writepacket(int dir,const unsigned char *buf,int size)
{
	/* NOISE */
	if (noise[dir]+noiseplus[dir] > 0) {
		double noiseval=noise[dir];
		int nobit=0;
		if (noiseplus) noiseval+=((drand48()*2.0)-1.0)*noiseplus[dir];
		while ((drand48()*8*MEGA) < (size-2)*8*noiseval)
			nobit++;
		if (nobit>0) {
			unsigned char noisedpacket[BUFSIZE];
			memcpy(noisedpacket,buf,size);
			while(nobit>0) {
				int flippedbit=(drand48()*size*8);
				noisedpacket[(flippedbit >> 3) + 2] ^= 1<<(flippedbit & 0x7);
				nobit--;
			}
			return outpacket(dir,noisedpacket,size);
		} else
			return outpacket(dir,buf,size);
	} else
		return outpacket(dir,buf,size);
}

/* packet queues are priority queues implemented on a heap.
 * enqueue time = dequeue time = O(log n) max&mean
 */

static void packet_dequeue()
{
	struct timeval v;
	gettimeofday(&v,NULL);
	unsigned long long now=v.tv_sec*1000000+v.tv_usec;
	while (npq>0 && pqh[1]->when <= now) {
		struct packpq *old=pqh[npq--];
		int k=1;
		delay_bufsize[pqh[1]->dir] -= pqh[1]->size;
		writepacket(pqh[1]->dir,pqh[1]->buf,pqh[1]->size);
		free(pqh[1]->buf);
		free(pqh[1]);
		while (k<= npq>>1)
		{
			int j= k<<1;
			if (j<npq && pqh[j]->when > pqh[j+1]->when) j++;
			if (old->when <= pqh[j]->when) {
				break;
			} else {
				pqh[k]=pqh[j];k=j;
			}
		}
		pqh[k]=old;
	}
}

static void packet_enqueue(int dir,const unsigned char *buf,int size,int delms)
{
	struct timeval v;

	/* CAPACITY */
	if (capacity[dir]+capacityplus[dir] > 0) {
		double capval=capacity[dir];
		if (capacityplus[dir])
			capval+=((drand48()*2.0)-1.0)*capacityplus[dir];
		if ((delay_bufsize[dir]+size) > capval)
			return;
	}
	/* */

	struct packpq *new=malloc(sizeof(struct packpq));
	if (new==NULL) {
		printlog(LOG_WARNING,"%s: malloc elem %s",progname,strerror(errno));
		exit (1);
	}
	gettimeofday(&v,NULL);
	new->when=v.tv_sec * 1000000 + v.tv_usec + delms * 1000;
	if (new->when > maxwhen) maxwhen=new->when;
	if (!nofifo && new->when < maxwhen) new->when=maxwhen;
	new->dir=dir;
	new->buf=malloc(size);
	if (new->buf==NULL) {
		printlog(LOG_WARNING,"%s: malloc elem buf %s",progname,strerror(errno));
		exit (1);
	}
	memcpy(new->buf,buf,size);
	new->size=size;
	delay_bufsize[dir]+=size;
	if (pqh==NULL) {
		pqh=malloc(PQCHUNK*sizeof(struct packpq *));
		if (pqh==NULL) {
			printlog(LOG_WARNING,"%s: malloc %s",progname,strerror(errno));
			exit (1);
		}
		pqh[0]=&sentinel; maxpq=PQCHUNK;
	}
	if (npq >= maxpq) {
		pqh=realloc(pqh,(maxpq=maxpq+PQCHUNK) * sizeof(struct packpq *));
		if (pqh==NULL) {
			printlog(LOG_WARNING,"%s: malloc %s",progname,strerror(errno));
			exit (1);
		}
	}
	{int k=++npq;
		while (new->when < pqh[k>>1]->when) {
			pqh[k]=pqh[k>>1];
			k >>= 1;
		}
		pqh[k]=new;
	}
}

void handle_packet(int dir,const unsigned char *buf,int size)
{
	/* MTU */
	if (mtu[dir] > 0 && size > mtu[dir])
		return;

	/* LOSS */
	if (loss[dir]-lossplus[dir] >= 100.0)
		return;
	if (loss[dir]+lossplus[dir] > 0) {
		double losval=(loss[dir]+((drand48()*2.0)-1.0)*lossplus[dir])/100;
		if (drand48() < losval)
			return;
	}

	/* DUP */
	int times=1;
	if (ddup[dir]+ddupplus[dir] > 0) {
		double dupval=(ddup[dir]+((drand48()*2.0)-1.0)*ddupplus[dir])/100;
		while (drand48() < dupval)
			times++;
	}
	while (times>0) {
		int banddelay=0;

		/* SPEED */
		if (speed[dir]+speedplus[dir] > 0) {
			double speedval=speed[dir];
			if (speedplus[dir]) {
				speedval+=((drand48()*2.0)-1.0)*speedplus[dir];
				if (speedval<=0) return;
			}
			if (speed>0) {
				unsigned int commtime=((unsigned)size)*1000000/((unsigned int)speedval);
				struct timeval tv;
				gettimeofday(&tv,NULL);
				banddelay=commtime/1000;
				if (timercmp(&tv,&nextspeed[dir], > ))
					nextspeed[dir]=tv;
				nextspeed[dir].tv_usec += commtime;
				nextspeed[dir].tv_sec += nextspeed[dir].tv_usec / 1000000;
				nextspeed[dir].tv_usec %= 1000000;
			}
		}

		/* BANDWIDTH */
		if (band[dir]+bandplus[dir] > 0) {
			double bandval=band[dir];
			if (bandplus[dir]) {
				bandval+=((drand48()*2.0)-1.0)*bandplus[dir];
				if (bandval<=0) return;
			}
			if (band>0) {
				unsigned int commtime=((unsigned)size)*1000000/((unsigned int)bandval);
				struct timeval tv;
				gettimeofday(&tv,NULL);
				if (timercmp(&tv,&nextband[dir], > )) {
					nextband[dir]=tv;
					banddelay=commtime/1000;
				} else {
					timersub(&nextband[dir],&tv,&tv);
					banddelay=tv.tv_sec*1000 + (tv.tv_usec + commtime)/1000;
				}
				nextband[dir].tv_usec += commtime;
				nextband[dir].tv_sec += nextband[dir].tv_usec / 1000000;
				nextband[dir].tv_usec %= 1000000;
			} else
				banddelay=-1;
		}

		/* DELAY */
		if (banddelay >= 0) {
			if (banddelay > 0 || delay[dir]+delayplus[dir] > 0) {
				double delval=(delay[dir]+((drand48()*2.0)-1.0)*delayplus[dir]);
				delval=(delval >= 0)?delval+banddelay:banddelay;
				if (delval > 0) {
					packet_enqueue(dir,buf,size,(int) delval); 
				} else
					writepacket(dir,buf,size);
			} else
				writepacket(dir,buf,size);
		}
		times--;
	}
}

#define MIN(X,Y) (((X)<(Y))?(X):(Y))

static void splitpacket(const unsigned char *buf,int size,int dir)
{
	static unsigned char fragment[BUFSIZE][2];
	static unsigned char *fragp[2];
	static unsigned int rnx[2],remaining[2];

	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",progname,rnx[dir],remaining[dir],size);
	if (size==0) return;
	if (rnx[dir]>0) {
		register int amount=MIN(remaining[dir],size);
		//fprintf(stderr,"%s: fragment amount %d\n",progname,amount);
		memcpy(fragp[dir],buf,amount);
		remaining[dir]-=amount;
		fragp[dir]+=amount;
		buf+=amount;
		size-=amount;
		if (remaining[dir]==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",progname,rnx[dir]);
			handle_packet(dir,fragment[dir],rnx[dir]+2);
			rnx[dir]=0;
		}
	}
	while (size > 0) {
		rnx[dir]=(buf[0]<<8)+buf[1];
		//fprintf(stderr,"%s: packet %d size %d %x %x dir %d\n",progname,rnx[dir],size-2,buf[0],buf[1],dir);
		if (rnx[dir]>1521) {
			printlog(LOG_WARNING,"%s: Packet length error size %d rnx %d",progname,size,rnx[dir]);
			rnx[dir]=0;
			return;
		}
		if (rnx[dir]+2 > size) {
			//fprintf(stderr,"%s: begin defrag %d\n",progname,rnx[dir]);
			fragp[dir]=fragment[dir];
			memcpy(fragp[dir],buf,size);
			remaining[dir]=rnx[dir]+2-size;
			fragp[dir]+=size;
			size=0;
		} else {
			handle_packet(dir,buf,rnx[dir]+2);
			buf+=rnx[dir]+2;
			size-=rnx[dir]+2;
			rnx[dir]=0;
		}
	}
}
					
static void packet_in(int dir)
{
	unsigned char buf[BUFSIZE];
	int n;
	if(vdeplug[dir]) {
		n=vde_recv(vdeplug[dir],buf+2,BUFSIZE-2,0);
		buf[0]=n>>8;
		buf[1]=n&0xFF;
		handle_packet(dir,buf,n+2);
	} else {
		n=read(pfd[dir].fd,buf,BUFSIZE);
		if (n == 0)
			exit (0);
		splitpacket(buf,n,dir);
	}
}

static void initrand()
{
	struct timeval v;
	gettimeofday(&v,NULL);
	srand48(v.tv_sec ^ v.tv_usec ^ getpid());
}

static int check_open_fifos_n_plugs(struct pollfd *pfd,int *outfd,char *vdepath[],VDECONN *vdeplug[])
{
	int ndirs=0;
	struct stat stfd[NPIPES];
	char *env_in;
	char *env_out;
	env_in=getenv("ALTERNATE_STDIN");
	env_out=getenv("ALTERNATE_STDOUT");
	if (env_in != NULL)
		alternate_stdin=atoi(env_in);
	if (env_out != NULL)
		alternate_stdout=atoi(env_out);
	if (vdepath[0]) { // -v selected
		if (strcmp(vdepath[0],"-") != 0) {
			if((vdeplug[LR]=vde_open(vdepath[0],"vde_crosscable",NULL))==NULL){
				fprintf(stderr,"vdeplug %s: %s\n",vdepath[0],strerror(errno));
				return -1;
			}
			pfd[0].fd=vde_datafd(vdeplug[LR]);
			pfd[0].events=POLLIN | POLLHUP;
		}
		if (strcmp(vdepath[1],"-") != 0) {
			if((vdeplug[RL]=vde_open(vdepath[1],"vde_crosscable",NULL))==NULL){
				fprintf(stderr,"vdeplug %s: %s\n",vdepath[1],strerror(errno));
				return -1;
			}
			pfd[1].fd=vde_datafd(vdeplug[RL]);
			pfd[1].events=POLLIN | POLLHUP;
		}
		ndirs=2;
	}
	if (vdeplug[LR] == NULL || vdeplug[RL] == NULL) {
		if (fstat(STDIN_FILENO,&stfd[STDIN_FILENO]) < 0) {
			fprintf(stderr,"%s: Error on stdin: %s\n",progname,strerror(errno));
			return -1;
		}
		if (fstat(STDOUT_FILENO,&stfd[STDOUT_FILENO]) < 0) {
			fprintf(stderr,"%s: Error on stdout: %s\n",progname,strerror(errno));
			return -1;
		}
		if (!S_ISFIFO(stfd[STDIN_FILENO].st_mode)) {
			fprintf(stderr,"%s: Error on stdin: %s\n",progname,"it is not a pipe");
			return -1;
		}
		if (!S_ISFIFO(stfd[STDOUT_FILENO].st_mode)) {
			fprintf(stderr,"%s: Error on stdin: %s\n",progname,"it is not a pipe");
			return -1;
		}
		if (vdeplug[RL] != NULL) { /* -v -:xxx */
			pfd[0].fd=STDIN_FILENO;
			pfd[0].events=POLLIN | POLLHUP;
			outfd[1]=STDOUT_FILENO;
		} else if (vdeplug[LR] != NULL) { /* -v xxx:- */
			pfd[1].fd=STDIN_FILENO;
			pfd[1].events=POLLIN | POLLHUP;
			outfd[0]=STDOUT_FILENO;
		} else if (env_in == NULL || fstat(alternate_stdin,&stfd[0]) < 0) {
			ndirs=1;
			pfd[0].fd=STDIN_FILENO;
			pfd[0].events=POLLIN | POLLHUP;
			outfd[0]=STDOUT_FILENO;
		} else {
			if (fstat(outfd[1],&stfd[1]) < 0) {
				fprintf(stderr,"%s: Error on secondary out: %s\n",progname,strerror(errno));
				return -1;
			}
			if (!S_ISFIFO(stfd[0].st_mode)) {
				fprintf(stderr,"%s: Error on secondary in: %s\n",progname,"it is not a pipe");
				return -1;
			}
			if (!S_ISFIFO(stfd[1].st_mode)) {
				fprintf(stderr,"%s: Error on secondary out: %s\n",progname,"it is not a pipe");
				return -1;
			}
			ndirs=2;
			pfd[LR].fd=STDIN_FILENO;
			pfd[LR].events=POLLIN | POLLHUP;
			outfd[LR]=alternate_stdout;
			pfd[RL].fd=alternate_stdin;
			pfd[RL].events=POLLIN | POLLHUP;
			outfd[RL]=STDOUT_FILENO;
		}
	}
	return ndirs;
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
	if((pidfile != NULL) && unlink(pidfile_path) < 0) {
		printlog(LOG_WARNING,"Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
	}
	if (vdeplug[LR])
		vde_close(vdeplug[LR]);
	if (vdeplug[RL])
		vde_close(vdeplug[RL]);
	if (mgmt)
		unlink(mgmt);
}

static void sig_handler(int sig)
{
	/*fprintf(stderr,"Caught signal %d, cleaning up and exiting", sig);*/
	cleanup();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
} 

static void setsighandlers()
{
	/* setting signal handlers.
	 *    *      * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 *       *           * ignores all the others signals which could cause termination. */
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
			fprintf(stderr,"%s: Setting handler for %s: %s", progname, signals[i].name,
					strerror(errno));
}

static int openmgmt(char *mgmt)
{
	int mgmtconnfd;
	struct sockaddr_un sun;
	int one = 1;

	if((mgmtconnfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		fprintf(stderr,"%s: mgmt socket: %s",progname,strerror(errno));
		exit(1);
	}
	if(setsockopt(mgmtconnfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		fprintf(stderr,"%s: mgmt setsockopt: %s",progname,strerror(errno));
		exit(1);
	}
	if(fcntl(mgmtconnfd, F_SETFL, O_NONBLOCK) < 0){
		fprintf(stderr,"%s: Setting O_NONBLOCK on mgmt fd: %s",progname,strerror(errno));
		exit(1);
	}
	sun.sun_family = PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",mgmt);
	if(bind(mgmtconnfd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		fprintf(stderr,"%s: mgmt bind %s",progname,strerror(errno));
		exit(1);
	}
	chmod(sun.sun_path,mgmtmode);
	if(listen(mgmtconnfd, 15) < 0){
		fprintf(stderr,"%s: mgmt listen: %s",progname,strerror(errno));
		exit(1);
	}
	return mgmtconnfd;
}

static char header[]="\nVDE wirefilter V.%s\n(C) R.Davoli 2005,2006 - GPLv2\n";
static char prompt[]="\nVDEwf$ ";
static int newmgmtconn(int fd,struct pollfd *pfd,int nfds)
{
	int new;
	unsigned int len;
	char buf[MAXCMD];
	struct sockaddr addr;
	new = accept(fd, &addr, &len);
	if(new < 0){
		printlog(LOG_WARNING,"%s: mgmt accept %s",progname,strerror(errno));
		return nfds;
	}
	if (nfds < NPFD) {
		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		return ++nfds;
	} else {
		printlog(LOG_WARNING,"%s: too many mgmt connections",progname);
		close (new);
		return nfds;
	}
}

static void printoutc(int fd, const char *format, ...)
{
	va_list arg;
	char outbuf[MAXCMD+1];

	va_start (arg, format);
	vsnprintf(outbuf,MAXCMD,format,arg);
	strcat(outbuf,"\n");
	write(fd,outbuf,strlen(outbuf));
}

static int setdelay(int fd,char *s)
{
	readdualvalue(s,delay,delayplus);
	return 0;
}

static int setloss(int fd,char *s)
{
	readdualvalue(s,loss,lossplus);
	return 0;
}

static int setddup(int fd,char *s)
{
	readdualvalue(s,ddup,ddupplus);
	return 0;
}

static int setband(int fd,char *s)
{
	readdualvalue(s,band,bandplus);
	return 0;
}

static int setnoise(int fd,char *s)
{
	readdualvalue(s,noise,noiseplus);
	return 0;
}

static int setmtu(int fd,char *s)
{
	readdualvalue(s,mtu,mtuplus);
	return 0;
}

static int setspeed(int fd,char *s)
{
	readdualvalue(s,speed,speedplus);
	return 0;
}

static int setcapacity(int fd,char *s)
{
	readdualvalue(s,capacity,capacityplus);
	return 0;
}

static int setfifo(int fd,char *s)
{
	int n=atoi(s);
	if (n==0) 
		nofifo=1;
	else
		nofifo=0;
	return 0;
}

static int logout(int fd,char *s)
{
	return -1;
}

static int doshutdown(int fd,char *s)
{
	exit(0);
}


static int help(int fd,char *s)
{
	printoutc(fd, "help:      print a summary of mgmt commands");
	printoutc(fd, "showinfo:  show status and parameter values");
	printoutc(fd, "loss:      set loss percentage");
	printoutc(fd, "delay:     set delay ms");
	printoutc(fd, "dup:       set dup packet percentage");
	printoutc(fd, "bandwidth: set channel bandwidth bytes/sec");
	printoutc(fd, "speed:     set interface speed bytes/sec");
	printoutc(fd, "noise:     set noise factor bits/Mbyte");
	printoutc(fd, "mtu:       set channel MTU (bytes)");
	printoutc(fd, "capacity:  set channel capacity (bytes)");
	printoutc(fd, "fifo:      set channel fifoness");
	printoutc(fd, "shutdown:  shut the channel down");
	printoutc(fd, "logout:    log out from this mgmt session");
	return 0;
}

static int showinfo(int fd,char *s)
{
	printoutc(fd, "WireFilter: %sdirectional",(ndirs==2)?"bi":"mono");
	if (ndirs==2) {
		printoutc(fd, "Loss  L->R %g+%g   R->L %g+%g",loss[LR],lossplus[LR],loss[RL],lossplus[RL]);
		printoutc(fd, "Delay L->R %g+%g   R->L %g+%g",delay[LR],delayplus[LR],delay[RL],delayplus[RL]);
		printoutc(fd, "Dup   L->R %g+%g   R->L %g+%g",ddup[LR],ddupplus[LR],ddup[RL],ddupplus[RL]);
		printoutc(fd, "Bandw L->R %g+%g   R->L %g+%g",band[LR],bandplus[LR],band[RL],bandplus[RL]);
		printoutc(fd, "Speed L->R %g+%g   R->L %g+%g",speed[LR],speedplus[LR],speed[RL],speedplus[RL]);
		printoutc(fd, "Noise L->R %g+%g   R->L %g+%g",noise[LR],noiseplus[LR],noise[RL],noiseplus[RL]);
		printoutc(fd, "MTU   L->R %g      R->L %g   ",mtu[LR],mtu[RL]);
		printoutc(fd, "Cap.  L->R %g+%g   R->L %g+%g",capacity[LR],capacityplus[LR],capacity[RL],capacityplus[RL]);
		printoutc(fd, "Current Delay Queue size:   L->R %d      R->L %d   ",delay_bufsize[LR],delay_bufsize[RL]);
	} else {
		printoutc(fd, "Loss  %g+%g",loss[0],lossplus[0]);
		printoutc(fd, "Delay %g+%g",delay[0],delayplus[0]);
		printoutc(fd, "Dup   %g+%g",ddup[0],ddupplus[0]);
		printoutc(fd, "Bandw %g+%g",band[0],bandplus[0]);
		printoutc(fd, "Speed %g+%g",speed[0],speedplus[0]);
		printoutc(fd, "Noise %g+%g",noise[0],noiseplus[0]);
		printoutc(fd, "MTU   %g",mtu[0]);
		printoutc(fd, "Cap.  %g+%g",capacity[0],capacityplus[0]);
		printoutc(fd, "Current Delay Queue size:   %d",delay_bufsize[0]);
	}
	printoutc(fd,"Fifoness %s",(nofifo == 0)?"TRUE":"FALSE");
	printoutc(fd,"Waiting packets in delay queues %d",npq);
	return 0;
}

#define WITHFD 0x80
static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
	unsigned char type;
} commandlist [] = {
	{"help", help, WITHFD},
	{"showinfo",showinfo, WITHFD},
	{"delay",setdelay, 0},
	{"loss",setloss, 0},
	{"dup",setddup, 0},
	{"bandwidth",setband, 0},
	{"band",setband, 0},
	{"speed",setspeed, 0},
	{"capacity",setcapacity, 0},
	{"noise",setnoise, 0},
	{"mtu",setmtu, 0},
	{"fifo",setfifo, 0},
	{"logout",logout, 0},
	{"shutdown",doshutdown, 0}
};

#define NCL sizeof(commandlist)/sizeof(struct comlist)

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	while (*inbuf == ' ' || *inbuf == '\t' || *inbuf == '\n') inbuf++;
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL 
				&& strncmp(commandlist[i].tag,inbuf,strlen(commandlist[i].tag))!=0;
				i++)
			;
		if (i<NCL)
		{
			inbuf += strlen(commandlist[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (commandlist[i].type & WITHFD)
				printoutc(fd,"0000 DATA END WITH '.'");
			rv=commandlist[i].fun(fd,inbuf);
			if (commandlist[i].type & WITHFD)
				printoutc(fd,".");
		}
		printoutc(fd,"1%03d %s",rv,strerror(rv));
		return rv;
	}
	return rv;
}

static int mgmtcommand(int fd)
{
	char buf[MAXCMD+1];
	int n,rv;
	int outfd=fd;
	n = read(fd, buf, MAXCMD);
	if (n<0) {
		printlog(LOG_WARNING,"%s: read from mgmt %s",progname,strerror(errno));
		return 0;
	}
	else if (n==0) 
		return -1;
	else {
		if (fd==STDIN_FILENO)
			outfd=STDOUT_FILENO;
		buf[n]=0;
		rv=handle_cmd(outfd,buf);
		if (rv>=0)
			write(outfd,prompt,strlen(prompt));
		return rv;
	}
}

static int delmgmtconn(int i,struct pollfd *pfd,int nfds)
{
	if (i<nfds) {
		close(pfd[i].fd);
		if (pfd[i].fd == 0) /* close stdin implies exit */
			exit(0);
		memmove(pfd+i,pfd+i+1,sizeof (struct pollfd) * (nfds-i-1));
		nfds--;
	}
	return nfds;
}

void usage(void)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\n"
			"\t--loss|-l loss_percentage\n"
			"\t--delay|-d delay_ms\n"
			"\t--dup|-D dup_percentage\n"
			"\t--band|-b bandwidth(bytes/s)\n"
			"\t--speed|-s interface_speed(bytes/s)\n"
			"\t--capacity|-c delay_channel_capacity\n"
			"\t--noise|-n noise_bits/megabye\n"
			"\t--mtu|-m mtu_size\n"
			"\t--nofifo|-N\n"
			"\t--mgmt|-M management_socket\n"
			"\t--mgmtmode management_permission(octal)\n"
			"\t--vde-plug plug1:plug2 | -v plug1:plug2\n"
			"\t--daemon\n"
			"\t--pidfile pidfile\n"
			,progname);
	exit (1);
}

int main(int argc,char *argv[])
{
	int n;
	int npfd;
	int option_index;
	int mgmtindex=-1;
	int consoleindex=-1;
	static struct option long_options[] = {
		{"help",0 , 0, 'h'},
		{"loss", 1, 0, 'l'},
		{"delay",1 , 0, 'd'},
		{"dup",1 , 0, 'D'},
		{"band",1 , 0, 'b'},
		{"speed",1 , 0, 's'},
		{"capacity",1 , 0, 'c'},
		{"noise",1 , 0, 'n'},
		{"mtu",1 , 0, 'm'},
		{"nofifo",0 , 0, 'N'},
		{"mgmt", 1, 0, 'M'},
		{"mgmtmode", 1, 0, MGMTMODEARG},
		{"vde-plug",1,0,'v'},
		{"daemon",0 , 0, DAEMONIZEARG},
		{"pidfile", 1, 0, PIDFILEARG}
	};
	progname=basename(argv[0]);

	setsighandlers();
	atexit(cleanup);


	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hnl:d:M:D:m:b:s:c:v:",
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'd':
				readdualvalue(optarg,delay,delayplus);
				break;
			case 'l':
				readdualvalue(optarg,loss,lossplus);
				break;
			case 'D':
				readdualvalue(optarg,ddup,ddupplus);
				break;
			case 'b':
				readdualvalue(optarg,band,bandplus);
				break;
			case 'm':
				readdualvalue(optarg,mtu,mtuplus);
				break;
			case 'n':
				readdualvalue(optarg,noise,noiseplus);
				break;
			case 's':
				readdualvalue(optarg,speed,speedplus);
				break;
			case 'c':
				readdualvalue(optarg,capacity,capacityplus);
				break;
			case 'M':
				mgmt=strdup(optarg);
				break;
			case 'N':
				nofifo=1;
				break;
			case 'v':
				{
					char *colon;
					vdepath[LR]=strdup(optarg);
					colon=index(vdepath[LR],':');
					if (colon) {
						*colon=0;
						vdepath[RL]=colon+1;
					} else {
						fprintf(stderr,"Bad vde_plugs specification.\n");
						usage();
					}
				}
			case MGMTMODEARG:
				sscanf(optarg,"%o",&mgmtmode);
				break;
			case DAEMONIZEARG:
				daemonize=1;
				break;
			case PIDFILEARG:
				pidfile=strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}
	if (optind < argc)
		usage();

	/* pfd structure:
	 * monodir: 0 input LR, 1 mgmtctl, >1  mgmt open conn (mgmtindex==ndirs==1)
	 * bidir on streams: 0 input LR, 1 input RL, 2 mgmtctl, >2 mgmt open conn (mgmtindex==ndirs==2)
	 * vdeplug xx:xx : 0 input LR, 1 input RL, 2&3 ctlfd, 4 mgmtctl, > 4 mgmt open conn (mgmtindex>ndirs==2) 5 is console
	 * vdeplug xx:xx : 0 input LR, 1 input RL, 2&3 ctlfd, 4 console (if not -M)
	 * vdeplug -:xx : 0 input LR(stdin), 1 input RL, 2 ctlfd, 3 mgmtctl, > 3 mgmt open conn (mgmtindex>ndirs==2)
	 * vdeplug xx:- : 0 input LR, 1 input RL(stdin), 2 ctlfd, 3 mgmtctl, > 3 mgmt open conn (mgmtindex>ndirs==2)
	 */

	ndirs=check_open_fifos_n_plugs(pfd,outfd,vdepath,vdeplug);

	if (ndirs < 0)
		usage();

	npfd=ndirs;
	if (vdeplug[LR]) {
		pfd[npfd].fd=vde_ctlfd(vdeplug[LR]);
		pfd[npfd].events=POLLIN | POLLHUP;
		npfd++;
	}
	if (vdeplug[RL]) {
		pfd[npfd].fd=vde_ctlfd(vdeplug[RL]);
		pfd[npfd].events=POLLIN | POLLHUP;
		npfd++;
	}

	if(mgmt != NULL) {
		int mgmtfd=openmgmt(mgmt);
		mgmtindex=npfd;
		pfd[mgmtindex].fd=mgmtfd;
		pfd[mgmtindex].events=POLLIN | POLLHUP;
		npfd++;
	}

	if (daemonize) {
		openlog(progname, LOG_PID, 0);
		logok=1;
	} else if (vdeplug[LR] && vdeplug[RL]) { // console mode
		consoleindex=npfd;
		pfd[npfd].fd=STDIN_FILENO;
		pfd[npfd].events=POLLIN | POLLHUP;
		npfd++;
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

	if (vdepath[LR]) 
	  printlog(LOG_INFO,"%s: bidirectional vdeplug filter L=%s R=%s starting...",progname,
				(*vdepath[LR])?vdepath[LR]:"DEFAULT_SWITCH",
				(*vdepath[RL])?vdepath[RL]:"DEFAULT_SWITCH");
	else if (ndirs==2)
		printlog(LOG_INFO,"%s: bidirectional filter starting...",progname);
	else
		printlog(LOG_INFO,"%s: monodirectional filter starting...",progname);

	initrand();
	while(1) {
		int delay=nextms();
		pfd[0].events |= POLLIN;
		if (speed[LR] > 0) {
			struct timeval tv;
			int speeddelay;
			gettimeofday(&tv,NULL);
			if (timercmp(&tv, &nextspeed[LR], <)) {
				timersub(&nextspeed[LR],&tv,&tv);
				speeddelay=tv.tv_sec*1000 + tv.tv_usec/1000;
				if (speeddelay > 0) {
					pfd[0].events &= ~POLLIN;
					if (speeddelay < delay || delay < 0) delay=speeddelay;
				}
			}
		}
		if (ndirs > 1) {
			pfd[1].events |= POLLIN;
			if (speed[RL] > 0) {
				struct timeval tv;
				int speeddelay;
				if (timercmp(&tv, &nextspeed[RL], <)) {
					gettimeofday(&tv,NULL);
					timersub(&nextspeed[RL],&tv,&tv);
					speeddelay=tv.tv_sec*1000 + tv.tv_usec/1000;
					if (speeddelay > 0) {
						pfd[1].events &= ~POLLIN;
						if (speeddelay < delay || delay < 0) delay=speeddelay;
					}
				}
			}
		}
		n=poll(pfd,npfd,delay);
		if (pfd[0].revents & POLLHUP || (ndirs>1 && pfd[1].revents & POLLHUP))
			exit(0);
		if (pfd[0].revents & POLLIN) {
			packet_in(LR); n--;
		}
		if (ndirs>1 && pfd[1].revents & POLLIN) {
			packet_in(RL); n--;
		}
		if (n>0) { // if there are already events to handle (performance: packet switching first)
			int mgmtfdstart=consoleindex;
			if (mgmtindex >= 0) {
				if (pfd[mgmtindex].revents != 0) {
					npfd=newmgmtconn(pfd[mgmtindex].fd,pfd,npfd);
					n--;
				}
				mgmtfdstart=mgmtindex+1;
			}
			if (mgmtfdstart >= 0 && npfd > mgmtfdstart) {
				register int i;
				for (i=mgmtfdstart;i<npfd;i++) {
					if (pfd[i].revents & POLLHUP ||
							(pfd[i].revents & POLLIN && mgmtcommand(pfd[i].fd) < 0))
						npfd=delmgmtconn(i,pfd,npfd);
					if (pfd[i].revents) n--;
				}
			} 
/*			if (n>0) // if there are already pending events, it means that a ctlfd has hunged up
				exit(0);*/
		}
		packet_dequeue();
	}
}
