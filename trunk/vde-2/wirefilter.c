/* WIREFILTER (C) 2005 Renzo Davoli
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
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
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <config.h>

#include <vde.h>

#define NPIPES 2
#define MAXCONN 3
#define STDIN_ALTFILENO 3
#define STDOUT_ALTFILENO 4
#define NPFD NPIPES+MAXCONN+1
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
int ndirs;
int bufsize[2];

#define BUFSIZE 2048
#define MAXCMD 128
#define MGMTMODEARG 129
#define KILO (1<<10)
#define MEGA (1<<20)
#define GIGA (1<<30)

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
			return write(outfd[dir],noisedpacket,size);
		} else
			return write(outfd[dir],buf,size);
	} else
		return write(outfd[dir],buf,size);
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
		bufsize[pqh[1]->dir] -= pqh[1]->size;
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
		if ((bufsize[dir]+size) > capval)
			return;
	}
	/* */

	struct packpq *new=malloc(sizeof(struct packpq));
	if (new==NULL) {
		fprintf(stderr,"%s: malloc elem %s\n",progname,strerror(errno));
		exit (1);
	}
	gettimeofday(&v,NULL);
	new->when=v.tv_sec * 1000000 + v.tv_usec + delms * 1000;
	if (new->when > maxwhen) maxwhen=new->when;
	if (!nofifo && new->when < maxwhen) new->when=maxwhen;
	new->dir=dir;
	new->buf=malloc(size);
	if (new->buf==NULL) {
		fprintf(stderr,"%s: malloc elem buf %s\n",progname,strerror(errno));
		exit (1);
	}
	memcpy(new->buf,buf,size);
	new->size=size;
	bufsize[dir]+=size;
	if (pqh==NULL) {
		pqh=malloc(PQCHUNK*sizeof(struct packpq *));
		if (pqh==NULL) {
			fprintf(stderr,"%s: malloc %s\n",progname,strerror(errno));
			exit (1);
		}
		pqh[0]=&sentinel; maxpq=PQCHUNK;
	}
	if (npq >= maxpq) {
		pqh=realloc(pqh,(maxpq=maxpq+PQCHUNK) * sizeof(struct packpq *));
		if (pqh==NULL) {
			fprintf(stderr,"%s: malloc %s\n",progname,strerror(errno));
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
			fprintf(stderr,"%s: Packet length error size %d rnx %d\n",progname,size,rnx[dir]);
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
	n=read(pfd[dir].fd,buf,BUFSIZE);
	if (n == 0)
		exit (0);
	splitpacket(buf,n,dir);
}

static void initrand()
{
	struct timeval v;
	gettimeofday(&v,NULL);
	srand48(v.tv_sec ^ v.tv_usec ^ getpid());
}

static int check_open_fifos(struct pollfd *pfd,int *outfd)
{
	int ndirs;
	struct stat stfd[NPIPES];
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
	if (fstat(STDIN_ALTFILENO,&stfd[0]) < 0) {
		ndirs=1;
		pfd[0].fd=STDIN_FILENO;
		pfd[0].events=POLLIN | POLLHUP;
		pfd[0].revents=0;
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
		pfd[LR].revents=0;
		outfd[LR]=STDOUT_ALTFILENO;
		pfd[RL].fd=STDIN_ALTFILENO;
		pfd[RL].events=POLLIN | POLLHUP;
		pfd[RL].revents=0;
		outfd[RL]=STDOUT_FILENO;
	}
	return ndirs;
}

static void cleanup(void)
{
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

static char header[]="\nVDE wirefilter V.%s\n(C) R.Davoli 2005 - GPLv2\n";
static char prompt[]="\nVDEwf:";
static int newmgmtconn(int fd,struct pollfd *pfd,int nfds)
{
	int new;
	unsigned int len;
	char buf[MAXCMD];
	struct sockaddr addr;
	new = accept(fd, &addr, &len);
	if(new < 0){
		fprintf(stderr,"%s: mgmt accept %s",progname,strerror(errno));
		return nfds;
	}
	if (nfds < NPFD) {
		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		pfd[nfds].revents=0;
		return ++nfds;
	} else {
		fprintf(stderr,"%s: too many mgmt connections",progname);
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
		printoutc(fd, "Current Delay Queue size:   L->R %d      R->L %d   ",bufsize[LR],bufsize[RL]);
	} else {
		printoutc(fd, "Loss  %g+%g",loss[0],lossplus[0]);
		printoutc(fd, "Delay %g+%g",delay[0],delayplus[0]);
		printoutc(fd, "Dup   %g+%g",ddup[0],ddupplus[0]);
		printoutc(fd, "Bandw %g+%g",band[0],bandplus[0]);
		printoutc(fd, "Speed %g+%g",speed[0],speedplus[0]);
		printoutc(fd, "Noise %g+%g",noise[0],noiseplus[0]);
		printoutc(fd, "MTU   %g",mtu[0]);
		printoutc(fd, "Cap.  %g+%g",capacity[0],capacityplus[0]);
		printoutc(fd, "Current Delay Queue size:   %d",bufsize[0]);
	}
	printoutc(fd,"Fifoness %s",(nofifo == 0)?"TRUE":"FALSE");
	printoutc(fd,"Waiting packets in delay queues %d",npq);
	return 0;
}

static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
} commandlist [] = {
	{"help", help},
	{"showinfo",showinfo},
	{"delay",setdelay},
	{"loss",setloss},
	{"dup",setddup},
	{"bandwidth",setband},
	{"band",setband},
	{"speed",setspeed},
	{"capacity",setcapacity},
	{"noise",setnoise},
	{"mtu",setmtu},
	{"fifo",setfifo},
	{"logout",logout},
	{"shutdown",doshutdown}
};

#define NCL sizeof(commandlist)/sizeof(struct comlist)

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL 
				&& strncmp(commandlist[i].tag,inbuf,strlen(commandlist[i].tag))!=0;
				i++)
			;
		if (i<NCL)
		{
			inbuf += strlen(commandlist[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			rv=commandlist[i].fun(fd,inbuf);
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
	n = read(fd, buf, MAXCMD);
	if (n<0) {
		fprintf(stderr,"%s: read from mgmt %s",progname,strerror(errno));
		return 0;
	}
	else if (n==0) 
		return -1;
	else {
		buf[n]=0;
		rv=handle_cmd(fd,buf);
		if (rv>=0)
			write(fd,prompt,strlen(prompt));
		return rv;
	}
}

static int delmgmtconn(int i,struct pollfd *pfd,int nfds)
{
	if (i<nfds) {
		close(pfd[i].fd);
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
			,progname);
	exit (1);
}

int main(int argc,char *argv[])
{
	int n;
	int npfd;
	int option_index;
	int mgmtindex=-1;
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
		{"mgmtmode", 1, 0, MGMTMODEARG}
	};
	progname=basename(argv[0]);

	setsighandlers();
	atexit(cleanup);

	ndirs=check_open_fifos(pfd,outfd);
	if (ndirs < 0)
		usage();

	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hnl:d:M:D:m:b:s:c:",
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
			case MGMTMODEARG:
				sscanf(optarg,"%o",&mgmtmode);
				break;
			default:
				usage();
				break;
		}
	}
	if (optind < argc)
		usage();

	if (ndirs==2)
		fprintf(stderr,"%s: bidirectional filter starting...\n",progname);
	else
		fprintf(stderr,"%s: monodirectional filter starting...\n",progname);

	npfd=ndirs;

	if(mgmt != NULL) {
		int mgmtfd=openmgmt(mgmt);
		mgmtindex=npfd;
		pfd[mgmtindex].fd=mgmtfd;
		pfd[mgmtindex].events=POLLIN | POLLHUP;
		pfd[mgmtindex].revents=0;
		npfd++;
	}

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
			packet_in(LR);
		}
		if (ndirs>1 && pfd[1].revents & POLLIN) {
			packet_in(RL);
		}
		if (mgmtindex >= 0 && pfd[mgmtindex].revents != 0) 
			npfd=newmgmtconn(pfd[mgmtindex].fd,pfd,npfd);
		if (npfd > mgmtindex+1) {
			register int i;
			for (i=mgmtindex+1;i<npfd;i++) {
				if (pfd[i].revents & POLLHUP ||
						(pfd[i].revents & POLLIN && mgmtcommand(pfd[i].fd) < 0))
					npfd=delmgmtconn(i,pfd,npfd);
			}
		}
		packet_dequeue();
	}
}
