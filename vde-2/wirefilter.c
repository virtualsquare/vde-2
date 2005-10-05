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
#include <linux/un.h>
#include <config.h>

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
int nofifo;
int ndirs;

#define BUFSIZE 2048
#define MAXCMD 128
#define MGMTMODEARG 129

void usage(void)
{
	fprintf(stderr,"Usage: %s [-l loss_percentage] [-d delay] [-n] [-M mgmt]\n",progname);
	exit (1);
}

static void readdualvalue(char *s,double *val,double *valplus)
{
	double v=0.0;
	double vplus=0.0;
	int n;
	if ((n=sscanf(s,"%lf+%lf",&v,&vplus)) > 0) {
		val[LR]=val[RL]=v;
		valplus[LR]=valplus[RL]=vplus;
	} else if ((n=sscanf(s,"LR%lf+%lf",&v,&vplus)) > 0) {
		val[LR]=v;
		valplus[LR]=vplus;
	} else if ((n=sscanf(s,"RL%lf+%lf",&v,&vplus)) > 0) {
		val[RL]=v;
		valplus[RL]=vplus;
	}
}

struct packpq {
	unsigned long long when;
	int dir;
	char *buf;
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

static void packet_dequeue()
{
	struct timeval v;
	gettimeofday(&v,NULL);
	unsigned long long now=v.tv_sec*1000000+v.tv_usec;
	while (npq>0 && pqh[1]->when <= now) {
		struct packpq *old=pqh[npq--];
		int k=1;
		write(outfd[pqh[1]->dir],pqh[1]->buf,pqh[1]->size);
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
	struct packpq *new=malloc(sizeof(struct packpq));
	if (new==NULL) {
		fprintf(stderr,"Usage: %s malloc elem %s\n",progname,strerror(errno));
		exit (1);
	}
	gettimeofday(&v,NULL);
	new->when=v.tv_sec * 1000000 + v.tv_usec + delms * 1000;
	if (new->when > maxwhen) maxwhen=new->when;
	if (!nofifo && new->when < maxwhen) new->when=maxwhen;
	new->dir=dir;
	new->buf=malloc(size);
	if (new->buf==NULL) {
		fprintf(stderr,"Usage: %s malloc elem buf %s\n",progname,strerror(errno));
		exit (1);
	}
	memcpy(new->buf,buf,size);
	new->size=size;
	if (pqh==NULL) {
		pqh=malloc(PQCHUNK*sizeof(struct packpq *));
		if (pqh==NULL) {
			fprintf(stderr,"Usage: %s malloc %s\n",progname,strerror(errno));
			exit (1);
		}
		pqh[0]=&sentinel; maxpq=PQCHUNK;
	}
	if (npq >= maxpq) {
		pqh=realloc(pqh,(maxpq=maxpq+PQCHUNK) * sizeof(struct packpq *));
		if (pqh==NULL) {
			fprintf(stderr,"Usage: %s malloc %s\n",progname,strerror(errno));
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
	/* LOSS */
	if (loss[dir]-lossplus[dir] >= 100.0)
		return;
	if (loss[dir]+lossplus[dir] > 0) {
		double losval=(loss[dir]+((drand48()*2.0)-1.0)*lossplus[dir])/100;
		if (drand48() < losval)
			return;
	}

	/* DELAY */
	if (delay[dir]+delayplus[dir] > 0) {
		double delval=(delay[dir]+((drand48()*2.0)-1.0)*delayplus[dir]);
		if (delval > 0) {
			packet_enqueue(dir,buf,size,(int) delval); 
		} else
			write(outfd[dir],buf,size);
	} else
		write(outfd[dir],buf,size);
}

#define MIN(X,Y) (((X)<(Y))?(X):(Y))

static void splitpacket(const unsigned char *buf,int size,int dir)
{
	static unsigned char fragment[BUFSIZE];
	static unsigned char *fragp;
	static unsigned int rnx,remaining;

	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",myname,rnx,remaining,size);
	if (size==0) return;
	if (rnx>0) {
		register int amount=MIN(remaining,size);
		//fprintf(stderr,"%s: fragment amount %d\n",myname,amount);
		memcpy(fragp,buf,amount);
		remaining-=amount;
		fragp+=amount;
		buf+=amount;
		size-=amount;
		if (remaining==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",myname,rnx);
			handle_packet(dir,fragment,rnx+2);
			rnx=0;
		}
	}
	while (size > 0) {
		rnx=(buf[0]<<8)+buf[1];
		//fprintf(stderr,"%s: packet %d size %d %x %x dir %d\n",progname,rnx,size-2,buf[0],buf[1],dir);
		if (rnx>1521) {
			fprintf(stderr,"%s: Packet length error size %d rnx %d\n",progname,size,rnx);
			rnx=0;
			return;
		}
		if (rnx+2 > size) {
			//fprintf(stderr,"%s: begin defrag %d\n",myname,rnx);
			fragp=fragment;
			memcpy(fragp,buf,size);
			remaining=rnx+2-size;
			fragp+=size;
			size=0;
		} else {
			handle_packet(dir,buf,rnx+2);
			buf+=rnx+2;
			size-=rnx+2;
			rnx=0;
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
		exit(1);
	}
	if (fstat(STDOUT_FILENO,&stfd[STDOUT_FILENO]) < 0) {
		fprintf(stderr,"%s: Error on stdout: %s\n",progname,strerror(errno));
		exit(1);
	}
	if (!S_ISFIFO(stfd[STDIN_FILENO].st_mode)) {
		fprintf(stderr,"%s: Error on stdin: %s\n",progname,"it is not a pipe");
		exit(1);
	}
	if (!S_ISFIFO(stfd[STDOUT_FILENO].st_mode)) {
		fprintf(stderr,"%s: Error on stdin: %s\n",progname,"it is not a pipe");
		exit(1);
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
			exit(1);
		}
		if (!S_ISFIFO(stfd[0].st_mode)) {
			fprintf(stderr,"%s: Error on secondary in: %s\n",progname,"it is not a pipe");
			exit(1);
		}
		if (!S_ISFIFO(stfd[1].st_mode)) {
			fprintf(stderr,"%s: Error on secondary out: %s\n",progname,"it is not a pipe");
			exit(1);
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
		{ SIGPOLL, "SIGPOLL", 1 },
		{ SIGPROF, "SIGPROF", 1 },
		{ SIGVTALRM, "SIGVTALRM", 1 },
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
		{ SIGUNUSED, "SIGUNUSED", 1 },
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
	snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",mgmt);
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

static int help(int fd,char *s)
{
	printoutc(fd, "help:      print a summary of mgmt commands");
	printoutc(fd, "showinfo:  show status and parameter values");
	printoutc(fd, "loss:      set loss percentage");
	printoutc(fd, "delay:     set delay");
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
	} else {
		printoutc(fd, "Loss  %g+%g",loss[0],lossplus[0]);
		printoutc(fd, "Delay %g+%g",delay[0],delayplus[0]);
	}
	printoutc(fd,"Fifoness %s",(nofifo == 0)?"TRUE":"FALSE");
	printoutc(fd,"Waiting packets in delay queues %d",npq);
	return 0;
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

static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
} commandlist [] = {
	{"help", help},
	{"showinfo",showinfo},
	{"delay",setdelay},
	{"loss",setloss},
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
		{"nofifo",0 , 0, 'n'},
		{"mgmt", 1, 0, 'M'},
		{"mgmtmode", 1, 0, MGMTMODEARG}
	};
	progname=basename(argv[0]);

	setsighandlers();
	atexit(cleanup);

	ndirs=check_open_fifos(pfd,outfd);

	while(1) {
		int c;
		c = getopt_long_only (argc, argv, "hnl:d:M:",
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
			case 'M':
				mgmt=strdup(optarg);
				break;
			case 'n':
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
		n=poll(pfd,npfd,nextms());
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
