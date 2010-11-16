/* WIREFILTER (C) 2005 Renzo Davoli
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
 * Modified by Renzo Davoli, Luca Bigliardi 2007
 * Modified by Renzo Davoli, Luca Raggi 2009 (Markov chain support)
 * Gauss normal distribution/blinking support, requested and parlty implemented
 * by Luca Saiu and Jean-Vincent Loddo (Marionnet project)
 * Gilbert model for packet loss requested by Leandro Galvao.
 *
 * This filter can be used for testing network protcols. 
 * It is possible to loose, delay or reorder packets.
 * Options can be set on command line or interactively with a remote interface
 * on a unix socket (see unixterm).
 */

#define _GNU_SOURCE
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
#include <math.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>
#include <libvdeplug.h>

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
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
struct pollfd pfd[NPFD]={[0 ... NPFD-1 ]={.fd=-1}};
int outfd[NPIPES];
char debuglevel[NPFD];
char *progname;
char *mgmt;
int mgmtmode=0700;
#define LR 0
#define RL 1
#define ALGO_UNIFORM      0
#define ALGO_GAUSS_NORMAL 1
static char charalgo[]="UN";
struct wirevalue {
	double value;
	double plus;
	char alg;
};

#define LOSS 0
#define LOSTBURST 1
#define DELAY 2
#define DDUP 3
#define BAND 4
#define SPEED 5
#define CAPACITY 6
#define NOISE 7
#define MTU 8
#define NUMVALUES 9

/* general Markov chain approach */
int markov_numnodes=0;
int markov_current=0;
struct markov_node {
	char *name;
	struct wirevalue val[NUMVALUES][2];
};
double *adjmap;
#define ADJMAPN(M,I,J,N) (M)[(I)*(N)+(J)]
#define ADJMAP(I,J) ADJMAPN(adjmap,(I),(J),markov_numnodes)
#define ROT(I,J) (((I)+(J))%markov_numnodes)
struct markov_node **markov_nodes;
#define WFVAL(N,T,D) (markov_nodes[N]->val[T][D])
#define WFADDR(N,T) (markov_nodes[N]->val[T])
#define WFNAME(N) (markov_nodes[N]->name)
double markov_time=100.0;
long long markov_next;

/*for the Gilbert model */
#define OK_BURST 0
#define FAULTY_BURST 1
char loss_status[2]; /* Gilbert model Markov chain status */
struct timeval nextband[2];
struct timeval nextspeed[2];
int nofifo; 
int ndirs; //1 mono directional, 2 bi directional filter (always 2 with -v)
int delay_bufsize[2]; //total size of delayed packets
char *vdepath[2]; //path of the directly connected switched (via vde_plug)
VDECONN *vdeplug[2]; //vde_plug connections (if NULL stdin/stdout)
int daemonize; // daemon mode
static int logok=0;
static char *rcfile;
static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];
static int blinksock;
static struct sockaddr_un blinksun;
static char *blinkmsg;
static char blinkidlen;

static void printoutc(int fd, const char *format, ...);
/* markov node mgmt */
static inline struct markov_node *markov_node_new(void)
{
	return calloc(1,sizeof(struct markov_node));
}

static inline void markov_node_free(struct markov_node *old)
{
	free(old);
}

static void markov_compute(i)
{
	int j;
	ADJMAP(i,i)=100.0;
	for (j=1;j<markov_numnodes;j++)
		ADJMAP(i,i)-=ADJMAP(i,ROT(i,j));
}

static void copyadjmap(int newsize, double *newmap)
{
	int i,j;
	for (i=0;i<newsize;i++) {
		ADJMAPN(newmap,i,i,newsize)=100.0;
		for (j=1;j<newsize;j++) {
			int newj=(i+j)%newsize;
			if (i<markov_numnodes && newj<markov_numnodes) 
				ADJMAPN(newmap,i,i,newsize)-=
					(ADJMAPN(newmap,i,newj,newsize) = ADJMAP(i,newj));
		}
	}
}

static void markov_resize(int numnodes)
{
	if (numnodes != markov_numnodes) {
		int i;
		double *newadjmap=calloc(numnodes*numnodes,sizeof(double));
		if (numnodes>markov_numnodes) {
			markov_nodes=realloc(markov_nodes,numnodes*(sizeof(struct markov_node *)));
			for (i=markov_numnodes;i<numnodes;i++)
				markov_nodes[i]=markov_node_new();
		} else {
			for (i=numnodes;i<markov_numnodes;i++)
				markov_node_free(markov_nodes[i]);
			markov_nodes=realloc(markov_nodes,numnodes*(sizeof(struct markov_node *)));
			if (markov_current >= numnodes)
				markov_current = 0;
		}
		copyadjmap(numnodes,newadjmap);
		if (adjmap)
			free(adjmap);
		adjmap=newadjmap;
		markov_numnodes=numnodes;
	}
}

static int markov_step(int i) {
	double num=drand48() * 100;
	int j,k=0;
	markov_next+=markov_time;
	for (j=0;j<markov_numnodes;j++) {
		k=ROT(i,j);
		double val=ADJMAP(i,ROT(i,j));
		if (num <= val)
			break;
		else
			num -= val;
	}
	if (i != k) {
		for (j=0;j<NPFD;j++) { 
			if (debuglevel[j] > 0) {
				int fd=pfd[j].fd;
				if (fd == 0) fd=1;
				printoutc(fd,"%04d Node %d \"%s\" -> %d \"%s\"",
						3800+k,
						i, WFNAME(i)?WFNAME(i):"",
						k, WFNAME(k)?WFNAME(k):"");
			}
		}
	}
	return k;
}

static int markovms(void) {
	if (markov_numnodes > 1) {
		struct timeval v;
		gettimeofday(&v,NULL);
		unsigned long long next=markov_next-(v.tv_sec*1000+v.tv_usec/1000);
		if (next < 0) next=0;
		return next;
	} else
		return -1;
}

static inline void markov_try(void) {
	if (markov_numnodes > 1) {
		struct timeval v;
		gettimeofday(&v,NULL);
		if ((markov_next-(v.tv_sec*1000+v.tv_usec/1000)) <= 0)
			markov_current=markov_step(markov_current);
	}
}

static void markov_start(void) {
	if (markov_numnodes > 1) {
		struct timeval v;
		gettimeofday(&v,NULL);
		markov_next=v.tv_sec*1000+v.tv_usec/1000;
		markov_current=markov_step(markov_current);
	}
}

#define BUFSIZE 2048
#define MAXCMD 128
#define MGMTMODEARG 129
#define DAEMONIZEARG 130
#define PIDFILEARG 131
#define LOGSOCKETARG 132
#define LOGIDARG 133
#define KILO (1<<10)
#define MEGA (1<<20)
#define GIGA (1<<30)

static inline double max_wirevalue(int node,int tag, int dir)
{
	return (WFVAL(node,tag,dir).value + WFVAL(node,tag,dir).plus);
}

static inline double min_wirevalue(int node,int tag, int dir)
{
	return (WFVAL(node,tag,dir).value - WFVAL(node,tag,dir).plus);
}

static void initrand()
{
	struct timeval v;
	gettimeofday(&v,NULL);
	srand48(v.tv_sec ^ v.tv_usec ^ getpid());
}

/*more than 98% inside the bell */
#define SIGMA (1.0/3.0)
static double compute_wirevalue(int tag, int dir)
{
	struct wirevalue *wv=&WFVAL(markov_current,tag,dir);
	if (wv->plus == 0)
		return wv->value;
	switch (wv->alg) {
		case ALGO_UNIFORM:
			return wv->value+wv->plus*((drand48()*2.0)-1.0);
		case ALGO_GAUSS_NORMAL:
			{
				double x,y,r2;
				do {
					x = (2*drand48())-1;
					y = (2*drand48())-1;
					r2=x*x+y*y;
				} while (r2 >= 1.0);
				return wv->value+wv->plus* SIGMA * x * sqrt ( (-2 * log(r2)) /r2);
			}
		default:
			return 0.0;
	}
}

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

static int read_wirevalue(char *s, int tag)
{
	struct wirevalue *wv;
	int markov_node=0;
	double v=0.0;
	double vplus=0.0;
	int n;
	int mult;
	char algo=ALGO_UNIFORM;
	n=strlen(s)-1;
	while ((s[n] == ' ' || s[n] == '\n' || s[n] == '\t') && n>0)
		s[n--]=0;
	if (s[n]==']')
	{
		char *idstr=&s[n];
		s[n--] = 0;
		while(s[n]!='[' && n>1)
			idstr = &s[n--];
		s[n--] = 0;
		sscanf(idstr,"%d",&markov_node);
		if (markov_node < 0 || markov_node >= markov_numnodes)
			return EINVAL;
	}
	wv=WFADDR(markov_node,tag);
	switch (s[n]) {
		case 'u':
		case 'U':
			algo=ALGO_UNIFORM;
			n--;
			break;
		case 'n':
		case 'N':
			algo=ALGO_GAUSS_NORMAL;
			n--;
			break;
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
		wv[LR].value=wv[RL].value=v*mult;
		wv[LR].plus=wv[RL].plus=vplus*mult;
		wv[LR].alg=wv[RL].alg=algo;
	} else if ((n=sscanf(s,"LR%lf+%lf",&v,&vplus)) > 0) {
		wv[LR].value=v*mult;
		wv[LR].plus=vplus*mult;
		wv[LR].alg=algo;
	} else if ((n=sscanf(s,"RL%lf+%lf",&v,&vplus)) > 0) {
		wv[RL].value=v*mult;
		wv[RL].plus=vplus*mult;
		wv[RL].alg=algo;
	}
	return 0;
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

static unsigned long long nextms()
{
	if (npq>0) {
		unsigned long long now=0;
		struct timeval v;
		gettimeofday(&v,NULL);
		now = (unsigned long long) v.tv_sec*1000+v.tv_usec/1000;
		if (pqh[1]->when > now)
			return  pqh[1]->when - now;
		else
			return 0; 
	}
	return -1;
}

static inline int outpacket(int dir,const unsigned char *buf,int size)
{
	if (blinksock) {
		snprintf(blinkmsg+blinkidlen,20,"%s %d\n",
				(ndirs==2)?((dir==0)?"LR":"RL"):"--",
				size);
		sendto(blinksock,blinkmsg,strlen(blinkmsg+blinkidlen)+blinkidlen,0,
				(struct sockaddr *)&blinksun, sizeof(blinksun));
	}
	if (vdeplug[1-dir]) 
		return vde_send(vdeplug[1-dir],buf+2,size-2,0);
	else
		return write(outfd[dir],buf,size);
}

int writepacket(int dir,const unsigned char *buf,int size)
{
	/* NOISE */
	if (max_wirevalue(markov_current,NOISE,dir) > 0) {
		double noiseval=compute_wirevalue(NOISE,dir);
		int nobit=0;
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
	unsigned long long now=(unsigned long long)v.tv_sec*1000+v.tv_usec/1000; 
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
	/* when bandwidth is limited, packets exceeding capacity are discarded */
	if (max_wirevalue(markov_current,CAPACITY,dir) > 0) {
		double capval=compute_wirevalue(CAPACITY,dir);
		if ((delay_bufsize[dir]+size) > capval)
			return;
	}
	/* */

	struct packpq *new=malloc(sizeof(struct packpq));
	if (new==NULL) {
		printlog(LOG_WARNING,"malloc elem %s",strerror(errno));
		exit (1);
	}
	gettimeofday(&v,NULL);
	new->when= ((unsigned long long)v.tv_sec * 1000 + v.tv_usec/1000) + delms; 
	if (new->when > maxwhen) maxwhen=new->when;
	if (!nofifo && new->when < maxwhen) new->when=maxwhen;
	new->dir=dir;
	new->buf=malloc(size);
	if (new->buf==NULL) {
		printlog(LOG_WARNING,"malloc elem buf %s",strerror(errno));
		exit (1);
	}
	memcpy(new->buf,buf,size);
	new->size=size;
	delay_bufsize[dir]+=size;
	if (pqh==NULL) {
		pqh=malloc(PQCHUNK*sizeof(struct packpq *));
		if (pqh==NULL) {
			printlog(LOG_WARNING,"malloc %s",strerror(errno));
			exit (1);
		}
		pqh[0]=&sentinel; maxpq=PQCHUNK;
	}
	if (npq >= maxpq) {
		pqh=realloc(pqh,(maxpq=maxpq+PQCHUNK) * sizeof(struct packpq *));
		if (pqh==NULL) {
			printlog(LOG_WARNING,"malloc %s",strerror(errno));
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
	/* if the packet is incosistent with the MTU of the line just drop it */
	if (min_wirevalue(markov_current,MTU,dir) > 0 && size > min_wirevalue(markov_current,MTU,dir))
		return;

	/* LOSS */
	/* Total packet loss */
	if (min_wirevalue(markov_current,LOSS,dir) >= 100.0)
		return;
	/* probabilistic loss */
	if (max_wirevalue(markov_current,LOSTBURST,dir) > 0) {
		/* Gilbert model */
		double losval=compute_wirevalue(LOSS,dir)/100;
		double burstlen=compute_wirevalue(LOSTBURST,dir);
		double alpha=losval / (burstlen*(1-losval));
		double beta=1.0 / burstlen;
		switch (loss_status[dir]) {
			case OK_BURST:
				if (drand48() < alpha) loss_status[dir]=FAULTY_BURST;
				break;
			case FAULTY_BURST:
				if (drand48() < beta) loss_status[dir]=OK_BURST;
				break;
		}
		if (loss_status[dir] != OK_BURST)
			return;
	} else {
		loss_status[dir] = OK_BURST;
		if (max_wirevalue(markov_current,LOSS,dir) > 0) {
			/* standard non bursty model */
			double losval=compute_wirevalue(LOSS,dir)/100;
			if (drand48() < losval)
				return;
		}
	}

	/* DUP */
	/* times is the number of dup packets */
	int times=1;
	if (max_wirevalue(markov_current,DDUP,dir) > 0) {
		double dupval=compute_wirevalue(DDUP,dir)/100;
		while (drand48() < dupval)
			times++;
	}
	while (times>0) {
		int banddelay=0;

		/* SPEED */
		/* speed limit, if packets arrive too fast, delay the sender */
		if (max_wirevalue(markov_current,SPEED,dir) > 0) {
			double speedval=compute_wirevalue(SPEED,dir);
			if (speedval<=0) return;
			if (speedval>0) {
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
		/* band, when band overflows, delay just the delivery */
		if (max_wirevalue(markov_current,BAND,dir) > 0) {
			double bandval=compute_wirevalue(BAND,dir);
			if (bandval<=0) return;
			if (bandval >0) {
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
		/* line delay */
		if (banddelay >= 0) {
			if (banddelay > 0 || max_wirevalue(markov_current,DELAY,dir) > 0) {
				double delval=compute_wirevalue(DELAY,dir);
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
			printlog(LOG_WARNING,"Packet length error size %d rnx %d",size,rnx[dir]);
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
		printlog(LOG_WARNING,"mgmt accept %s",strerror(errno));
		return nfds;
	}
	if (nfds < NPFD) {
		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		debuglevel[nfds]=0;
		return ++nfds;
	} else {
		printlog(LOG_WARNING,"too many mgmt connections");
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
	return read_wirevalue(s,DELAY);
}

static int setloss(int fd,char *s)
{
	return read_wirevalue(s,LOSS);
}

static int setlostburst(int fd,char *s)
{
	return read_wirevalue(s,LOSTBURST);
}

static int setddup(int fd,char *s)
{
	return read_wirevalue(s,DDUP);
}

static int setband(int fd,char *s)
{
	return read_wirevalue(s,BAND);
}

static int setnoise(int fd,char *s)
{
	return read_wirevalue(s,NOISE);
}

static int setmtu(int fd,char *s)
{
	return read_wirevalue(s,MTU);
}

static int setspeed(int fd,char *s)
{
	return read_wirevalue(s,SPEED);
}

static int setcapacity(int fd,char *s)
{
	return read_wirevalue(s,CAPACITY);
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

static int setmarkov_resize(int fd,char *s)
{
	int n=atoi(s);
	if (n>0) {
		markov_resize(n);
		markov_start();
		return 0;
	} else
		return EINVAL;
}

static int setedge(int fd,char *s)
{
	int x,y;
	double weight;
	sscanf(s,"%d,%d,%lg",&x,&y,&weight);
	if (x>=0 && x<markov_numnodes && y>=0 && y<markov_numnodes) {
		ADJMAP(x,y)=weight;
		markov_compute(x);
		return 0;
	} else
		return EINVAL;
}

static int setmarkov_time(int fd,char *s)
{
	double newvalue;
	sscanf(s,"%lg",&newvalue);
	if (newvalue > 0) {
		markov_time=newvalue;
		markov_start();
		return 0;
	} else
		return EINVAL;
}

static int setmarkov_node(int fd,char *s)
{
	int n=atoi(s);
	if (n>=0 && n<markov_numnodes) {
		markov_current=n;
		return 0;
	} else
		return EINVAL;
}

static int setmarkov_debug(int fd,char *s)
{
	int n=atoi(s);
	if (fd >= 0 && n>=0) {
		int i;
		if (fd==1) fd=0;
		for (i=0;i<NPFD;i++) {
			if (pfd[i].fd == fd) 
				break;
		}
		if (i<NPFD) {
				debuglevel[i]=n;
				return 0;
		} else
			return EINVAL;
	} else
		return EINVAL;
}

static int showcurrent(int fd,char *s)
{
	printoutc(fd, "Current Markov Node %d \"%s\" (0,..,%d)",markov_current,
			        WFNAME(markov_current)?WFNAME(markov_current):"",
							markov_numnodes-1);
	return 0;
}

static int setmarkov_name(int fd,char *s)
{
	int n;
	while (strchr(" \t",*s)) s++;
	n=atoi(s);
	if (n>=0 && n<markov_numnodes) {
		while (strchr("0123456789",*s)) s++;
		while (strchr(" \t",*s)) s++;
		if (*s == ',') s++;
		if (s[strlen(s)-1]=='\n')
			s[strlen(s)-1]=0;
		if (WFNAME(n)) free(WFNAME(n));
		if (*s) 
			WFNAME(n)=strdup(s);
		else
			WFNAME(n)=0;
		return 0;
	} else
		return EINVAL;
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
	printoutc(fd, "COMMAND      HELP");
	printoutc(fd, "------------ ------------");
	printoutc(fd, "help         print a summary of mgmt commands");
	printoutc(fd, "load         load a configuration file");
	printoutc(fd, "showinfo     show status and parameter values");
	printoutc(fd, "loss         set loss percentage");
	printoutc(fd, "lostburst    mean length of lost packet bursts");
	printoutc(fd, "delay        set delay ms");
	printoutc(fd, "dup          set dup packet percentage");
	printoutc(fd, "bandwidth    set channel bandwidth bytes/sec");
	printoutc(fd, "speed        set interface speed bytes/sec");
	printoutc(fd, "noise        set noise factor bits/Mbyte");
	printoutc(fd, "mtu          set channel MTU (bytes)");
	printoutc(fd, "capacity     set channel capacity (bytes)");
	printoutc(fd, "fifo         set channel fifoness");
	printoutc(fd, "shutdown     shut the channel down");
	printoutc(fd, "logout       log out from this mgmt session");
	printoutc(fd, "markov-numnodes n  markov mode: set number of states");
	printoutc(fd, "markov-setnode n   markov mode: set current state");
	printoutc(fd, "markov-name n,name markov mode: set state's name");
	printoutc(fd, "markov-time ms     markov mode: transition period");
	printoutc(fd, "setedge n1,n2,w    markov mode: set edge weight");
	printoutc(fd, "showinfo n         markov mode: show parameter values");
	printoutc(fd, "showedges n        markov mode: show edge weights");
	printoutc(fd, "showcurrent        markov mode: show current state");
	printoutc(fd, "markov-debug n     markov mode: set debug level");
	return 0;
}

#define CHARALGO(X) (charalgo[(int)(X)])
#define WIREVALUE_X_FIELDS(X) (X)->value,(X)->plus,(charalgo[(int)((X)->alg)])
#define WIREVALUE_FIELDS(N,T,D) WIREVALUE_X_FIELDS(WFADDR(N,T)+D)
static int showinfo(int fd,char *s)
{
	int node=0;
	if (*s != 0)
		node=atoi(s);
	else
		node=markov_current;
	if (node >= markov_numnodes || node < 0)
		return EINVAL;
	printoutc(fd, "WireFilter: %sdirectional",(ndirs==2)?"bi":"mono");
	if (markov_numnodes > 1) {
		printoutc(fd, "Node %d \"%s\" (0,..,%d) Markov-time %lg",node,
				WFNAME(node)?WFNAME(node):"",markov_numnodes-1,markov_time);
	}
	if (ndirs==2) {
		printoutc(fd, "Loss   L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,LOSS,LR),
				WIREVALUE_FIELDS(node,LOSS,RL));
		printoutc(fd, "Lburst L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,LOSTBURST,LR),
				WIREVALUE_FIELDS(node,LOSTBURST,RL));
		printoutc(fd, "Delay  L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,DELAY,LR),
				WIREVALUE_FIELDS(node,DELAY,RL));
		printoutc(fd, "Dup    L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,DDUP,LR),
				WIREVALUE_FIELDS(node,DDUP,RL));
		printoutc(fd, "Bandw  L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,BAND,LR),
				WIREVALUE_FIELDS(node,BAND,RL));
		printoutc(fd, "Speed  L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,SPEED,LR),
				WIREVALUE_FIELDS(node,SPEED,RL));
		printoutc(fd, "Noise  L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,NOISE,LR),
				WIREVALUE_FIELDS(node,NOISE,RL));
		printoutc(fd, "MTU    L->R %g     R->L %g   ",
				min_wirevalue(node,MTU,LR),
				min_wirevalue(node,MTU,RL));
		printoutc(fd, "Cap.   L->R %g+%g%c   R->L %g+%g%c",
				WIREVALUE_FIELDS(node,CAPACITY,LR),
				WIREVALUE_FIELDS(node,CAPACITY,RL));
		printoutc(fd, "Current Delay Queue size:   L->R %d      R->L %d   ",delay_bufsize[LR],delay_bufsize[RL]);
	} else {
		printoutc(fd, "Loss   %g+%g%c",
			WIREVALUE_FIELDS(node,LOSS,0));
		printoutc(fd, "Lburst %g+%g%c",
			WIREVALUE_FIELDS(node,LOSTBURST,0));
		printoutc(fd, "Delay  %g+%g%c",
			WIREVALUE_FIELDS(node,DELAY,0));
		printoutc(fd, "Dup    %g+%g%c",
			WIREVALUE_FIELDS(node,DDUP,0));
		printoutc(fd, "Bandw  %g+%g%c",
			WIREVALUE_FIELDS(node,BAND,0));
		printoutc(fd, "Speed  %g+%g%c",
			WIREVALUE_FIELDS(node,SPEED,0));
		printoutc(fd, "Noise  %g+%g%c",
			WIREVALUE_FIELDS(node,NOISE,0));
		printoutc(fd, "MTU    %g", min_wirevalue(node,MTU,0));
		printoutc(fd, "Cap.   %g+%g%c",
			WIREVALUE_FIELDS(node,CAPACITY,0));
		printoutc(fd, "Current Delay Queue size:   %d",delay_bufsize[0]);
	}
	printoutc(fd,"Fifoness %s",(nofifo == 0)?"TRUE":"FALSE");
	printoutc(fd,"Waiting packets in delay queues %d",npq);
	if (blinksock) {
		blinkmsg[(int)blinkidlen]=0;
		printoutc(fd,"Blink socket: %s",blinksun.sun_path);
		printoutc(fd,"Blink id:     %s",blinkmsg);
	}
	return 0;
}

static int showedges(int fd,char *s)
{
	int node=0;
	int j;
	if (*s != 0)
		node=atoi(s);
	else
		node=markov_current;
	if (node >= markov_numnodes || node < 0)
		return EINVAL;
	for (j=0;j<markov_numnodes;j++) 
		if (ADJMAP(node,j) != 0)
			printoutc(fd, "Edge %-2d->%-2d \"%s\"->\"%s\" weigth %lg",node,j,
					WFNAME(node)?WFNAME(node):"",
					WFNAME(j)?WFNAME(j):"",
					ADJMAP(node,j));
	return 0;
}

static int runscript(int fd,char *path);

#define WITHFILE 0x80
static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
	unsigned char type;
} commandlist [] = {
	{"help", help, WITHFILE},
	{"showinfo",showinfo, WITHFILE},
	{"load",runscript,WITHFILE},
	{"delay",setdelay, 0},
	{"loss",setloss, 0},
	{"lostburst",setlostburst, 0},
	{"dup",setddup, 0},
	{"bandwidth",setband, 0},
	{"band",setband, 0},
	{"speed",setspeed, 0},
	{"capacity",setcapacity, 0},
	{"noise",setnoise, 0},
	{"mtu",setmtu, 0},
	{"fifo",setfifo, 0},
	{"markov-numnodes",setmarkov_resize, 0},
	{"markov-setnode",setmarkov_node, 0},
	{"markov-name",setmarkov_name, 0},
	{"markov-time",setmarkov_time, 0},
	{"setedge",setedge, 0},
	{"showedges",showedges, WITHFILE},
	{"showcurrent",showcurrent, WITHFILE},
	{"markov-debug",setmarkov_debug, 0},
	{"logout",logout, 0},
	{"shutdown",doshutdown, 0}
};

#define NCL sizeof(commandlist)/sizeof(struct comlist)

static inline void delnl(char *buf)
{
	int len=strlen(buf)-1;
	while (len>0 && 
				(buf[len]=='\n' || buf[len]==' ' || buf[len]=='\t')) {
		buf[len]=0;
		len--;
	}
}

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	char *cmd=inbuf;
	while (*inbuf == ' ' || *inbuf == '\t' || *inbuf == '\n') inbuf++;
	delnl(inbuf);
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL 
				&& strncmp(commandlist[i].tag,inbuf,strlen(commandlist[i].tag))!=0;
				i++)
			;
		if (i<NCL)
		{
			inbuf += strlen(commandlist[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (fd>=0 && commandlist[i].type & WITHFILE)
				printoutc(fd,"0000 DATA END WITH '.'");
			rv=commandlist[i].fun(fd,inbuf);
			if (fd>=0 && commandlist[i].type & WITHFILE)
				printoutc(fd,".");
		}
		if (fd >= 0) {
			if (rv == 0) {
				printoutc(fd,"1000 Success");
			} else {
				printoutc(fd,"1%03d %s",rv,strerror(rv));
			}
		} else if (rv != 0) {
			printlog(LOG_ERR,"rc command error: %s %s",cmd,strerror(rv));
		}
		return rv;
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
			delnl(buf);
			if (fd >= 0) {
				printoutc(fd,"%s (%s) %s",prompt,path,buf);
			}
			handle_cmd(fd, buf);
		}
		fclose(f);
		return 0;
	}
}

static int mgmtcommand(int fd)
{
	char buf[MAXCMD+1];
	int n,rv;
	int outfd=fd;
	n = read(fd, buf, MAXCMD);
	if (n<0) {
		printlog(LOG_WARNING,"read from mgmt %s",strerror(errno));
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
		memmove(debuglevel+i,debuglevel+i+1,sizeof(char) * (nfds-i-1));
		pfd[nfds].fd = -1;
		debuglevel[nfds] = 0;
		nfds--;
	}
	return nfds;
}

void usage(void)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\n"
			"\t--rcfile|-f Configuration file\n"
			"\t--loss|-l loss_percentage\n"
			"\t--lostburst|-L lost_packet_burst_len\n"
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
			"\t--blink blinksocket\n"
			"\t--blinkid blink_id_string\n"
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
		{"rcfile", 1, 0, 'f'},
		{"loss", 1, 0, 'l'},
		{"lostburst", 1, 0, 'L'},
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
		{"pidfile", 1, 0, PIDFILEARG},
		{"blink",1,0,LOGSOCKETARG},
		{"blinkid",1,0,LOGIDARG}
	};
	progname=basename(argv[0]);
	markov_resize(1);

	setsighandlers();
	atexit(cleanup);

	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hnl:d:M:D:m:b:s:c:v:L:f:",
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'f':
				rcfile=strdup(optarg);
				break;
			case 'd':
				read_wirevalue(optarg,DELAY);
				break;
			case 'l':
				read_wirevalue(optarg,LOSS);
				break;
			case 'L':
				read_wirevalue(optarg,LOSTBURST);
				break;
			case 'D':
				read_wirevalue(optarg,DDUP);
				break;
			case 'b':
				read_wirevalue(optarg,BAND);
				break;
			case 'm':
				read_wirevalue(optarg,MTU);
				break;
			case 'n':
				read_wirevalue(optarg,NOISE);
				break;
			case 's':
				read_wirevalue(optarg,SPEED);
				break;
			case 'c':
				read_wirevalue(optarg,CAPACITY);
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
			case LOGSOCKETARG:
				blinksun.sun_family = PF_UNIX;
				snprintf(blinksun.sun_path,sizeof(blinksun.sun_path),"%s",optarg);
				break;
			case LOGIDARG:
				if (blinkmsg) free(blinkmsg);
				blinkidlen=strlen(optarg)+1;
				asprintf(&blinkmsg,"%s 12345678901234567890",optarg);
				break;
			default:
				usage();
				break;
		}
	}
	if (optind < argc)
		usage();

	if (blinksun.sun_path[0] != 0) {
		blinksock=socket(AF_UNIX, SOCK_DGRAM, 0);
		if (blinkmsg==NULL) {
			blinkidlen=7;
			asprintf(&blinkmsg,"%06d 12345678901234567890",getpid());
		}
	}

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

	if (rcfile)
		runscript(-1,rcfile);
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
	  printlog(LOG_INFO,"bidirectional vdeplug filter L=%s R=%s starting...",
				(*vdepath[LR])?vdepath[LR]:"DEFAULT_SWITCH",
				(*vdepath[RL])?vdepath[RL]:"DEFAULT_SWITCH");
	else if (ndirs==2)
		printlog(LOG_INFO,"bidirectional filter starting...");
	else
		printlog(LOG_INFO,"monodirectional filter starting...");

	initrand();
	while(1) {
		unsigned long long delay=nextms();
		int markovdelay=markovms();
		if (markovdelay >= 0 &&
				(markovdelay < delay || delay < 0)) delay=markovdelay;
		pfd[0].events |= POLLIN;
		if (WFVAL(markov_current,SPEED,LR).value > 0) {
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
			if (WFVAL(markov_current,SPEED,RL).value > 0) {
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
			if (mgmtindex >= 0) mgmtfdstart=mgmtindex+1;
			if (mgmtfdstart >= 0 && npfd > mgmtfdstart) {
				register int i;
				for (i=mgmtfdstart;i<npfd;i++) {
					if (pfd[i].revents & POLLIN && mgmtcommand(pfd[i].fd) < 0)
						pfd[i].revents |= POLLHUP;
					if (pfd[i].revents) n--;
				}
				for (i=mgmtfdstart;i<npfd;i++) {
					if (pfd[i].revents & POLLHUP)
						npfd=delmgmtconn(i,pfd,npfd);
				}
			} 
			if (mgmtindex >= 0) {
				if (pfd[mgmtindex].revents != 0) {
					npfd=newmgmtconn(pfd[mgmtindex].fd,pfd,npfd);
					n--;
				}
			}
/*			if (n>0) // if there are already pending events, it means that a ctlfd has hunged up
				exit(0);*/
		}
		markov_try();
		packet_dequeue();
	}
}
