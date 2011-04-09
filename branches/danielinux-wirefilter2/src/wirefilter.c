/* WIREFILTER2 (C) 2011 Renzo Davoli, Daniele Lacamera
 * Licensed under the GPLv2
 * Based on "wirefilter" by Renzo Davoli 
 * Modified by Ludovico Gardenghi 2005
 * Modified by Renzo Davoli, Luca Bigliardi 2007
 * Modified by Renzo Davoli, Luca Raggi 2009
 * Some implementation by:
 * Luca Saiu and Jean-Vincent Loddo (Marionnet project)
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
#include <stdint.h>

#define min(a,b) a<b?a:b

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
#define CHANBUFSIZE 6
#define NOISE 7
#define MTU 8
#define NUMVALUES 9

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
int nofifo = 0; 
int ndirs; //1 mono directional, 2 bi directional filter (always 2 with -v)
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

static inline unsigned long long
gettimeofdayms(void) {
	struct timeval tv;
	gettimeofday(&tv, 0);
	return (unsigned long long) tv.tv_sec * 1000ULL + (unsigned long long) tv.tv_usec / 1000;
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


/*** WF 2 ***/

struct red_parms {
	int enabled;
	uint32_t min;
	uint32_t max;
	double P;
	uint32_t limit;
};

static struct red_parms red[2];

void red_set_parms(struct red_parms *p, uint32_t min, uint32_t max, double P, uint32_t limit)
{
	p->min = min;
	p->max = max;
	p->P = P;
	p->limit = limit;
	p->enabled=1;
}

int parse_red(char *arg, struct red_parms *p){
	unsigned rmin=0,rmax=0,limit=0;
	double probability=0;
	int direction;
	if (strncmp(arg,"LR",2)==0){
		direction=LR;
		arg+=2;
	} else if(strncmp(arg,"RL",2)==0){
		direction=RL;
		arg+=2;
	} else direction = 2;

	if (
	sscanf(arg,"%lu,%lu,%lf,%lu",&rmin,&rmax,&probability,&limit)<=0 
	|| (!rmin || !rmax || !limit || probability <= 0)
	){
		fprintf(stderr,"Failed to set RED parameters. Red disabled.\n");
		return 0;
	}
	fprintf(stderr,"red min=%lu, max=%lu, prob=%lf, limit=%lu\n", rmin,rmax,probability,limit);
	switch (direction){
		case LR:
 			red_set_parms(&p[LR],rmin,rmax,probability,limit);
			return 0;	
		case RL:
 			red_set_parms(&p[LR],rmin,rmax,probability,limit);
 			red_set_parms(&p[RL],rmin,rmax,probability,limit);
			return 0;	
		case 2:
 			red_set_parms(&p[LR],rmin,rmax,probability,limit);
 			red_set_parms(&p[RL],rmin,rmax,probability,limit);
			return 0;
	}

	return 0;
}

#define WFP_LOSS 0x01
struct wf_packet {
	struct wf_packet *next;
	unsigned char payload[BUFSIZE];
	unsigned short size;
	unsigned long long dequeue_time;
	int dir;
	unsigned char flags;
};

static unsigned long outqueue_delay;
static struct wf_packet *wf_queue_in[2], *wf_queue_in_tail[2];
static struct wf_packet *wf_queue_out[2], *wf_queue_out_tail[2];
static unsigned long queue_size_in[2], queue_size_out[2];

int queue_size(struct wf_packet *p) {
	int n = 0;
	while(p){
		n++;
		p=p->next;
	}
	return n;
}

static struct wf_packet *_pkt_enqueue(struct wf_packet *q, struct wf_packet *pkt)
{
	if (!q) {
		return pkt;
	}
	if ((nofifo) && (pkt->dequeue_time < q->dequeue_time)) {
		fprintf(stderr,"reordering...\n");
		pkt->next = q;
		return pkt;
	}
	q->next = _pkt_enqueue(q->next, pkt);
	return q;
}

static void pkt_enqueue_in(struct wf_packet *pkt)
{
	struct wf_packet *q = wf_queue_in[pkt->dir];
	pkt->next = NULL;
	queue_size_in[pkt->dir] += pkt->size;
	if (!q) {
		wf_queue_in[pkt->dir] = pkt;
		wf_queue_in_tail[pkt->dir] = pkt;
		return;
	}
	if (!nofifo && wf_queue_in_tail[pkt->dir]) {
		wf_queue_in_tail[pkt->dir]->next = pkt;
		wf_queue_in_tail[pkt->dir] = pkt;
		return;
	}
	wf_queue_in[pkt->dir] = _pkt_enqueue(q, pkt);
	//fprintf(stderr,"enqueued[%d]. Size now: %d\n", pkt->dir, queue_size(wf_queue_in[pkt->dir]));
	
}

static void pkt_enqueue_out(struct wf_packet *pkt)
{
	struct wf_packet *q = wf_queue_out[pkt->dir];
	queue_size_out[pkt->dir] += pkt->size;
	pkt->next = NULL;
	wf_queue_out[pkt->dir] = _pkt_enqueue(q, pkt);
	//fprintf(stderr,"============= OUT =========== enqueued[%d]. Size now: %d\n", pkt->dir, queue_size(wf_queue_out[pkt->dir]));
}

static int is_time_to_dequeue(int dir)
{
	unsigned long long now = gettimeofdayms();
	if (wf_queue_in[dir]) 
		return (now >= wf_queue_in[dir]->dequeue_time);
	else return 0;
}

static int process_queue_out(void)
{
	static unsigned long long now, last_out[2] = {0ULL, 0ULL};
	struct wf_packet *pkt;
	int i, count[2] = {0}, old_count[2] = {0};
	do {
		old_count[0] = count[0];
		old_count[1] = count[1];
		for (i = 0; i < 2; i++) {
			double bandval;
			pkt = wf_queue_out[i];
			if (!pkt)
				continue;
			bandval = compute_wirevalue(BAND,i);
			if (bandval == 0) {
				writepacket(pkt);
				wf_queue_out[i] = pkt->next;
				queue_size_out[pkt->dir] -= pkt->size;
				count[i] += pkt->size;
				last_out[i] = gettimeofdayms(); 
				free(pkt);
			} else {
				now = gettimeofdayms();
				pkt->dequeue_time = (unsigned long long) ((double)last_out[i] + (((double)(pkt->size + count[i])*1000) / bandval));
				if (now >= pkt->dequeue_time) {
					writepacket(pkt);
					wf_queue_out[i] = pkt->next;
					queue_size_out[pkt->dir] -= pkt->size;
					count[i] += pkt->size;
					last_out[i] = now; 
					free(pkt);
				}
			}
		}
	} while (count[0] > old_count[0] || count[1] > old_count[1]);
	/*
	if (count[0] > 0)
		fprintf(stderr,">>------------> OUT process queue: %d bytes transferred\n", count[0]);
	if (count[1] > 0)
		fprintf(stderr,"<------------<< OUT process queue: %d bytes transferred\n", count[1]);
	*/
	return count[0] + count[1];
}

static int process_queue_in(void)
{
	struct wf_packet *p;
	int i, count = 0;
	for (i = 0; i < 2; i++) {
		if(is_time_to_dequeue(i)) {
			p = wf_queue_in[i];
			wf_queue_in[i] = p->next;
			queue_size_in[p->dir] -= p->size;
			pkt_enqueue_out(p);
			count++;
		}
	}
	/*
	if (count > 0)
		fprintf(stderr,"process queue: %d packets transferred\n", count);
	*/
	return count;
} 

static struct wf_packet 
*pkt_discard(struct wf_packet *q, struct wf_packet *pkt)
{
	if (!q)
		return NULL;
	if (pkt == q) {
		free(pkt);
		return q->next;
	} else 
		q->next = pkt_discard(q->next, pkt);
	return q;
}


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
	unsigned int counter;
	int dir;
	unsigned char *buf;
	int size;
};

struct packpq **pqh;
struct packpq sentinel={0,0,0,NULL,0};
int npq,maxpq;
unsigned long long maxwhen;
unsigned int counter;

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

int writepacket(struct wf_packet *pkt)
{
	if (pkt->flags & WFP_LOSS) {
		//fprintf(stderr, "PACKET LOSS ********************\n");
		return 0;
	}
	/* NOISE */
	if (max_wirevalue(markov_current,NOISE,pkt->dir) > 0) {
		double noiseval=compute_wirevalue(NOISE,pkt->dir);
		int nobit=0;
		while ((drand48()*8*MEGA) < (pkt->size-2)*8*noiseval)
			nobit++;
		if (nobit>0) {
			unsigned char noisedpacket[BUFSIZE];
			memcpy(noisedpacket,pkt->payload,pkt->size);
			while(nobit>0) {
				int flippedbit=(drand48()*pkt->size*8);
				noisedpacket[(flippedbit >> 3) + 2] ^= 1<<(flippedbit & 0x7);
				nobit--;
			}
			return outpacket(pkt->dir,noisedpacket,pkt->size);
		} else
			return outpacket(pkt->dir,pkt->payload,pkt->size);
	} else
		return outpacket(pkt->dir,pkt->payload,pkt->size);
}

unsigned long time_in_queue(struct wf_packet *pkt)
{
	unsigned long bytes_in_queue = 0;
	double bw_val;	
	unsigned long timetogo = 0;
	if (!pkt)
		return 0U;

	bw_val = max_wirevalue(markov_current,BAND,pkt->dir);

	if (!bw_val) {
		return 0U;
	}
	while(pkt) {
		bytes_in_queue += pkt->size;
		pkt = pkt->next;
	} 
	timetogo = 1000 * (bytes_in_queue / bw_val);
/*
	fprintf(stderr,"Time that will be spent in out queue: %lu ms (queue size: %lu B, speed: %.2f B/s)\n", 
			timetogo, bytes_in_queue, bw_val);
*/
	return timetogo;
}

void set_ingres_delay(struct wf_packet *pkt)
{
	pkt->dequeue_time = 0U;
	if (max_wirevalue(markov_current,DELAY,pkt->dir) > 0) {
		double delval=compute_wirevalue(DELAY,pkt->dir);
		unsigned long banddelay = time_in_queue(wf_queue_in[pkt->dir]);
		delval=(delval >= 0)?delval+banddelay:banddelay;
		if (delval > 0) {
			struct timeval tv;
			unsigned long long now = gettimeofdayms();
			pkt->dequeue_time = now + delval - banddelay; 
		}
	}
}

void handle_packet(struct wf_packet *pkt)
{
	int times=1;
	int chanbuf;
	pkt->flags = 0;

	/* MTU */
	/* if the packet is incosistent with the MTU of the line just drop it */
	if (min_wirevalue(markov_current,MTU,pkt->dir) > 0 && pkt->size > min_wirevalue(markov_current,MTU,pkt->dir)) {
		free(pkt);
		return;
	}

	/* LOSS */
	/* Total packet loss */
	if (min_wirevalue(markov_current,LOSS,pkt->dir) >= 100.0) {
		pkt->flags |= WFP_LOSS;
	}
	/* probabilistic loss */
	if (max_wirevalue(markov_current,LOSTBURST,pkt->dir) > 0) {
		/* Gilbert model */
		double losval=compute_wirevalue(LOSS,pkt->dir)/100;
		double burstlen=compute_wirevalue(LOSTBURST,pkt->dir);
		double alpha=losval / (burstlen*(1-losval));
		double beta=1.0 / burstlen;
		switch (loss_status[pkt->dir]) {
			case OK_BURST:
				if (drand48() < alpha) loss_status[pkt->dir]=FAULTY_BURST;
				break;
			case FAULTY_BURST:
				if (drand48() < beta) loss_status[pkt->dir]=OK_BURST;
				break;
		}
		if (loss_status[pkt->dir] != OK_BURST) {
			pkt->flags |= WFP_LOSS;
		}
	} else {
		loss_status[pkt->dir] = OK_BURST;
		if (max_wirevalue(markov_current,LOSS,pkt->dir) > 0) {
			/* standard non bursty model */
			double losval=compute_wirevalue(LOSS,pkt->dir)/100;
			if (drand48() < losval) {
				pkt->flags |= WFP_LOSS;
			}
		}
	}

	/* DUP */
	/* times is the number of dup packets */
	if (max_wirevalue(markov_current,DDUP,pkt->dir) > 0) {
		double dupval=compute_wirevalue(DDUP,pkt->dir)/100;
		while (drand48() < dupval)
			times++;
	}
	while (times > 0) {
		struct wf_packet *pkt_in;
		if (times > 1) { 
			pkt_in = malloc(sizeof(struct wf_packet)); 
			memcpy(pkt_in, pkt, sizeof(struct wf_packet));
		} else
			pkt_in = pkt;
		set_ingres_delay(pkt_in);
		/* RED */
		double red_probability;
		if (red[pkt_in->dir].enabled){
			if (red[pkt_in->dir].min > queue_size_in[pkt_in->dir]) {
				goto RED_PASS;
			} else if (red[pkt_in->dir].max > queue_size_in[pkt_in->dir]) {
				red_probability = red[pkt_in->dir].P * 
					((double)queue_size_in[pkt_in->dir] - (double)red[pkt_in->dir].min) /
					((double)red[pkt_in->dir].max - (double)red[pkt_in->dir].min);
			} else if (queue_size_in[pkt_in->dir] < red[pkt_in->dir].limit) {
				red_probability = red[pkt_in->dir].P;
			} else {
				fprintf(stderr,"RED: Hard limit drop.\n");
				free(pkt_in);
				times--;
				continue;
			}
			if (drand48() < red_probability) {
				fprintf(stderr,"RED: Probability drop. (red probability= %lf, queue size= %lu\n", red_probability, queue_size_in[pkt_in->dir]);
				free(pkt_in);
				times--;
				continue;
			}
			
		} else {
			int drop_tail = max_wirevalue(markov_current, CHANBUFSIZE, pkt_in->dir);
			if (drop_tail > 0 && drop_tail < queue_size_in[pkt_in->dir]) {
				fprintf(stderr, "Drop Tail. Queue size: %lu, limit: %lu\n", queue_size_in[pkt_in->dir], drop_tail);
				free(pkt_in);
				times--;
				continue;
			}
		}
	RED_PASS:
		pkt_enqueue_in(pkt_in);
		times--;
	}
}

static void splitpacket(struct wf_packet *pkt)
{
	static unsigned char fragment[BUFSIZE][2];
	static unsigned char *fragp[2];
	static unsigned int rnx[2],remaining[2];
	unsigned short size = pkt->size;
	memset(red, 0, 2* sizeof(struct red_parms));

	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",progname,rnx[dir],remaining[dir],size);
	if (pkt->size==0) return;
	if (rnx[pkt->dir]>0) {
		register int amount=min(remaining[pkt->dir],pkt->size);
		//fprintf(stderr,"%s: fragment amount %d\n",progname,amount);
		memcpy(fragp[pkt->dir],pkt->payload,amount);
		remaining[pkt->dir]-=amount;
		fragp[pkt->dir]+=amount;
		size-=amount;
		if (remaining[pkt->dir]==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",progname,rnx[dir]);
			pkt->size = rnx[pkt->dir]+2;
			memcpy(pkt->payload, fragment[pkt->dir], rnx[pkt->dir]+2);
			handle_packet(pkt);
			rnx[pkt->dir]=0;
		}
	}
	while (size > 0) {
		rnx[pkt->dir]=(pkt->payload[0]<<8)+pkt->payload[1];
		//fprintf(stderr,"%s: packet %d pkt->size %d %x %x pkt->dir %d\n",progname,rnx[pkt->dir],pkt->size-2,pkt->payload[0],pkt->payload[1],pkt->dir);
		if (rnx[pkt->dir]>1521) {
			printlog(LOG_WARNING,"Packet length error pkt->size %d rnx %d",pkt->size,rnx[pkt->dir]);
			rnx[pkt->dir]=0;
			return;
		}
		if (rnx[pkt->dir]+2 > size) {
			//fprintf(stderr,"%s: begin defrag %d\n",progname,rnx[pkt->dir]);
			fragp[pkt->dir]=fragment[pkt->dir];
			memcpy(fragp[pkt->dir],pkt->payload,pkt->size);
			remaining[pkt->dir]=rnx[pkt->dir]+2-size;
			fragp[pkt->dir]+=size;
			size=0;
		} else {
			pkt->size = rnx[pkt->dir]+2;
			handle_packet(pkt);
			size-=rnx[pkt->dir]+2;
			rnx[pkt->dir]=0;
		}
	}
}

	
					
static int packet_in(int dir)
{
	struct wf_packet *pkt;
	int n;

	pkt = malloc(sizeof(struct wf_packet));
	pkt->next = NULL;
	pkt->dir = dir;
	if(vdeplug[dir]) {
		n=vde_recv(vdeplug[dir],pkt->payload + 2,BUFSIZE-2,0);
		pkt->payload[0]=n>>8;
		pkt->payload[1]=n&0xFF;
		pkt->size = (unsigned short)n + 2;
		handle_packet(pkt);
	} else {
		n = read(pfd[dir].fd,pkt->payload,BUFSIZE);
		if (n <= 0)
			exit (0);
			pkt->size = (unsigned short)n;
		splitpacket(pkt);
	}
	//fprintf(stderr,"Packet In: %d\n",n);
	return n;
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
			if((vdeplug[LR]=vde_open(vdepath[0],"vde_wirefilter",NULL))==NULL){
				fprintf(stderr,"vdeplug %s: %s\n",vdepath[0],strerror(errno));
				return -1;
			}
			pfd[0].fd=vde_datafd(vdeplug[LR]);
			pfd[0].events=POLLIN | POLLHUP;
		}
		if (strcmp(vdepath[1],"-") != 0) {
			if((vdeplug[RL]=vde_open(vdepath[1],"vde_wirefilter",NULL))==NULL){
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
	if (sig == SIGTERM)
		_exit(0);
	else
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

static int setchanbufsize(int fd,char *s)
{
	return read_wirevalue(s,CHANBUFSIZE);
}

static int setred(int fd, char *s)
{
	return parse_red(s, red);
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
	printoutc(fd, "chanbufsize  set channel buffer size (bytes)");
	printoutc(fd, "fifo         set channel fifoness");
	printoutc(fd, "RED  	    set channel random early detection algorithm min,max,probability,limit");
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
				WIREVALUE_FIELDS(node,CHANBUFSIZE,LR),
				WIREVALUE_FIELDS(node,CHANBUFSIZE,RL));
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
			WIREVALUE_FIELDS(node,CHANBUFSIZE,0));
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
	{"chanbufsize",setchanbufsize, 0},
	{"capacity",setchanbufsize, 0},
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
	{"red",setred,0},
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
			"\t--chanbufsize|-c channel_bufsize\n"
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
			"\t--RED min,max,probability,limit\n"
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
		{"chanbufsize",1 , 0, 'c'},
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
		{"blinkid",1,0,LOGIDARG},
		{0,0,0,0}
	};
	progname=basename(argv[0]);
	markov_resize(1);

	setsighandlers();
	atexit(cleanup);

	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hl:n:d:M:D:m:b:s:c:v:L:f:r:",
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
				read_wirevalue(optarg,CHANBUFSIZE);
				break;
			case 'M':
				mgmt=strdup(optarg);
				break;
			case 'N':
				nofifo=1;
				break;
			case 'r':
				parse_red(optarg,red);
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
		n=poll(pfd,npfd,1);
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
		process_queue_out();
		process_queue_in();
	}
}
