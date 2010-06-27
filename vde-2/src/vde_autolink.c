/*
 * Copyright (C) 2007 - Luca Bigliardi
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
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <signal.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>
#include <libvdemgmt.h>

#define STDRCFILE "/etc/vde2/vde_autolink.rc"

#define MAXCONS 4
#define MGMTMODEARG 129
#define MAXPORTS 256

#define FSTPDBG_PADD "fstp/+"
#define FSTPDBG_PDEL "fstp/-"
#define FSTPDBG_STAT "fstp/status"

#define MAXCMD 128
#define BUFSIZE 1024

#define CHANGEWIRETIME 8
#define SLEEPWIRETIME 30
#define SCHED_TRY 60
#define SCHED_LONGTRY 120
#define SCHED_CHECK 30

#define ST_DISCARD 0
#define ST_ACTIVE  1

char *progname = NULL;
char *mgmt = NULL;
int mgmtmode = 0700;
char *vdeswitch = NULL;
char *switchmgmt = NULL;
int daemonize = 0;
char *rcfile = NULL;
char *pidfile = NULL;
char pidfile_path[PATH_MAX];
struct pollfd pfd[MAXCONS];
int logok=0;
struct vdemgmt* vdemgmt=NULL;
int polltimeout=-1;

static int runscript(int fd,char *path);

static char prompt[]="\nVDEal$ ";
static char header[]="\nVDE autolink V.%s\n(C) L.Bigliardi 2007 - GPLv2\n";

static char *myport = "$myport";
static char *mysock = "$mysock";
static char *myhost = "$remotehost";

struct wire {
	char *type;
	char *cmd;
	struct wire *next;
};

struct alwire {
	char *type;
	char *cmd;
	time_t try;
	time_t oldtry;
	struct alwire *next;
};

 struct autolink {
	char *name;		/* alink name */
	char **hosts;		/* list of remote hosts */
	unsigned int portno;	/* number of switch port */
	int enabled;		/* flag for active */
	int state;		/* link status */
	int connhost;		/* current remote host to connect to */
	struct alwire *connwire; /* current type of wire we try to use */
	int wirepid;		/* pid of wire, -1 if no up */
	struct alwire **wires;	/* list of wire types to use */
	struct autolink *next;
};

static struct wire *av_wires = NULL;
static struct autolink *alinks = NULL;

struct job{
	void (*f)(struct autolink *al);
	time_t time;
	struct autolink *al;
	struct job *n;
};

static struct job *jq = NULL;

/* Generic utils (from vde framework) */
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

void printoutc(int fd, const char *format, ...)
{
	va_list arg;
	char outbuf[MAXCMD+1];

	va_start (arg, format);
	vsnprintf(outbuf,MAXCMD,format,arg);
	strcat(outbuf,"\n");
	write(fd,outbuf,strlen(outbuf));
}

void port_dispose(int p);

static void cleanup(void)
{

	int tmppid;
	struct autolink *curlink = alinks;

	/* kill every link */
	while(curlink){
		port_dispose(curlink->portno);
		if ( (tmppid = curlink->wirepid) != -1) {
			curlink->wirepid = -1;
			kill(tmppid, SIGQUIT);
		}
		curlink = curlink->next;
	}	

	/* close management connections */
	if (mgmt)
		unlink(mgmt);
	if (vdemgmt) {
		vdemgmt_asyncunreg(vdemgmt, FSTPDBG_PADD);
		vdemgmt_asyncunreg(vdemgmt, FSTPDBG_PDEL);
		vdemgmt_asyncunreg(vdemgmt, FSTPDBG_STAT);
		vdemgmt_close(vdemgmt);
	}
}

static void sig_handler(int sig)
{

	/*fprintf(stderr,"Caught signal %d, cleaning up and exiting", sig);*/
	cleanup();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
} 

struct autolink *find_alink_pid(int pid);

static void catch_zombies(int signo)
{
	int status;
	struct autolink *a;

	if( (a=find_alink_pid(wait(&status))) )
		a->wirepid = -1;
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
		if(signal(signals[i].sig, signals[i].ignore ? SIG_IGN :
					sig_handler) < 0)
			printlog(LOG_ERR,"Setting handler for %s: %s",
					signals[i].name, strerror(errno));

	signal(SIGCHLD,catch_zombies);
}

/* Autolink Utils */
struct wire *find_wire(char *type)
{
	struct wire *curwire = av_wires;
	while(curwire){
		if(!strcmp(curwire->type, type))
			return curwire;
		curwire = curwire->next;
	}
	return NULL;
}

struct alwire *find_alwire(char *type, struct autolink *alink)
{
	struct alwire *curalwire = alink->wires[0];
				/* each wires[i] has same types */
	while(curalwire){
		if(!strcmp(curalwire->type, type))
			return curalwire;
		curalwire = curalwire->next;
	}
	return NULL;
}

struct autolink *find_alink_port(int port)
{
	struct autolink *curlink = alinks;
	while(curlink){
		if( curlink->portno == port )
			return curlink;
		curlink = curlink->next;
	}
	return NULL;
}

struct autolink *find_alink_pid(int pid)
{
	struct autolink *curlink = alinks;
	while(curlink){
		if(curlink->wirepid == pid )
			return curlink;
		curlink = curlink->next;
	}
	return NULL;
}

struct autolink *find_alink(char *name)
{
	struct autolink *curlink = alinks;
	while(curlink){
		if(!strcmp(curlink->name, name))
			return curlink;
		curlink = curlink->next;
	}
	return NULL;
}

struct autolink *alink_exists(struct autolink *al)
{
	struct autolink *c = alinks;
	while(c){
		if (c == al)
			return c;
		c = c->next;
	}
	return NULL;
}

int port_reserve(void)
{

	int p; char cmd[strlen("port/create")+5];

	for(p=1; p <= MAXPORTS ; p++){
		sprintf(cmd, "port/create %d", p);
		if(!vdemgmt_sendcmd(vdemgmt, cmd, NULL))
			return p;
	}
	return -1;
}

void port_dispose(int p)
{

	char cmd[strlen("port/remove")+5];
	sprintf(cmd, "port/remove %d", p);
	vdemgmt_sendcmd(vdemgmt, cmd, NULL);

}

char *strrplc(char **s, char *old, char *new)
{
/* create new string (free old) replacing old with new */

	char *limit, *new_s, *old_s;
	int slen, oldlen, newlen, headlen, diff, taillen = 0;

	old_s = *s;

	slen=strlen(old_s); oldlen=strlen(old); newlen=strlen(new);

	limit = strstr(old_s, old);
	if ( limit == NULL )
		return NULL;

	headlen = (int)(limit - old_s);
	diff = newlen - oldlen;
	taillen = slen  - ( headlen + oldlen );

	if( (new_s=(char *)malloc(slen+diff+1)) == NULL)
		return NULL;

	snprintf(new_s, headlen+1, "%s", old_s);
	snprintf(new_s+headlen, newlen+1, "%s", new);
	snprintf(new_s+headlen+newlen, taillen+1, "%s", old_s+headlen+oldlen);

	*s = new_s;
	return new_s;
}

void alink_connect(struct autolink *link)
{

	char *token, *dupcmd, **myargv = NULL;
	int count=0, s[2], sdata=1;

 	if(!link->connwire){
		printlog(LOG_ERR, "alink_connect null connwire");
		exit(1);
	}

	printlog(LOG_NOTICE,"[%s] connecting wire: %s to %s", link->name,
			link->connwire->type, link->hosts[link->connhost]);

	for( dupcmd=strdup(link->connwire->cmd) ; ; dupcmd=NULL){
		token = strtok(dupcmd, " ");
		myargv=realloc(myargv, (count+1)*sizeof(char *));
		if(!myargv) exit(1);
		myargv[count]=token;
		if( !token ) break;
		count++;
	};

	if( socketpair(AF_UNIX, SOCK_STREAM, 0, s) ) exit(1);

	if( (link->wirepid = fork()) == 0 ){
		/* parent goes first, otherwise pid may be lost */
		read(s[1],&sdata,sizeof(int));
		close(s[0]); close(s[1]);
		execvp(myargv[0], myargv);
		/* TODO: handle return from execvp */
	} else {
		write(s[0],&sdata,sizeof(int));
		close(s[0]); close(s[1]);
	}

}

void insert_job(void (*f)(struct autolink *al), struct autolink *al, int gap)
{
	struct job *j=jq, *pj=jq, *nj; time_t now;

	/* remove other jobs for same alink, if any */
	while(j){
		if (al == j->al) {
			if (jq == j) jq=j->n;
			else pj->n=j->n;
			free(j);
		}
		pj = j;
		j = j->n;
	}
	
	/* insert job, ordered by time */
	if ((nj=(struct job *)malloc(sizeof(struct job))) == NULL){
		printlog(LOG_ERR, "%s, cannot alloc new job", __FUNCTION__);
		exit(-1);
	}
	time(&now);
	nj->f=f; nj->time=now+gap; nj->al=al; nj->n=NULL;
	if(jq == NULL){
		jq = nj;
		return;
	}
	j = pj = jq;
	while(j){
		if (j->time > nj->time){
			if (jq == j){
				jq = nj;
				jq->n = j;
			}
			else {
				pj->n = nj;
				nj->n = j;
			}
			return;
		}
		pj = j;
		j = j->n;
	}
	

}

struct job *extract_job()
{
	struct job *j = jq;

	jq=jq->n;
	return j;
}

/* Async functions and handlers */
void alink_try(struct autolink *al);

void alink_check(struct autolink *al)
{
 	if (al->state != ST_ACTIVE){
		printlog(LOG_NOTICE, "[%s] check failed, scheduled new wire connection", al->name);
		kill(al->wirepid, SIGQUIT);
		insert_job(alink_try, al, SCHED_TRY);
	}
	else
		printlog(LOG_NOTICE, "[%s] check passed", al->name);
}

void alink_try(struct autolink *al)
{

	time_t now;

        time(&now);
        
        /* change wire if died too fast,
         * try hosts in round robin */
        if(al->connwire->try > (now - CHANGEWIRETIME)){
                if(!al->connwire->next){
                        al->connhost++;
                        if( al->hosts[al->connhost] == NULL )
                                al->connhost = 0;
                        al->connwire = al->wires[al->connhost];
                } else {
                        al->connwire = al->connwire->next;
                }
                printlog(LOG_NOTICE, "[%s] try next wire: %s (%s)", al->name,
                                al->connwire->type, al->hosts[al->connhost]);
                /* suspend autolink if cycled too fast */
                if(al->connwire->oldtry > (now - SLEEPWIRETIME)){
                        printlog(LOG_NOTICE, "[%s], go suspend", al->name);
			insert_job(alink_try, al, SCHED_LONGTRY);
			return;
                }
        }

        al->connwire->oldtry = al->connwire->try;
        al->connwire->try = now;

        alink_connect(al);

	insert_job(alink_check, al, SCHED_CHECK);
}

void ah_padd(const char *event, int tag, const char *data)
{

	int port; char *s;
	struct autolink *al;

	for( s = (char *)data ; *s != ' ' ; s++);
	s++;
	port=atoi(s);

	al = find_alink_port(port);
	if (!al || !al->enabled)
		return;
	printlog(LOG_NOTICE, "[%s] received %s for port %d", al->name, event, port);

	if (al->state == ST_DISCARD){
		al->state = ST_ACTIVE;
		printlog(LOG_NOTICE, "[%s] state change, discard -> active", al->name);
	}
}

void ah_pdel(const char *event, int tag, const char *data)
{

	int port; char *s;
	struct autolink *al;

	for( s = (char *)data ; *s != ' ' ; s++);
	s++;
	port=atoi(s);

	al = find_alink_port(port);
	if (!al || !al->enabled)
		return;
	printlog(LOG_NOTICE, "[%s] received %s for port %d", al->name, event, port);
	
	if (al->state == ST_ACTIVE){
		al->state = ST_DISCARD;
		printlog(LOG_NOTICE, "[%s] state change, active -> discard", al->name);
		if(al->wirepid != -1)
			kill(al->wirepid, SIGQUIT);
		printlog(LOG_NOTICE, "[%s] scheduled new wire connection");
		insert_job(alink_try, al, SCHED_TRY);
	}
}

void ah_state(const char *event, int tag, const char *data)
{
	int port; char *s;
	struct autolink *al;

	for( s = (char *)data ; *s != ' ' ; s++);
	s++;
	port=atoi(s);

	al = find_alink_port(port);
	if (!al || !al->enabled)
		return;
	printlog(LOG_NOTICE, "[%s] received %s for port %d", al->name, event, port);

	if (strstr(data, "learning+forwarding") && (al->state == ST_DISCARD)){
		al->state = ST_ACTIVE;
		printlog(LOG_NOTICE, "[%s] state change, discard -> active", al->name);
		return;
	}
	if (strstr(data, "discarding") && (al->state == ST_ACTIVE)){
		al->state = ST_DISCARD;
		printlog(LOG_NOTICE, "[%s] state change, active -> discard", al->name);
		return;
	}
}

/* MGMT functions */
int jobsqueue(int fd, char *arg)
{
	time_t now; struct job *j;

	if(!jq){
		printoutc(fd, "jobs queue is empty");
		return 0;
	}
	time(&now);
	j = jq;
	while (j){
		printoutc(fd, "TIME: %d, ACTION: %s, LINK: %s", j->time - now,
				(j->f == alink_try) ? "try  " : "check", j->al->name);
		j = j->n;
	}
	printoutc(fd, "");
	return 0;
}

int alinklinkonoff(int fd, char *arg)
{

	char *endname, *name;
	int namelen, vallen, value;
	struct autolink *curlink;

	/* check if we have name and type */
        endname = strstr(arg, " ");
        namelen = (int)(endname - arg);
	if( namelen <= 0 ) return EINVAL;

        vallen = (int)(arg+strlen(arg) - (endname+1));
	if( vallen <= 0 ) return EINVAL;
	
	if( sscanf(endname+1, "%i", &value) != 1)
		return EINVAL;
	
	/* pick autolink and wire */
	if( (name = (char *)malloc(namelen+1) ) == NULL ) exit(1);
        snprintf(name, namelen+1, "%s", arg);

	curlink = find_alink(name);
	free(name);
	if(!curlink) return ENXIO;
	
	if(value){
		if(!curlink->wires) return ENXIO;
		if(curlink->enabled) return 0;
		curlink->enabled = 1;
		curlink->state = ST_DISCARD;
		curlink->connwire=curlink->wires[0];
		alink_try(curlink);
	}
	else {
		if(!curlink->enabled) return 0;
		curlink->enabled = 0;
		kill(curlink->wirepid, SIGQUIT);
		curlink->connwire = NULL;
	}
	return 0;
}

int alinkdeltypelink(int fd, char *arg)
{
	
	char *endname, *name, *type;
	int namelen, typelen, i;
	struct autolink *curlink;
	struct alwire *curalwire, *prevalwire;

	/* check if we have name and type */
        endname = strstr(arg, " ");
        namelen = (int)(endname - arg);
	if( namelen <= 0 ) return EINVAL;

        typelen = strlen(arg) - namelen -1;
	if( typelen <= 0 ) return EINVAL;
	
	/* pick autolink */
	if( (name = (char *)malloc(namelen+1) ) == NULL ) exit(1);
        snprintf(name, namelen+1, "%s", arg);

	curlink = find_alink(name);
	free(name);
	if(!curlink) return ENXIO;
	if(curlink->enabled) return EINVAL; /* avoid RC */

	if(!curlink->wires[0]) return EINVAL; /* no wires! */

	/* delete alwire */
	if( (type = (char *)malloc(typelen+1) ) == NULL ) exit(1);
        snprintf(type, typelen+1, "%s", endname+1);
	
	for( i = 0 ; curlink->hosts[i] != NULL ; i++){
		curalwire = prevalwire = curlink->wires[i];

		while(curalwire){
			if(!strcmp(curalwire->type, type)){
				if(curalwire == curlink->wires[i]){
					curlink->wires[i] = curalwire->next;
				}
				else {
					prevalwire->next = curalwire->next;
				}
				free(curalwire->type);
				free(curalwire->cmd);
				free(curalwire);
				free(type);
				return 0;
			}
			prevalwire = curalwire;
			curalwire = curalwire->next;
		}
	}

	free(type);
	return EINVAL;
}

int alinkaddtypelink(int fd, char *arg)
{

	char *endname, *name, *type, portbuf[42];
	int namelen, typelen, i;
	struct autolink *curlink;
	struct wire *wire;
	struct alwire *alwire;

	/* check if we have name and type */
        endname = strstr(arg, " ");
        namelen = (int)(endname - arg);
	if( namelen <= 0 ) return EINVAL;

        typelen = strlen(arg) - namelen -1;
	if( typelen <= 0 ) return EINVAL;
	
	/* pick autolink and wire */
	if( (name = (char *)malloc(namelen+1) ) == NULL ) exit(1);
        snprintf(name, namelen+1, "%s", arg);

	curlink = find_alink(name);
	free(name);
	if(!curlink) return ENXIO;
	if(curlink->enabled) return EINVAL; /* avoid RC */

	if( (type = (char *)malloc(typelen+1) ) == NULL ) exit(1);
        snprintf(type, typelen+1, "%s", endname+1);
	
	wire = find_wire(type);
	free(type);
	if(!wire) return ENXIO;

	/* only one wire type for each autolink */
	alwire = find_alwire(wire->type, curlink);
	if(alwire) return EINVAL;

	/* alloc alwires */
	for( i = 0 ; curlink->hosts[i] != NULL ; i++ ){
		if(!curlink->wires[i]){
			if( (curlink->wires[i] = (struct alwire *)
					malloc(sizeof(struct alwire))) == NULL )
				exit(1);
			alwire = curlink->wires[i];
		}
		else {
			alwire = curlink->wires[i];
			while(alwire->next)
				alwire = alwire->next;
			if( (alwire->next=(struct alwire *)
					malloc(sizeof(struct alwire))) == NULL )
				exit(1);
			alwire = alwire->next;
		}

		/* set port, sock and remotehost in alwire command */
		if( (alwire->cmd = (char *)malloc(strlen(wire->cmd)+1)) == NULL)
			exit(1);

		strcpy(alwire->cmd, wire->cmd);
		sprintf(portbuf, "%u", curlink->portno);
		strrplc(&(alwire->cmd), myport, portbuf);
		strrplc(&(alwire->cmd), mysock, vdeswitch);
		strrplc(&(alwire->cmd), myhost, curlink->hosts[i]);

		/* fill rest of alwire struct */
		if( (alwire->type = (char *)
					malloc(strlen(wire->type)+1)) == NULL)
			exit(1);

		strcpy(alwire->type, wire->type);
		alwire->try = 0;
		alwire->oldtry = 0;
		alwire->next = NULL;
	}

	return 0;
}

int alinkdellink(int fd, char *arg)
{
	
	struct autolink *curlink, *prevlink;
	struct alwire *curalwire, *prevalwire;
	int i;

	if(!alinks) return EINVAL;

	prevlink = curlink = alinks;
	while(curlink){
		if(!strcmp(curlink->name, arg)){
			if(curlink->enabled) return EINVAL; /* avoid RC */
			if(curlink == alinks){
				alinks = curlink->next;
			}
			else {
				prevlink->next = curlink->next;
			}
			port_dispose(curlink->portno);
			free(curlink->name);
			/* remove hosts and alwires */
			for ( i = 0 ; curlink->hosts[i] != NULL ; i++){
				free(curlink->hosts[i]);
				curalwire = curlink->wires[i];
				while(curalwire){
					prevalwire = curalwire;
					curalwire = curalwire->next;
					free(prevalwire);
				}
			}
			free(curlink->hosts);
			free(curlink->wires);
			free(curlink);
			return 0;
		}
		prevlink = curlink;
		curlink = curlink->next;
	}
	return EINVAL;
}

int alinkaddlink(int fd, char *arg)
{

	char *name, *endname = NULL, *tmphosts, *token;
	int namelen, hostlen, i, j;
	struct autolink *curlink;

	/* check if we have name and remotehost */
        endname = strstr(arg, " ");
        namelen = (int)(endname - arg);
	if( namelen <= 0 ) return EINVAL;

        hostlen = strlen(arg) - namelen -1;
	if( hostlen <= 0 ) return EINVAL;
	
	/* alloc and set name */
	if( (name = (char *)malloc(namelen+1) ) == NULL ) exit(1);
        snprintf(name, namelen+1, "%s", arg);
	
	/* check for duplicate */
	if( find_alink(name) ){
		free(name); return EINVAL;
	}

	/* alloc autolink */
	if(alinks == NULL){
		alinks = (struct autolink *)malloc(sizeof(struct autolink));
		if(alinks == NULL) exit(1);
		curlink = alinks;
	} else {
		curlink = alinks;
		while(curlink->next)
			curlink = curlink->next;
		curlink->next = (struct autolink *)
					malloc(sizeof(struct autolink));
		if(curlink->next == NULL) exit(1);
		curlink = curlink->next;
	}
	curlink->name = name;

	/* reserve a port on switch */
	if( (curlink->portno = port_reserve()) < 0 ){
		free(curlink->name);
		free(curlink);
		if(alinks == curlink) alinks = NULL;
		return ENXIO;
	}

	/* alloc and set remote host array (null terminated) */
	i=0;
	curlink->hosts=NULL;
	for( tmphosts=strdup(endname+1) ; ; tmphosts=NULL){
		token = strtok(tmphosts, " ");
		curlink->hosts=realloc(curlink->hosts, (i+1)*sizeof(char *));
		if(!curlink->hosts) exit(1);
		curlink->hosts[i]=token;
		if( !token ) break;
		i++;
	};
	/* alloc wires array */
	if( (curlink->wires = malloc(i*sizeof(char *))) == NULL ) exit(1);
	for( j = 0 ; j < i ; j++)
		curlink->wires[j] = NULL;

	curlink->enabled = 0;
	curlink->state = 0;
	curlink->connhost = 0;
	curlink->connwire = NULL;
	curlink->next = NULL;

	return 0;
 }

int alinkrunninglinks(int fd, char *arg)
{
	struct autolink *curlink;
	time_t now;

	if(!alinks) return 0;
	time(&now);
	curlink = alinks;
	while (curlink){
		if( curlink->enabled && (curlink->wirepid != -1) &&
					( curlink->state == ST_ACTIVE )	&&
					(curlink->connwire->try < 
					now - CHANGEWIRETIME) ) {
					/* show only stable connections */
			printoutc(fd, "NAME = %s , RHOST = %s , WIRE = %s ,"
					" PID: %d", curlink->name,
					curlink->hosts[curlink->connhost],
					curlink->connwire->type,
					curlink->wirepid);
			printoutc(fd, "");
		}
		curlink = curlink->next;
	}
	return 0;
}

int alinkshowlinks(int fd, char *arg)
{
	struct autolink *curlink;
	struct alwire *curalwire = NULL;
	int i ;

	if(!alinks){
		printoutc(fd, "no autolink defined");
		return 0;
	}
	curlink = alinks;
	while (curlink){
		printoutc(fd, "NAME = %s (PORT: %d%s)", curlink->name, 
					curlink->portno,
					(curlink->enabled?" - ACTIVE":""));
		for(i = 0 ; curlink->hosts[i] != NULL ; i++){
			printoutc(fd, "RHOST: %s", curlink->hosts[i]);
			if(curlink->wires[i]){
				printoutc(fd, "WIRES:");
				curalwire = curlink->wires[i];
			}
			while(curalwire){
				printoutc(fd,"%s: %s\n", curalwire->type,
							curalwire->cmd);
				curalwire = curalwire->next;
			}
		}
		printoutc(fd, "");
		curlink = curlink->next;
	}
	return 0;
}

int alinkdelwire(int fd, char* arg)
{
	struct wire *curwire, *prevwire;

	if(!av_wires) return EINVAL;

	prevwire = curwire = av_wires;
	while(curwire){
		if(!strcmp(curwire->type, arg)){
			if(curwire == av_wires){
				av_wires = curwire->next;
			}
			else {
				prevwire->next = curwire->next;
			}
			free(curwire->type);
			free(curwire->cmd);
			free(curwire);
			return 0;
		}
		prevwire = curwire;
		curwire = curwire->next;
	}
	return EINVAL;
}

int alinkaddwire(int fd, char* arg)
{

	struct wire *curwire = NULL;
	char *type = NULL;
        int typelen = 0;
        int cmdlen = 0;

	/* check if we have type and command */
        char *endtype = strstr(arg, " ");
        typelen =  (int)(endtype - arg);
	if( typelen <= 0 ) return EINVAL;
        cmdlen = strlen(arg) - typelen -1;
	if( cmdlen <= 0 ) return EINVAL;
	
	/* alloc and set type */
	if( (type = (char *)malloc(typelen+1) ) == NULL ) exit(1);
        snprintf(type, typelen+1, "%s", arg);

	/* check for duplicate */
	if( find_wire(type) ){
		free(type); return EINVAL;
	}
	/* alloc wire */
	if(av_wires == NULL){
		av_wires = (struct wire *)malloc(sizeof(struct wire));
		if(av_wires == NULL) exit(1);
		curwire = av_wires;
	} else {
		curwire = av_wires;
		while(curwire->next)
			curwire = curwire->next;
		curwire->next = (struct wire *)malloc(sizeof(struct wire));
		if(curwire->next == NULL) exit(1);
		curwire = curwire->next;
	}

	curwire->next = NULL;
	curwire->type = type;
	
	/* alloc and set command */
	if( (curwire->cmd = (char *)malloc(cmdlen+1) ) == NULL )
		exit(1);
	snprintf(curwire->cmd, cmdlen+1, "%s", endtype+1);

	/* check variables */
	if( !strstr(curwire->cmd, myport) || !strstr(curwire->cmd, mysock) ||
			!strstr(curwire->cmd, myhost) ){
		free(curwire->type); free(curwire->cmd);
		free(curwire);
		if(av_wires == curwire) av_wires = NULL;
		return EINVAL;
	}

	return 0;
}

int alinkshowwires(int fd, char *arg)
{
	struct wire *curwire;
	if(!av_wires){
		printoutc(fd, "no wire defined");
		return 0;
	}
	curwire = av_wires;
	while (curwire){
		printoutc(fd, "TYPE = %s\nCMD = %s\n", curwire->type,
					curwire->cmd);
		curwire = curwire->next;
	}
	return 0;
}

int alinkshutdown(int fd, char *arg)
{
	printlog(LOG_WARNING,"Shutdown from mgmt command");
	exit(0);
}

int alinkhelp(int fd, char *arg)
{

	printoutc(fd, "help:         print a summary of mgmt commands");
	printoutc(fd, "shutdown:     terminate");
	printoutc(fd, "runscript:    load a config file [args: PATH]");
	printoutc(fd, "showwires:    list inserted wires");
	printoutc(fd, "addwire:      add a type of wire, with variables [args: TYPE CMD]");
	printoutc(fd, "delwire:      delete a type of wire [args: TYPE]");
	printoutc(fd, "showlinks:    list inserted autolinks");
	printoutc(fd, "runninglinks: print running links");
	printoutc(fd, "addlink:      add an autolink [args: NAME REMOTEHOSTS]");
	printoutc(fd, "dellink:      delete an autolink [args: NAME]");
	printoutc(fd, "addtypelink:  add a type of wire to named link [args: NAME TYPE]");
	printoutc(fd, "deltypelink:  delete a type of wire from named link [args: NAME TYPE]");
	printoutc(fd, "linkonoff:    activate/deactivate autolink [args: NAME 1/0]");
	printoutc(fd, "jobsqueue:    print status of job queue");

	return 0;
}

struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
} cl[]={
	{"help",alinkhelp},
	{"shutdown", alinkshutdown},
	{"showwires", alinkshowwires},
	{"addwire", alinkaddwire},
	{"delwire", alinkdelwire},

	{"showlinks", alinkshowlinks},
	{"runninglinks", alinkrunninglinks},
	{"addlink", alinkaddlink},
	{"dellink", alinkdellink},

	{"addtypelink", alinkaddtypelink},
	{"deltypelink", alinkdeltypelink},
	{"linkonoff", alinklinkonoff},
	{"runscript", runscript},

	{"jobsqueue", jobsqueue},
};

#define NCL sizeof(cl)/sizeof(struct comlist)

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL &&
			strncmp(cl[i].tag,inbuf,strlen(cl[i].tag))!=0; i++)
			;
		if (i<NCL) {
			inbuf += strlen(cl[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			printoutc(fd,"0000 DATA END WITH '.'");
			rv=cl[i].fun(fd,inbuf);
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
	n = read(fd, buf, MAXCMD);
	if (n<0) {
		printlog(LOG_ERR,"read from mgmt %s", strerror(errno));
		return 0;
	}
	else if (n==0)
		return -1;
	else {
		buf[n]=0;
		if (n>0 && buf[n-1] == '\n')
			buf[n-1] = 0;
		rv=handle_cmd(fd,buf);
		if (rv>=0)
			write(fd,prompt,strlen(prompt));
		return rv;
	}
}

static int newmgmtconn(int fd,struct pollfd *pfd,int nfds)
{
	int new;
	unsigned int len;
	char buf[MAXCMD];
	struct sockaddr addr;
	new = accept(fd, &addr, &len);
	if(new < 0){
		printlog(LOG_ERR,"mgmt accept %s",strerror(errno));
		return nfds;
	}
	if (nfds < MAXCONS) {

		if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
			printlog(LOG_WARNING, "mgmt fcntl - setting "
					"O_NONBLOCK %s",strerror(errno));
			close(new);
			return nfds;
		}

		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		pfd[nfds].revents=0;

		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		return ++nfds;
	} else {
		printlog(LOG_ERR,"too many mgmt connections");
		close (new);
		return nfds;
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
		fprintf(stderr,"%s: mgmt setsockopt: %s",progname,
					strerror(errno));
		exit(1);
	}
	if(fcntl(mgmtconnfd, F_SETFL, O_NONBLOCK) < 0){
		fprintf(stderr,"%s: Setting O_NONBLOCK on mgmt fd: %s",
					progname,strerror(errno));
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

static int runscript(int fd,char *path)
{
	FILE *f=fopen(path,"r");
	char buf[MAXCMD];
	if (f==NULL)
		return ENOENT;
	else {
		while (fgets(buf,MAXCMD,f) != NULL) {
			if (strlen(buf) > 1 && buf[strlen(buf)-1]=='\n')
						buf[strlen(buf)-1]= '\0';
			if (fd >= 0) printoutc(fd,"vde_autolink[%s]: %s",
						path,buf);
			handle_cmd(fd, buf);
		}
		return 0;
	}
}

static void loadrcfile(void)
{
	if (rcfile != NULL)
		runscript(-1,rcfile);
	else {
		char path[PATH_MAX];
		snprintf(path,PATH_MAX,"%s/.vde2/vde_autolink.rc",getenv("HOME"));
		if (access(path,R_OK) == 0)
			runscript(-1,path);
		else {
			if (access(STDRCFILE,R_OK) == 0)
				runscript(-1,STDRCFILE);
		}
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
		printlog(LOG_ERR, "Error in pidfile creation: %s",
					strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s",
					strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

static void usage(void)
{
	printf(
			"  -h, --help                 Display this help\n"
			"  -f, --rcfile               Configuration file (overrides %s and ~/.vde_autolinkrc)\n"
			"  -d, --daemon               Daemonize vde_autolink once run\n"
			"  -p, --pidfile PIDFILE      Write pid of daemon to PIDFILE\n"
			"  -M, --mgmt SOCK            Path of the management UNIX socket\n"
			"      --mgmtmode MODE        Management UNIX socket access mode (octal)\n"
			"  -s, --sock             [*] Attach to this vde_switch socket\n"
			"  -S, --switchmgmt       [*] Attach to this vde_switch management socket\n"
			"  [*] == Required option!\n"
			,STDRCFILE);
}

int main(int argc,char **argv)
{

	int n, npfd=0, option_index;
	int mgmtfd, mgmtindex=-1, vdemgindex=-1, consoleindex=-1;
	struct job *j; time_t now;

	static struct option long_options[] = {
		{"help",	0, 0, 'h'},
		{"rcfile",	1, 0, 'f'},
		{"daemon",	0, 0, 'd'},
		{"pidfile",	1, 0, 'p'},
		{"mgmt",	1, 0, 'M'},
		{"mgmtmode",	1, 0, MGMTMODEARG},
		{"sock",	1, 0, 's'},
		{"switchmgmt",	1, 0, 'S'},
	};
	progname=basename(argv[0]);

	setsighandlers();
	atexit(cleanup);

	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hf:dp:M:s:S:",
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
				daemonize=1;
				break;
			case 'p':
				pidfile=strdup(optarg);
				break;
			case 'M':
				mgmt=strdup(optarg);
				break;
			case MGMTMODEARG:
				sscanf(optarg,"%o",&mgmtmode);
				break;
			case 's':
				vdeswitch=strdup(optarg);
				break;
			case 'S':
				switchmgmt=strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}

	if (optind < argc)
		usage();

	if( !vdeswitch || !switchmgmt )
		usage();

	if (daemonize){
		openlog(basename(progname), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"VDE_AUTOLINK started");
	}

	if(isatty(0) && !daemonize){
		consoleindex=npfd;
		pfd[consoleindex].fd=0;
		pfd[consoleindex].events=POLLIN | POLLHUP;
		pfd[consoleindex].revents=0;
		npfd++;
	}

	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 1)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}
	if(pidfile) save_pidfile();

	if( (vdemgmt=vdemgmt_open(switchmgmt)) == NULL ){
		printlog(LOG_ERR, "cannot open %s\n", switchmgmt);
		return -1;
	}
	vdemgindex=npfd;
	pfd[vdemgindex].fd=vdemgmt_getfd(vdemgmt);
	pfd[vdemgindex].events=POLLIN | POLLHUP;
	pfd[vdemgindex].revents=0;
	npfd++;

	if( vdemgmt_asyncreg(vdemgmt, FSTPDBG_PADD, ah_padd)
		|| vdemgmt_asyncreg(vdemgmt, FSTPDBG_PDEL, ah_pdel)
		|| vdemgmt_asyncreg(vdemgmt, FSTPDBG_STAT, ah_state) ){
		printlog(LOG_ERR, "cannot register async handler on switch");
		return -1;
	}

	if(mgmt){
		mgmtfd=openmgmt(mgmt);
		mgmtindex=npfd;
		pfd[mgmtindex].fd=mgmtfd;
		pfd[mgmtindex].events=POLLIN | POLLHUP;
		pfd[mgmtindex].revents=0;
		npfd++;
	}

	loadrcfile();

	while(1){

		n=poll(pfd,npfd,polltimeout);

		/* Handle async output from switch */
		if(pfd[vdemgindex].revents & POLLHUP){
			printlog(LOG_ERR, "switch closed connection, exiting");
			exit(1);
		}
		if( pfd[vdemgindex].revents & POLLIN )
			vdemgmt_asyncrecv(vdemgmt);

		/* Handle console connections and commands */
		if(consoleindex >= 0 &&
				( pfd[consoleindex].revents & POLLHUP ||
				  (pfd[consoleindex].revents & POLLIN &&
				  mgmtcommand(pfd[consoleindex].fd)<0) ) )
			exit(0);

		if (mgmt && (pfd[mgmtindex].revents != 0))
			npfd=newmgmtconn(pfd[mgmtindex].fd,pfd,npfd);

		if (mgmt && (npfd > mgmtindex+1)) {
			register int i;
			for (i=mgmtindex+1;i<npfd;i++) {
				if( (pfd[i].revents & POLLHUP) ||
						((pfd[i].revents & POLLIN) &&
						(mgmtcommand(pfd[i].fd) < 0)) )
					npfd=delmgmtconn(i,pfd,npfd);
			}
		}

		/* Run scheduled jobs and compute new timeout for poll */
		time(&now);
		while ( jq && (now > jq->time) ){
			j=extract_job();
			if (alink_exists(j->al) && j->al->enabled)
				j->f(j->al);
			free(j);
		}
		polltimeout = jq ? jq->time - now : -1 ;

		 
	}
}

