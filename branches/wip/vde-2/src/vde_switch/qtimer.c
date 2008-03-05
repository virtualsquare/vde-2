/*
 * Copyright 2005 Renzo Davoli
 * Licensed under the GPLv2
 */

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include "switch.h"
#include <stdio.h>
#include "consmgmt.h" /* just for printlog def */

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#define QT_ALLOC_STEP 4

struct qt_timer {
	int qt_n; //timer ID
	time_t qt_period; //timer period
	time_t qt_nextcall; //next call time  (in secs)
	unsigned int qt_times; //number of times to be activated <0 = infinity
	void (* qt_call)(); //funct. to call
	void *qt_arg; // opt arg to the funct.
};

struct qt_timer **qth; // head of the active timer array
struct qt_timer *qtf; // free list
int maxqt; //size of active timer array

static time_t gqtime; // global time in secs, secs from the epoch
static int activeqt; // number of active timers
static int countqt; // counter for timer ID

time_t qtime() // returns global time (faster than time())
{
	return gqtime;
}

static sigset_t ss_alarm, ss_old;
void qtime_csenter()
{
	if (sigprocmask(SIG_BLOCK,&ss_alarm,&ss_old) < 0)
		printlog(LOG_WARNING,"error qtime_csenter\n");
}

void qtime_csexit()
{
	if (sigprocmask(SIG_SETMASK,&ss_old,NULL) < 0)
		printlog(LOG_WARNING,"error qtime_csexit\n");
}

unsigned int qtimer_add(time_t period,int times,void (*call)(),void *arg)
{
	register int n;
	if (period>0 && call && times>=0) {
		qtime_csenter();
		if (activeqt >= maxqt) {
			int newmaxqt=maxqt+QT_ALLOC_STEP;
			qth=realloc(qth,newmaxqt*sizeof(struct qt_timer *));
			if (qth == NULL) {
				return -1;
			}
			/* it is not possible to use unitialized elements */
			/*memset(qth+maxqt,0,QT_ALLOC_STEP*sizeof(struct qt_timer *));*/
			maxqt=newmaxqt;
		}
		n=activeqt++;
		if (qtf == NULL) {
			qtf=malloc(sizeof(struct qt_timer));
			if (qth == NULL) {
				return -1;
			}
			/*all the fields but qt_arg get initialized */
			/*memset(qtf,0,sizeof(struct qt_timer));*/
			qtf->qt_arg=NULL;
		}
		qth[n]=qtf;
		qtf=qtf->qt_arg;
		qth[n]->qt_n=countqt++;
		qth[n]->qt_period=period;
		qth[n]->qt_nextcall=gqtime+period;
		qth[n]->qt_call=call;
		qth[n]->qt_arg=arg;
		qth[n]->qt_times=(times==0)?-1:times;
		qtime_csexit();
    return qth[n]->qt_n;
	} else
		return -1;
}

void qtimer_del(unsigned int n)
{
	register int i;
	for (i=0; i<activeqt; i++) {
		if (n==qth[i]->qt_n) {
			qth[i]->qt_times=0;
			break;
		}
	}
}

static void sig_alarm(int sig)
{
	register int i;
	register int j;
	gqtime++;
	//printf("%d\n",gqtime);
	for (i=0,j=0; i<activeqt; i++) {
		if (qth[i]->qt_times == 0)
		{
			//printf("timer %d eliminated\n",qth[i]->qt_n);
			qth[i]->qt_arg=qtf;
			qtf=qth[i];
		}
		else { 
			if (gqtime >= qth[i]->qt_nextcall) {
				//printf("timer %d fires\n",qth[i]->qt_n);
				qth[i]->qt_call(qth[i]->qt_arg);
				qth[i]->qt_nextcall+=qth[i]->qt_period;
				if (qth[i]->qt_times > 0 )
					(qth[i]->qt_times)--;
			}
			//printf("%d -> %d \n",i,j);
			if (i-j) qth[j]=qth[i];
			j++;
		}
	}
	activeqt=j;
}

void qtimer_init()
{
	struct itimerval it;
	struct sigaction sa;

  sa.sa_handler = sig_alarm;
  sa.sa_flags = SA_RESTART;
  if(sigaction(SIGALRM, &sa, NULL) < 0){
	  printlog(LOG_WARNING,"Setting handler for SIGALRM %s", strerror(errno));
	    return;
  }
 
	sigemptyset(&ss_alarm);
	sigaddset(&ss_alarm,SIGALRM);

	it.it_value.tv_sec = 1;
	it.it_value.tv_usec = 0 ;
	it.it_interval.tv_sec = 1;
	it.it_interval.tv_usec = 0 ;
	setitimer(ITIMER_REAL, &it, NULL);
}

/*
 * test stub */
/*
void fun(void *arg)
{
	printf("FUN\n");
}

main()
{
	qtimer_init();
	qtimer_add(7,0,fun,NULL);
	qtimer_add(3,0,fun,NULL);
	qtimer_add(4,2,fun,NULL);
	while(1)
		pause();
}
*/
