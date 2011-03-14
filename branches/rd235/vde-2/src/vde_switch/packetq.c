/*
 * packetq - packet queue management. try to send packets several times before discarding.
 * Copyright 2005,...,2011 Renzo Davoli
 * Licensed under the GPLv2
 * 2011 Thanks to Simone Abbakus for the idea of dynamic delay
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "consmgmt.h"

#define TIMES 10
#define MAXQLEN 4192

#ifdef VDE_PQ
#include "packetq.h"
#include <time.h>

#ifdef VDE_PQ_PPOLL

#ifdef CLOCK_MONOTONIC_RAW
#define CLOCK_TYPE CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE CLOCK_MONOTONIC
#endif
struct timespec *packetq_timeout;
static struct timespec packetq_timeout_value;
#ifdef VDE_PQ_DYNAMIC
#define TIMEOUT_MAX 10000000 //Upper bound 10ms
#define TIMEOUT_MIN  1000000 //Lower bound  1ms
#define TIMEOUT_MEAN ((TIMEOUT_MAX + TIMEOUT_MIN) / 2)
#define TIMEOUT_STEP ((TIMEOUT_MAX - TIMEOUT_MIN) / MAXQLEN)
#else
#define TIMEOUT_NS 5000000
#endif
#else

int packetq_timeout= -1;
#define TIMEOUT 5
#endif

static int countq;

struct packetqq {
	int (*sender)(int fd, int fd_ctl, void *packet, int len, void *data, int port);
	int fd; 
	int fd_ctl; 
	void *packet; 
	int len; 
	void *data; 
	int port;
	int times;
	struct packetqq *next;
};

static struct packetqq *pqh=NULL;
static struct packetqq *pqt=NULL;
#ifdef VDE_PQ_PPOLL
static struct timespec last_try;
#else
static struct timeval last_try;
#endif

void packetq_add(int (*sender)(int fd, int fd_ctl, void *packet, int len, void *data, int port),
		int fd, int fd_ctl, void *packet, int len, void *data, int port)
{
	if (countq < MAXQLEN) {
		struct packetqq *new=malloc(sizeof(struct packetqq));
		void *packetcopy=malloc(len);
		if (new != NULL && packetcopy != NULL && len > 0) {
			countq++;
			new->sender=sender;
			new->fd=fd;
			new->fd_ctl=fd_ctl;
			memcpy(packetcopy,packet,len);
			new->packet=packetcopy;
			new->len=len;
			new->data=data;
			new->port=port;
			new->times=TIMES;
			new->next=NULL;
			if (pqh==NULL) {
#ifdef VDE_PQ_PPOLL
				clock_gettime(CLOCK_TYPE,&last_try);
#ifdef VDE_PQ_DYNAMIC
				packetq_timeout_value.tv_nsec=TIMEOUT_MEAN;
#else
				packetq_timeout_value.tv_nsec=TIMEOUT_NS;
#endif
				packetq_timeout=&packetq_timeout_value;
#else
				gettimeofday(&last_try,NULL);
				packetq_timeout=TIMEOUT;
#endif
				pqh=pqt=new;
			} else {
				pqt->next=new;
				pqt=new;
			}
		} else {
			if (new != NULL) free(new);
			if (packetcopy != NULL) free(packetcopy);
		}
	}
}

static struct packetqq *packetq_scantry(struct packetqq *h,struct packetqq **t,fd_set *fds)
{
	if (h != NULL) {
		int sendrv=!(FD_ISSET(h->fd,fds));
		h->times--;
		if ((sendrv && (sendrv=h->sender(h->fd,h->fd_ctl,h->packet,h->len,h->data,h->port)) == 0)   /*send OK*/
				|| h->times<=0) { /*or max number of attempts reached*/
			struct packetqq *next;
			next=h->next;
			countq--;
			free(h->packet);
			free(h);
			return packetq_scantry(next,t,fds);
		} else {
			FD_SET(h->fd,fds);
			h->next=packetq_scantry(h->next,t,fds);
			if (h->next == NULL) *t=h;
			return h;
		}
	} else
		return NULL;
}

void packetq_try(void)
{
	if (pqh != NULL) {
#ifdef VDE_PQ_PPOLL
		struct timespec this_try;
		long remaining_nsecs;
		clock_gettime(CLOCK_TYPE,&this_try);
		/* TIMEOUT should never exceed 2.1 secs! */
		remaining_nsecs = packetq_timeout_value.tv_nsec - ((this_try.tv_sec-last_try.tv_sec) * 1000000000 + (this_try.tv_nsec-last_try.tv_nsec));
		if (remaining_nsecs <= 0) {
			fd_set fds;
			FD_ZERO(&fds);
			pqh=packetq_scantry(pqh,&pqt,&fds); 
			if (pqh != NULL) {
				clock_gettime(CLOCK_TYPE,&last_try);
#ifdef VDE_PQ_DYNAMIC
				packetq_timeout_value.tv_nsec = TIMEOUT_MAX - TIMEOUT_STEP * countq;
#else
				packetq_timeout_value.tv_nsec = TIMEOUT_NS;
#endif
			} else
				packetq_timeout = NULL;
		}
#else
		struct timeval this_try;
		gettimeofday(&this_try,NULL);
		packetq_timeout=TIMEOUT - ((this_try.tv_sec-last_try.tv_sec) * 1000 + 
				(this_try.tv_usec-last_try.tv_usec) / 1000);
		if (packetq_timeout <= 0) {
			fd_set fds;
			FD_ZERO(&fds);
			pqh=packetq_scantry(pqh,&pqt,&fds);	
			if (pqh != NULL) {
				gettimeofday(&last_try,NULL);
				packetq_timeout=TIMEOUT;
			} else
				packetq_timeout = -1;
		}
#endif
	}
}

static struct packetqq *packetq_scandelfd(int fd,struct packetqq *h,struct packetqq **t)
{
	if (h != NULL) {
		if (fd == h->fd) {
			struct packetqq *next=h->next;
			countq--;
			free(h->packet);
			free(h);
			return packetq_scandelfd(fd,next,t);
		} else {
			h->next=packetq_scandelfd(fd,h->next,t);
			if (h->next == NULL) *t=h;
			return h;
		}
	} else
		return NULL;
}

void packetq_delfd(int fd)
{
	pqh=packetq_scandelfd(fd,pqh,&pqt);
	if (pqh == NULL)
#ifdef VDE_PQ_PPOLL
		packetq_timeout = NULL;
#else
		packetq_timeout = -1;
#endif
}

int packetq_count()
{
	return countq;
}
#endif
