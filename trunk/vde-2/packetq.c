/*
 * packetq - packet queue management. try to send packets several times before discarding.
 * Copyright 2005 Renzo Davoli
 * Licensed under the GPLv2
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <consmgmt.h>
#include <vde.h>

#ifdef VDE_PQ
#include "packetq.h"

int packetq_timeout= -1;
#define TIMEOUT 5
#define TIMES 10

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
static struct timeval last_try;

void packetq_add(int (*sender)(int fd, int fd_ctl, void *packet, int len, void *data, int port),
		    int fd, int fd_ctl, void *packet, int len, void *data, int port)
{
	struct packetqq *new=malloc(sizeof(struct packetqq));
	void *packetcopy=malloc(len);
	if (new != NULL && packetcopy != NULL && len > 0) {
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
			gettimeofday(&last_try,NULL);
			packetq_timeout=TIMEOUT;
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

static struct packetqq *packetq_scantry(struct packetqq *h,struct packetqq **t,fd_set *fds)
{
	if (h != NULL) {
		int sendrv=!(FD_ISSET(h->fd,fds));
		if(sendrv) h->times--;
		if ((sendrv && (sendrv=h->sender(h->fd,h->fd_ctl,h->packet,h->len,h->data,h->port)) == 0)   /*send OK*/
				|| h->times==0) { /*or max number of attempts reached*/
			struct packetqq *next;
			if (sendrv != 0) {
				if (sendrv < 0) 
					printlog(LOG_WARNING,"packetqueue port %d: %s",h->port,strerror(-sendrv));
				else
					printlog(LOG_WARNING,"packetqueue port %d: partial send (%d bytes lost)",h->port,sendrv);
			}
			next=h->next;
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
	}
}

static struct packetqq *packetq_scandelfd(int fd,struct packetqq *h,struct packetqq **t)
{
	if (h != NULL) {
		h->times--;
		if (fd == h->fd) {
			struct packetqq *next=h->next;
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
		packetq_timeout = -1;
}

#endif
