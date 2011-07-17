/*
 * packetq - packet queue management. try to send packets several times before discarding.
 * Copyright 2011 Renzo Davoli
 * Licensed under the GPLv2
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

#ifdef VDE_PQ2

struct packetbuf {
	short len;
	short count;
};

struct vdepq {
	struct packetbuf *vdepq_pb;
	struct vdepq *vdepq_next;
};

int vdepq_add(struct vdepq **tail, void *packet, int len, void **tmp)
{
	struct packetbuf *packetbuftmp = *tmp;
	struct vdepq *newelem;
	if ((newelem = malloc(sizeof(struct vdepq))) == NULL)
		return 0;
	if (packetbuftmp == NULL) {
		if ((*tmp = packetbuftmp = malloc (sizeof(struct packetbuf)+len))==NULL) {
			free(newelem);
			return 0;
		}
		packetbuftmp->len=len;
		packetbuftmp->count=0;
		memcpy(((void *)(packetbuftmp+1)),packet,len);
	}
	newelem->vdepq_pb=packetbuftmp;
	(packetbuftmp->count)++;
	//printf("add %p count %d len %d/%d \n",newelem,packetbuftmp->count,len,packetbuftmp->len);
	if (*tail == NULL) 
		*tail=newelem->vdepq_next=newelem;
	else {
		newelem->vdepq_next=(*tail)->vdepq_next;
		(*tail)->vdepq_next=newelem;
		*tail=newelem;
	}
	return 1;
}

#define PACKETBUFDEL(X) \
	({ if (--((X)->count) == 0) \
	 free(X);\
	 })

void vdepq_del(struct vdepq **tail)
{
	while (*tail != NULL) {
		struct vdepq *first=(*tail)->vdepq_next;
		//printf("kill one %p %p\n",first,*tail);
		PACKETBUFDEL(first->vdepq_pb);
		if (first == (*tail))
			*tail=NULL;
		else
			(*tail)->vdepq_next=first->vdepq_next;
		free(first);
	}
}

int vdepq_try(struct vdepq **tail, void *ep,
		int (*sendfun)(void *ep, void *packet, int len)) {
	int sent=0;
	while (*tail != NULL) {
		struct vdepq *first = (*tail)->vdepq_next;
		//printf("trysend %p len %d\n",first,first->vdepq_pb->len);
		if (sendfun(ep, (void *)(first->vdepq_pb + 1), first->vdepq_pb->len) == -EWOULDBLOCK) 
			break;
		else {
			PACKETBUFDEL(first->vdepq_pb);
			if (first == (*tail))
				*tail=NULL;
			else
				(*tail)->vdepq_next=first->vdepq_next;
			free(first);
			sent++;
		} 
	}
	return sent;
}

#endif
