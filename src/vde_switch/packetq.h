/*
 * packetq - packet queue management. try to send packets several times before discarding.
 * Copyright 2005 Renzo Davoli
 * Licensed under the GPLv2
 */

#ifdef VDE_PQ2
#ifndef _PACKETQ_H
#define _PACKETQ_H

struct vdepq;
struct endpoint;

int vdepq_add(struct vdepq **tail, void *packet, int len, void *tmp);

void vdepq_del(struct vdepq **tail);

int vdepq_try(struct vdepq **tail, struct endpoint *ep,
		int (*sendfun)(struct endpoint *ep, void *packet, int len));

#endif
#endif
