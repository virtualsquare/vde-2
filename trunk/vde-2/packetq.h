/*
 * packetq - packet queue management. try to send packets several times before discarding.
 * Copyright 2005 Renzo Davoli
 * Licensed under the GPLv2
 */

#ifdef VDE_PQ
#ifndef _PACKETQ_H
#define _PACKETQ_H

extern int packetq_timeout;

void packetq_add(int (*sender)(int fd, int fd_ctl, void *packet, int len, void *data, int port),
		int fd, int fd_ctl, void *packet, int len, void *data, int port);

void packetq_try(void);

void packetq_delfd(int fd);

int packetq_count();
#endif
#endif
