/*
 * poll2select - convert poll() calls to select() calls
 * Copyright 2005 Ludovico Gardenghi
 * Licensed under the GPLv2
 */

#ifndef POLL2SELECT_H_
#define POLL2SELECT_H_

/* 
 * poll.h already has these definitions, so we must not repeat them in case
 * someone included that header
 */
#ifndef _SYS_POLL_H_

#define POLLIN	0x0001
#define POLLPRI	0x0002
#define POLLOUT	0x0004

struct pollfd
{
	int fd;
	short events;
	short revents;
};

typedef unsigned int nfds_t;

#endif

int poll2select(struct pollfd *, nfds_t, int);

#endif
