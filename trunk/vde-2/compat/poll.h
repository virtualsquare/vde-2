#include "config.h"

#ifdef HAVE_POLL
#include <poll.h>
#else
#ifndef __POLL_H__
#define __POLL_H__

typedef unsigned long int nfds_t;

#define POLLIN		0x001
#define POLLPRI		0x002
#define POLLOUT		0x004

struct pollfd
{
	int fd;
	short int events;
	short int revents;
};

int rpl_poll(struct pollfd *ufds, nfds_t nfds, int timeout);

#endif
#endif
