#ifndef VDEPOLL_H__
#define VDEPOLL_H__

#include "config.h"

#ifdef HAVE_POLL
#include <poll.h>
#else

typedef unsigned long int nfds_t;

#define POLLIN		0x001
#define POLLPRI		0x002
#define POLLOUT		0x004
#define POLLHUP		0x010


struct pollfd
{
	int fd;
	short int events;
	short int revents;
};

int vde_poll(struct pollfd *ufds, nfds_t nfds, int timeout);

#endif
#endif
