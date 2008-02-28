/*
 * poll2select - convert poll() calls to select() calls
 * Copyright 2005 Ludovico Gardenghi
 * Licensed under the GPLv2
 */

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

static int prepare_select(struct pollfd *ufds, nfds_t nfds, int timeout,
		struct timeval **pstimeout, int *maxfdp1, fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	register int i;
	struct pollfd *currfd;
	struct timeval *stimeout = *pstimeout;
		
	/*
	 * Conversion of information about file descriptors
	 */
	
	*maxfdp1 = 0;

	if ((nfds > 0) && (ufds == NULL))
	{
		errno = EFAULT;
		return 0;
	}

	for (i = 0; i < nfds; i++)
	{
		currfd = &ufds[i];

		if (currfd->fd < 0)
		{
			errno = EBADF;
			return 0;
		}

		if (currfd->events & POLLIN)
			FD_SET(currfd->fd, rfds);
		if (currfd->events & POLLOUT)
			FD_SET(currfd->fd, wfds);
		if (currfd->events & POLLPRI)
			FD_SET(currfd->fd, efds);

		*maxfdp1 = MAX(*maxfdp1, currfd->fd);
	}
		
	(*maxfdp1)++;

	/*
	 * Conversion of information about timeout
	 */

	if (timeout == 0)
	{
		if (stimeout == NULL)
		{
			errno = EINVAL;
			return 0;
		}
		stimeout->tv_sec = 0;
		stimeout->tv_usec = 0;
	}
	else if (timeout > 0)
	{
		if (stimeout == NULL)
		{
			errno = EINVAL;
			return 0;
		}
		stimeout->tv_sec = timeout / 1000;
		stimeout->tv_usec = (timeout % 1000) * 1000;
	}
	else // if (timeout < 0)
		*pstimeout = NULL;

	return 1;
}

static int convert_results(struct pollfd *ufds, int nfds,
		fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	register int i;
	struct pollfd *currfd;
	int retval = 0;

	for (i = 0; i < nfds; i++)
	{
		currfd = &ufds[i];

		currfd->revents = 0;

		if (FD_ISSET(currfd->fd, rfds))
			currfd->revents |= POLLIN;
		if (FD_ISSET(currfd->fd, wfds))
			currfd->revents |= POLLOUT;
		if (FD_ISSET(currfd->fd, efds))
			currfd->revents |= POLLPRI;

		if (currfd->revents != 0)
			retval++;
	}

	return retval;
}

int vde_poll(struct pollfd *ufds, nfds_t nfds, int timeout)
{
	fd_set rfds, wfds, efds;
	struct timeval stimeout;
	struct timeval *pstimeout = &stimeout;
	int maxfdp1;
	int pretval, sretval, tretval;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	tretval = prepare_select(ufds, nfds, timeout, &pstimeout, &maxfdp1, &rfds, &wfds, &efds);
	if (!tretval)
		return -1;

	sretval = select(maxfdp1, &rfds, &wfds, &efds, pstimeout);
	if (sretval <= 0)
		return sretval;
	
	pretval = convert_results(ufds, nfds, &rfds, &wfds, &efds);

	return pretval;
}

