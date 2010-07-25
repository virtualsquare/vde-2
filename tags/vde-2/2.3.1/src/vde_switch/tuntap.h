/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifdef HAVE_TUNTAP

#ifndef __TUNTAP_H__
#define __TUNTAP_H__

extern int send_tap(int fd, int ctl_fd, void *packet, int len, void *unused, int port);
extern int recv_tap(int fd, void *packet, int maxlen, int port);
extern int open_tap(char *dev);

#endif

#endif
