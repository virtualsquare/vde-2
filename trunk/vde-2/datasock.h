/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __TUNTAP_H__
#define __TUNTAP_H__

void send_datasock(int fd, int ctl_fd, void *packet, int len, void *unused, int port);
int recv_datasock(int_fd, void *packet, int maxlen, int port);
int open_datasock(char *dev);

#endif
