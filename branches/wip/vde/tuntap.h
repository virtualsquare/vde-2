/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __TUNTAP_H__
#define __TUNTAP_H__

extern void send_tap(int fd, void *packet, int len, void *unused);
extern int open_tap(char *dev);
//extern void handle_tap(int fd, int hub);

#endif
