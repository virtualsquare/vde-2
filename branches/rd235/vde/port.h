/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __PORT_H__
#define __PORT_H__

#include <sys/socket.h>
#include <sys/un.h>

//extern int handle_port(int fd);
extern void close_port(int i, int fd);
extern int setup_sock_port(int i, int fd, struct sockaddr_un *name, int data_fd, int group);
extern int setup_port(int i, int fd, void (*sender)(int fd, void *packet, int len, 
					     void *data), void *data, 
		      int data_len, int portgroup);
extern void handle_tap_data(int i, int fd, int hub);
extern int handle_sock_data(int fd, int hub);
extern int handle_sock_direct_data(int i, int fd, int hub);

#endif
