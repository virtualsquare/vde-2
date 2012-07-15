/* Copyright 2005 Renzo Davoli
 * Copyright 2002 Jeff Dike
 * Licensed under the GPLv2
 *
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef __PORT_H__
#define __PORT_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include "switch.h"
#include "bitarray.h"

#define ETH_HEADER_SIZE 14
/* a full ethernet 802.3 frame */
struct ethheader {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

struct packet {
	struct ethheader header;
  unsigned char data[1504]; /*including trailer, IF ANY */
};

struct bipacket {
	char filler[4];
	struct packet p;
};

#define pgetprio(X) ((X)[0] >> 5)
#define pgetcfi(X)  (((X)[0] >> 4) & 1)
#define pgetvlan(X) (((X)[0] & 0xf) << 8 + (X)[1])
#define psetprio(X,V) ((X)[0]= ((X)[0] & 0x1f) | (V)<<5)
#define psetcfi(X,V)  ((X)[0]= ((X)[0] & 0xef) | (V&1)<<4)
#define psetvlan(X,V) ({(X)[1]=(V)&0xff;(X)[0]=((X)[0] & 0xf0) | ((V)>>8) & 0xf; (V); })

struct endpoint;

struct mod_support {
	char *modname;
	int (*sender)(int fd_ctl, int fd_data, void *packet, int len, int port);
	void (*delep)(int fd_ctl, int fd_data, void *descr);
};

extern struct endpoint *setup_ep(int portno, int fd_ctl,
		int fd_data,
		uid_t user,
		struct mod_support *modfun);

extern int ep_get_port(struct endpoint *ep);

extern void setup_description(struct endpoint *ep, char *descr);

extern int close_ep(struct endpoint *ep);

#ifdef VDE_PQ2
extern void handle_out_packet(struct endpoint *ep);
#endif

extern void handle_in_packet(struct endpoint *ep, struct packet *packet, int len);

extern bitarray validvlan;
extern void fd2ip (int fd, struct sockaddr_in *sock);
extern void get_port_ip_info (int port, struct sockaddr_in *sock);
extern void setup_destination(struct endpoint *ep, int fd_data);

int portflag(int op, int f);
#define P_GETFLAG 0
#define P_SETFLAG 1
#define P_ADDFLAG 2
#define P_CLRFLAG 3

#define HUB_TAG 0x1
#define TRUNK_TAG 0x2

void port_init(int numports);


#define DISCARDING 0
#define LEARNING   1
/* forwarding implies learning */
#define FORWARDING 3

#ifdef FSTP
void port_send_packet(int portno, void *packet, int len);
void portset_send_packet(bitarray portset, void *packet, int len);
void port_set_status(int portno, int vlan, int status);
int port_get_status(int portno, int vlan);
int port_getcost(int port);
#endif

#endif
