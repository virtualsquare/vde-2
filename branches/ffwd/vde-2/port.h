/* Copyright 2005 Renzo Davoli
 * Copyright 2002 Jeff Dike
 * Licensed under the GPLv2
 */

#ifndef __PORT_H__
#define __PORT_H__

#include <sys/socket.h>
#include <switch.h>
#include <bitarray.h>

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

struct mod_support {
	char *modname;
	int (*sender)(int fd, int fd_ctl, void *packet, int len, void *data, int port);
	int (*newport)(int fd_ctl,int portno);
	void (*delep)(int fd, void* data, void *descr);
	void (*delport)(int fd,int portno);
};

extern int setup_ep(int portno, int fd_ctl,
		void *data,
		struct mod_support *modfun);

extern void setup_description(int portno, int fd_ctl, char *descr);

extern int close_ep(int portno, int fd_ctl);

extern void handle_in_packet(int port, struct packet *packet, int len);

extern bitarray validvlan;
int portflag(int op, int f);
#define P_SETFLAG 1
#define P_ADDFLAG 2
#define P_CLRFLAG 3

#define HUB_TAG 0x1

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
