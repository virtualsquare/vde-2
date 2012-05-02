/*   
 *   VIRTUALSQUARE wiki.virtualsquare.org
 *
 *   vtrill.h: vtrill support
 *   
 *   Copyright 2012 Renzo Davoli VirtualSquare University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, either version 2 
 *   of the License, or (at your option) any later version, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id: umview.c 974 2011-08-08 08:52:20Z rd235 $
 *
 */


#ifndef _VTRILL_H
#define _VTRILL_H
#include "port.h"
#include "stddef.h"
#include "stdint.h"
#include "switch.h"

#ifdef VDE_VTRILL

#define NTREE 5

extern unsigned char mynickname[];
extern int nreachable;

struct vtrillh {
	struct ethheader header;
	unsigned char vlan[2];
	unsigned char trilltag[2];
	unsigned char vtrilldata[2];
	unsigned char egress[2];
	unsigned char igress[2];
	struct {
		struct ethheader header;
		unsigned char data[];
	} payload;
} __attribute__((packed));
#define VTRILLHEADERSIZE offsetof(struct vtrillh, payload)

#define VT_VERSION(X) ((X)[0] >> 6)
#define VT_MULTI(X) ((X)[0] >> 3) & 1
#define VT_OPTIONS(X) (((X)[0] & 0x7)<<2 & ((X)[1]>>6))
#define VT_GETTTL(X) ((X)[1] & 0x3f)
#define VT_SETTTL(X,V) ((X)[1] = ((X)[1] & ~0x3f) | ((V) & 0x3f))
#define INTNICK(X) (((X)[0]<<8) + (X)[1])

#define UNVTRILL2VTRILL(P,LEN) \
	({ LEN += VTRILLHEADERSIZE; \
	 (struct packet *)(((char *)(P)) - VTRILLHEADERSIZE); })

#define VTRILL2UNVTRILL(P,LEN) \
	({ LEN -= VTRILLHEADERSIZE; \
	 (struct packet *)(((char *)(P)) + VTRILLHEADERSIZE); })

#define SETUP_VTRILLH(P,VLAN,MULTI,TTL) \
	({ memcpy((P)->header.src, switchmac, ETH_ALEN); \
	 (P)->header.proto[0] = 0x81; (P)->header.proto[1] = 0x00; \
	 (P)->vlan[0]=(VLAN)>>8; (P)->vlan[1]=(VLAN); \
	 (P)->trilltag[0]=0x22; (P)->trilltag[1]=0xf3; \
	 (P)->vtrilldata[0]=(MULTI)?0x8:0x0; \
	 (P)->vtrilldata[1]=TTL & 0x3f; \
	 (P)->igress[0]=mynickname[0]; (P)->igress[1]=mynickname[1]; })

#define VTRILLH_SETEGRESS(P,INTEGRESS) \
	({ (P)->egress[0]=(INTEGRESS)>>8; (P)->egress[1]=(INTEGRESS)&0xff; })

#define ISISIS(X)  (((unsigned char *)(X))[16]==0x22 && ((unsigned char *)(X))[17]==0xf4)
#define ISVISIS(X) (((unsigned char *)(X))[21]==0x2)
#define ISQISIS(X) (((unsigned char *)(X))[21]==0x6)
#define ISTRILL(X) (((unsigned char *)(X))[16]==0x22 && ((unsigned char *)(X))[17]==0xf3)

struct nextvtrill {
	uint16_t index;
	int port;
	unsigned char *mac;
};

struct nextmultivtrill {
	int ndst;
	int ttl;
	struct nextvtrill *dst;
};

int unicast_vtrill_port(int integress, unsigned char *mac, int *ttl);

struct nextmultivtrill *broadcast_vtrill(unsigned char *egress_tree);

void vtrill_in_isis(int port, struct packet *p, int len);

void vtrillsetnumports (int val);

void *vtrill_newport(int port);
void vtrill_delport(int port, void *vtrilldata);
void vtrill_enable(bitarray ports,int vlan);
void vtrill_disable(void);

void vtrill_init(int initnumports);
#endif
#endif
