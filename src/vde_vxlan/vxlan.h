/*
 * VDE - vde_vxlan Network emulator for vde
 * Copyright (C) 2014 Renzo Davoli, Alessandro Ghedini VirtualSquare
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <arpa/inet.h>
#include <netinet/in.h>

/* from vde_switch/port.h */

#define ETH_ALEN 6
#define ETH_HEADER_SIZE 14

struct eth_hdr {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

struct eth_pkt {
	struct eth_hdr header;
	unsigned char data[1504]; /*including trailer, IF ANY */
};

struct vxlan_pkt {
	unsigned char flags;
	unsigned char priv1[3];
	unsigned char id[3];
	unsigned char priv2[1];
	struct eth_pkt pkt;
};

extern int       vxlan_id;
extern in_addr_t vxlan_addr;
extern int       vxlan_port;
extern int       vxlan_mttl;

void vxlan_open(struct pollfd *pfd);
void vxlan_close();

void vxlan_process();
void vxlan_send(in_addr_t addr, struct vxlan_pkt *p, size_t len);
