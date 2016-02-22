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

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <poll.h>

#include <netinet/in.h>
#include <sys/un.h>

#include "vxlan_hash.h"
#include "log.h"
#include "vxlan.h"
#include "plug.h"

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))
#define hton24(p, v) { \
	p[0] = (((v) >> 16) & 0xFF); \
	p[1] = (((v) >> 8) & 0xFF); \
	p[2] = ((v) & 0xFF); \
}

int       vxlan_id   = -1;
in_addr_t vxlan_addr = INADDR_NONE;
int       vxlan_port = 4879;
int       vxlan_mttl = 1;

static int    vxlan_fd = -1;

void vxlan_open(struct pollfd *pfd) {
	int sock;
	int loop = 0;

	struct ip_mreq mc_req;
	struct sockaddr_in addr_in;

	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		printlog(LOG_ERR, "socket(): %s", strerror(errno));
		exit(1);
	}

	if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
					&vxlan_mttl, sizeof(vxlan_mttl))) < 0) {
		printlog(LOG_ERR, "setsockopt(TTL): %s", strerror(errno));
		exit(1);
	}

	if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
					&loop, sizeof(loop))) < 0) {
		printlog(LOG_ERR, "setsockopt(LOOP): %s", strerror(errno));
		exit(1);
	}

	memset(&addr_in, 0, sizeof(addr_in));
	addr_in.sin_family      = AF_INET;
	addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
	addr_in.sin_port        = htons(vxlan_port);

	if ((bind(sock, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0) {
		printlog(LOG_ERR, "bind(): %s", strerror(errno));
		exit(1);
	}

	/* send an IGMP join request */
	mc_req.imr_multiaddr.s_addr = vxlan_addr;
	mc_req.imr_interface.s_addr = htonl(INADDR_ANY);

	if ((setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
					&mc_req, sizeof(mc_req))) < 0) {
		printlog(LOG_ERR, "setsockopt(ADD): %s", strerror(errno));
		exit(1);
	}

	vxlan_fd = sock;

	pfd[2].fd = sock;
	pfd[2].events = POLLIN | POLLHUP;
}

void vxlan_process() {
	struct vxlan_pkt pkt;

	struct sockaddr_in src_addr;
	socklen_t src_addr_len=sizeof(src_addr);

	in_addr_t dest_addr;

	size_t len = recvfrom(vxlan_fd, &pkt, sizeof(pkt), 0,
			(struct sockaddr *) &src_addr, &src_addr_len);

	if (len < 0)
		printlog(LOG_ERR, "recvfrom(): %s", strerror(errno));

	printlog(LOG_DEBUG, "VXLAN packet from %s",inet_ntoa(src_addr.sin_addr));

	if (pkt.flags != (1<<3)) {
		printlog(LOG_ERR, "Invalid flags");
		return;
	}

	if (ntoh24(pkt.id) != vxlan_id) {
		printlog(LOG_DEBUG, "Invalid VNI");
		return;
	}

	find_in_hash_update(pkt.pkt.header.src, vxlan_id,
			src_addr.sin_addr.s_addr, NULL);

	if ((pkt.pkt.header.dest[0] == 0xff) &&
	    (pkt.pkt.header.dest[1] == 0xff) &&
	    (pkt.pkt.header.dest[2] == 0xff) &&
	    (pkt.pkt.header.dest[3] == 0xff) &&
	    (pkt.pkt.header.dest[4] == 0xff) &&
	    (pkt.pkt.header.dest[5] == 0xff)) {
		printlog(LOG_DEBUG, "Broadcast send");

		plug_send(&pkt.pkt, len-offsetof(struct vxlan_pkt,pkt));
		return;
	}

	find_in_hash(pkt.pkt.header.dest, vxlan_id, &dest_addr);

	switch (dest_addr) {
		case 0:
			printlog(LOG_DEBUG, "Not found");
		case 1:
			plug_send(&pkt.pkt,len-offsetof(struct vxlan_pkt,pkt));
			printlog(LOG_DEBUG, "Send to VDE");
			break;

		default:
			printlog(LOG_DEBUG, "Drop");
			break;
	}
}

void vxlan_send(in_addr_t addr_s, struct vxlan_pkt *pkt, size_t len) {
	struct sockaddr_in addr;

	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = addr_s ? addr_s : vxlan_addr;
	addr.sin_port        = htons(vxlan_port);

	memset(pkt, 0, offsetof(struct vxlan_pkt,pkt));
	pkt->flags = (1 << 3);

	hton24(pkt->id, vxlan_id);

	if (sendto(vxlan_fd, pkt, len+offsetof(struct vxlan_pkt,pkt), 0,
		   (struct sockaddr *) &addr, sizeof(addr)) < 0)
		printlog(LOG_ERR, "sendto(): %s", strerror(errno));
}

void vxlan_close() {
	if (vxlan_fd == -1)
		return;

	struct ip_mreq mc_req;

	mc_req.imr_multiaddr.s_addr = vxlan_addr;
	mc_req.imr_interface.s_addr = htonl(INADDR_ANY);

	if ((setsockopt(vxlan_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
			(void *) &mc_req, sizeof(mc_req))) < 0) {
		printlog(LOG_ERR, "setsockopt(DROP): %s", strerror(errno));
		exit(1);
	}

	close(vxlan_fd);
}
