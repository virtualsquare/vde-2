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
#include <poll.h>

#include <libvdeplug.h>

#include "vxlan_hash.h"
#include "log.h"
#include "vxlan.h"
#include "plug.h"

static VDECONN *conn;

void plug_open(char *path, int port, struct pollfd *pfd) {
	struct vde_open_args open_args = {
		.port  = port,
		.group = NULL,
		.mode  = 0700
	};

	conn = vde_open(path, "vde_vxlan:", &open_args);

	if (conn == NULL) {
		printlog(LOG_ERR,"vde_open(\"%s\"): %s", path ? path
				: "DEF_SWITCH", strerror(errno));
		exit(1);
	}

	pfd[0].fd = vde_ctlfd(conn);
	pfd[0].events = POLLIN | POLLHUP;

	pfd[1].fd = vde_datafd(conn);
	pfd[1].events = POLLIN | POLLHUP;
}

void plug_process() {
	struct vxlan_pkt pkt;

	in_addr_t dest_addr;

	int nx = vde_recv(conn, (void *) &pkt.pkt, sizeof(pkt), 0);

	if (nx < 0)
		printlog(LOG_ERR, "vde_recv(): %s",
				strerror(errno));

	printlog(LOG_DEBUG, "VDE packet");

	find_in_hash_update(pkt.pkt.header.src, vxlan_id, 1, NULL);

	if ((pkt.pkt.header.dest[0] == 0xff) &&
	    (pkt.pkt.header.dest[1] == 0xff) &&
	    (pkt.pkt.header.dest[2] == 0xff) &&
	    (pkt.pkt.header.dest[3] == 0xff) &&
	    (pkt.pkt.header.dest[4] == 0xff) &&
	    (pkt.pkt.header.dest[5] == 0xff)) {
		printlog(LOG_DEBUG, "Broadcast send");

		vxlan_send(0, &pkt, nx);
		return;
	}

	find_in_hash(pkt.pkt.header.dest, vxlan_id, &dest_addr);

	if (dest_addr == 0) {
		printlog(LOG_DEBUG, "Multicast send");
		vxlan_send(0, &pkt, nx);
		return;
	}

	if (dest_addr > 1) {
		struct in_addr a;
		a.s_addr = dest_addr;
		printlog(LOG_DEBUG, "Send to %s", inet_ntoa(a));

		vxlan_send(dest_addr, &pkt, nx);
	}
}

void plug_send(struct eth_pkt *pkt, size_t len) {
	int nx = vde_send(conn, pkt, len, 0);

	if (nx < 0)
		printlog(LOG_ERR, "vde_send(): %s", strerror(errno));
}

void plug_close() {
	vde_close(conn);
}
