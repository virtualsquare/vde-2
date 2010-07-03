/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2006 Renzo Davoli, University of Bologna
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#ifndef _VDELIB_H
#define _VDELIB_H
#include <sys/types.h>
#define LIBVDEPLUG_INTERFACE_VERSION 1

struct vdeconn;

typedef struct vdeconn VDECONN;

/* Open a VDE connection.
 * vde_open_options:
 *   port: connect to a specific port of the switch (0=any)
 *   group: change the ownership of the communication port to a specific group
 *        (NULL=no change)
 *   mode: set communication port mode (if 0 standard socket mode applies)
 */
struct vde_open_args {
	int port;
	char *group;
	mode_t mode;
};
	
/* vde_open args:
 *   vde_switch: switch id (path)
 *   descr: description (it will appear in the port description on the switch)
 */
#define vde_open(vde_switch,descr,open_args) \
	vde_open_real((vde_switch),(descr),LIBVDEPLUG_INTERFACE_VERSION,(open_args))
VDECONN *vde_open_real(char *vde_switch,char *descr,int interface_version,
	struct vde_open_args *open_args);

ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags);

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags);

/* for select/poll when this fd receive data, there are packets to recv
 * (call vde_recv) */
int vde_datafd(VDECONN *conn);

/* for select/poll. the ctl socket is silent after the initial handshake.
 * when EOF the switch has closed the connection */
int vde_ctlfd(VDECONN *conn);

int vde_close(VDECONN *conn);

/* vdestream */

struct vdestream;

typedef struct vdestream VDESTREAM;

#define PACKET_LENGTH_ERROR 1

VDESTREAM *vdestream_open(void *opaque, 
		int fdout,
		ssize_t (*frecv)(void *opaque, void *buf, size_t count),
		void (*ferr)(void *opaque, int type, char *format, ...)
		);

ssize_t vdestream_send(VDESTREAM *vdestream, const void *buf, size_t len);

void vdestream_recv(VDESTREAM *vdestream, unsigned char *buf, size_t len);

void vdestream_close(VDESTREAM *vdestream);

#endif
