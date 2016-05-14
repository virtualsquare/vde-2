/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013 Renzo Davoli, University of Bologna
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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include "libvdeplug_mod.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

static char *vde_tap_check(char *given_sockname);
static VDECONN *vde_tap_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_tap_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_tap_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_tap_datafd(VDECONN *conn);
static int vde_tap_ctlfd(VDECONN *conn);
static int vde_tap_close(VDECONN *conn);

struct vdeplug_module vdeplug_tap={
	.flags=ONLY_BY_CHECK,
	.vde_check=vde_tap_check,
	.vde_open_real=vde_tap_open,
	.vde_recv=vde_tap_recv,
	.vde_send=vde_tap_send,
	.vde_datafd=vde_tap_datafd,
	.vde_ctlfd=vde_tap_ctlfd,
	.vde_close=vde_tap_close};

struct vde_tap_conn {
	struct vdeplug_module *module;
	int fddata;
};

static char *vde_tap_check(char *given_sockname)
{
	static char tag[]="TAP:";
	static char atag[]="TAP/";
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0) {
		given_sockname[strlen(atag)-1]=':';
		return given_sockname+strlen(atag);
	}
	return NULL;
}

static VDECONN *vde_tap_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct ifreq ifr;
	int fddata=-1;
	struct vde_tap_conn *newconn;

	if((fddata = open("/dev/net/tun", O_RDWR)) < 0)
		goto abort;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, given_sockname, sizeof(ifr.ifr_name) - 1);
	//printf("tap dev=\"%s\", ifr.ifr_name=\"%s\"\n", ifr.ifr_name, given_sockname);
	if(ioctl(fddata, TUNSETIFF, (void *) &ifr) < 0)
		goto abort;

	if ((newconn=calloc(1,sizeof(struct vde_tap_conn)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_tap;
	newconn->fddata=fddata;

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_tap_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_tap_conn *vde_conn = (struct vde_tap_conn *)conn;
	return read(vde_conn->fddata,buf,len);
}

static ssize_t vde_tap_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_tap_conn *vde_conn = (struct vde_tap_conn *)conn;
	return write(vde_conn->fddata,buf,len);
}

static int vde_tap_datafd(VDECONN *conn)
{
	struct vde_tap_conn *vde_conn = (struct vde_tap_conn *)conn;
	return vde_conn->fddata;
}

static int vde_tap_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_tap_close(VDECONN *conn)
{
	struct vde_tap_conn *vde_conn = (struct vde_tap_conn *)conn;
	close(vde_conn->fddata);
	free(vde_conn);
	return 0;
}
