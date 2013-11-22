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
#include <unistd.h>
#include <string.h>
#include <libvdeplug.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "libvdeplug_mod.h"
#include "canonicalize.h"

#define USE_IPN

static char *vde_kvde_check(char *given_sockname);
static VDECONN *vde_kvde_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_kvde_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_kvde_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_kvde_datafd(VDECONN *conn);
static int vde_kvde_ctlfd(VDECONN *conn);
static int vde_kvde_close(VDECONN *conn);

struct vdeplug_module vdeplug_kvde={
	.vde_check=vde_kvde_check,
	.vde_open_real=vde_kvde_open,
	.vde_recv=vde_kvde_recv,
	.vde_send=vde_kvde_send,
	.vde_datafd=vde_kvde_datafd,
	.vde_ctlfd=vde_kvde_ctlfd,
	.vde_close=vde_kvde_close};

struct vde_kvde_conn {
	struct vdeplug_module *module;
	int fdctl;
	int fddata;
	char *inpath;
};

static char *vde_kvde_check(char *given_sockname)
{
	static char tag[]="KVDE:";
	static char atag[]="KVDE{";
	int len;
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	len=strlen(given_sockname);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0 &&
			given_sockname[len-1] == '}') {
		given_sockname[strlen(atag)-1]=':';
		given_sockname[len-1] = 0;
		return given_sockname+strlen(atag);
	}
	return NULL;
}

/* Fallback names for the control socket, NULL-terminated array of absolute
 * filenames. */
static char *fallback_sockname[] = {
	"/var/run/kvde.ctl/ctl",
	"/tmp/kvde.ctl/ctl",
	"/tmp/kvde.ctl",
	NULL,
};

#ifdef USE_IPN
#if 0
/* AF_IPN has not been officially assigned yet
	    we "steal" unused AF_NETBEUI in the meanwhile
			   this code will be uncommented when AF_IPN is assigned. */
#ifndef AF_IPN
#define AF_IPN    0  /* IPN sockets:       */
#define PF_IPN    AF_IPN
#endif
#endif
#ifndef AF_NETBEUI
#ifdef PF_NETBEUI
#define AF_NETBEUI PF_NETBEUI
#else
#define AF_NETBEUI 13
#endif
#endif
#define AF_IPN_STOLEN    AF_NETBEUI  /* IPN temporary sockets      */
#define PF_IPN_STOLEN    AF_IPN_STOLEN
#define IPN_ANY 0

#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#endif

#define UNUSED(expr) ({(void)(expr);})
static VDECONN *vde_kvde_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
#ifdef USE_IPN
	int port=0;
	char *portgroup=NULL;
	char *group=NULL;
	mode_t mode=0700;
	int fddata=-1;
	struct sockaddr_un sockun;
	char *split;
	int res;
	struct vde_kvde_conn *newconn;
	int port0=0;
	UNUSED(portgroup);
	UNUSED(mode);
	UNUSED(group);

	if (open_args != NULL) {
		if (interface_version == 1) {
			port=open_args->port;
			group=open_args->group;
			mode=open_args->mode;
		} else {
			errno=EINVAL;
			goto abort;
		}
	}

	if(*given_sockname && given_sockname[strlen(given_sockname)-1] == ']'
			&& (split=rindex(given_sockname,'[')) != NULL) {
		*split=0;
		split++;
		if (port == 0) {
			if (isdigit(*split))
				port0=1;
			else {
				portgroup=split;
				split[strlen(split)-1] = 0;
			}
		}
	}

	/* Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path. */

	fddata=socket(AF_IPN_STOLEN,SOCK_RAW,IPN_ANY);
	if (fddata < 0)
		goto abort;

	memset(&sockun, 0, sizeof(sockun));

	/* IPN_STOLEN service exists */
	sockun.sun_family = AF_IPN_STOLEN;
	if (port != 0 || port0)
		setsockopt(fddata,0,IPN_SO_PORT,&port,sizeof(port));

	/* If we're given a sockname, just try it */
	if (given_sockname)
	{
		snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", given_sockname);
		res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	}
	/* Else try all the fallback socknames, one by one */
	else
	{
		int i;
		for (i = 0, res = -1; fallback_sockname[i] && (res != 0); i++)
		{
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", fallback_sockname[i]);
			res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
		}
	}

	/* If one of the connect succeeded, we're done */
	if (res < 0) 
		goto abort;

	if ((newconn=calloc(1,sizeof(struct vde_kvde_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_kvde;
	newconn->fddata=fddata;

	setsockopt(fddata,0,IPN_SO_DESCR,descr, strlen(descr)+1);
	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
#endif
	return NULL;
}

static ssize_t vde_kvde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_kvde_conn *vde_conn = (struct vde_kvde_conn *)conn;
	return recv(vde_conn->fddata,buf,len,0);
}

static ssize_t vde_kvde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_kvde_conn *vde_conn = (struct vde_kvde_conn *)conn;
	return send(vde_conn->fddata,buf,len,0);
}

static int vde_kvde_datafd(VDECONN *conn)
{
	struct vde_kvde_conn *vde_conn = (struct vde_kvde_conn *)conn;
	return vde_conn->fddata;
}

static int vde_kvde_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_kvde_close(VDECONN *conn)
{
	struct vde_kvde_conn *vde_conn = (struct vde_kvde_conn *)conn;
	close(vde_conn->fddata);
	free(vde_conn);

	return 0;
}
