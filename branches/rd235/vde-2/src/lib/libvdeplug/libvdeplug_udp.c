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
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include "libvdeplug_mod.h"
#include "canonicalize.h"

static char *vde_udp_check(char *given_sockname);
static VDECONN *vde_udp_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_udp_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_udp_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_udp_datafd(VDECONN *conn);
static int vde_udp_ctlfd(VDECONN *conn);
static int vde_udp_close(VDECONN *conn);

struct vdeplug_module vdeplug_udp={
	.vde_check=vde_udp_check,
	.vde_open_real=vde_udp_open,
	.vde_recv=vde_udp_recv,
	.vde_send=vde_udp_send,
	.vde_datafd=vde_udp_datafd,
	.vde_ctlfd=vde_udp_ctlfd,
	.vde_close=vde_udp_close};

struct vde_udp_conn {
	struct vdeplug_module *module;
	int fddata;
	struct sockaddr *outsock;
	size_t outlen;
};

static char *vde_udp_check(char *given_sockname)
{
	static char tag[]="UDP:";
	static char atag[]="UDP{";
	int len;
	char *split;
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	len=strlen(given_sockname);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0 &&
			given_sockname[len-1] == '}') {
		given_sockname[strlen(atag)-1]=':';
		given_sockname[len-1] = 0;
		return given_sockname+strlen(atag);
	}
	if((split = strstr(given_sockname,"->")) != NULL && rindex(split,':') != NULL)
		return given_sockname;
	return NULL;
}

static VDECONN *vde_udp_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	int fddata=-1;
	struct addrinfo hints;
	struct addrinfo *result,*rp;
	int s;
	char *dst=strstr(given_sockname,"->");
	char *src=given_sockname;
	char *srcport;
	char *dstport;
	struct vde_udp_conn *newconn;

	if (dst == NULL)
		return NULL;

	memset(&hints,0,sizeof(hints));
	hints.ai_socktype=SOCK_DGRAM;
	*dst=0;
	dst+=2;
	dstport=rindex(dst,':');
	if (dstport==NULL) {
		errno=EINVAL;
		goto abort;
	}
	*dstport=0;
	dstport++;
	srcport=rindex(src,':');
	if (srcport==NULL) {
		srcport=src;
		src=NULL;
	}
	*srcport=0;
	srcport++;
	//fprintf(stderr,"UDP!%s:%s -> %s:%s \n",src,srcport,dst,dstport);
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(src, srcport, &hints, &result);

	if (s != 0) {
		//fprintf(stderr,"%s: %s\n",src,gai_strerror(s));
		errno=ECONNABORTED;
		goto abort;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fddata = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fddata == -1)
			continue;

		if (bind(fddata, rp->ai_addr, rp->ai_addrlen) == 0)
			break;                  /* Success */

		close(fddata);
	}

	if (rp == NULL) {
		errno=ECONNABORTED;
		goto abort;
	}

	freeaddrinfo(result);
	hints.ai_flags = 0;

	s = getaddrinfo(dst, dstport, &hints, &result);

	if (s != 0) {
		//fprintf(stderr,"%s: %s\n",dst,gai_strerror(s));
		errno=ECONNABORTED;
		goto abort;
	}


	freeaddrinfo(result);

	if ((newconn=calloc(1,sizeof(struct vde_udp_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_udp;
	newconn->fddata=fddata;
	newconn->outsock = malloc(result->ai_addrlen);
	newconn->outlen = result->ai_addrlen;
	memcpy(newconn->outsock, result->ai_addr, result->ai_addrlen);

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_udp_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_udp_conn *vde_conn = (struct vde_udp_conn *)conn;
#ifdef CONNECTED_P2P
	ssize_t retval;
	if (__builtin_expect(((retval=recv(vde_conn->fddata,buf,len,0)) > 0), 1))
		return retval;
	else {
		if (retval == 0 && vde_conn->outsock != NULL) {
			static struct sockaddr unspec={AF_UNSPEC};
			connect(vde_conn->fddata,&unspec,sizeof(unspec));
		}
		return retval;
	}
#else
	return recv(vde_conn->fddata,buf,len,0);
#endif
}

static ssize_t vde_udp_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_udp_conn *vde_conn = (struct vde_udp_conn *)conn;
#ifdef CONNECTED_P2P
	ssize_t retval;
	if (__builtin_expect(((retval=send(vde_conn->fddata,buf,len,0)) >= 0),1))
		return retval;
	else {
		if (__builtin_expect(errno == ENOTCONN || errno == EDESTADDRREQ,0)) {
			if (__builtin_expect(vde_conn->outsock != NULL,1)) {
				connect(vde_conn->fddata, vde_conn->outsock,vde_conn->outlen);
				return send(vde_conn->fddata,buf,len,0);
			} else
				return retval;
		} else
			return retval;
	}
#else
	return sendto(vde_conn->fddata,buf,len,0, vde_conn->outsock,vde_conn->outlen);
#endif
}

static int vde_udp_datafd(VDECONN *conn)
{
	struct vde_udp_conn *vde_conn = (struct vde_udp_conn *)conn;
	return vde_conn->fddata;
}

static int vde_udp_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_udp_close(VDECONN *conn)
{
	struct vde_udp_conn *vde_conn = (struct vde_udp_conn *)conn;
	if (vde_conn->outsock != NULL)
		free(vde_conn->outsock);
	close(vde_conn->fddata);
	free(vde_conn);

	return 0;
}
