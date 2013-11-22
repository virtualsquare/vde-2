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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "libvdeplug_mod.h"
#include "canonicalize.h"

#define USE_IPN

static char *vde_ptpf_check(char *given_sockname);
static VDECONN *vde_ptpf_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static char *vde_ptpm_check(char *given_sockname);
static VDECONN *vde_ptpm_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_ptp_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_ptp_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_ptp_datafd(VDECONN *conn);
static int vde_ptp_ctlfd(VDECONN *conn);
static int vde_ptp_close(VDECONN *conn);

struct vdeplug_module vdeplug_ptpf={
	.flags=ONLY_BY_CHECK,
	.vde_check=vde_ptpf_check,
	.vde_open_real=vde_ptpf_open,
	.vde_recv=vde_ptp_recv,
	.vde_send=vde_ptp_send,
	.vde_datafd=vde_ptp_datafd,
	.vde_ctlfd=vde_ptp_ctlfd,
	.vde_close=vde_ptp_close};

struct vdeplug_module vdeplug_ptpm={
	.vde_check=vde_ptpm_check,
	.vde_open_real=vde_ptpm_open,
	.vde_recv=vde_ptp_recv,
	.vde_send=vde_ptp_send,
	.vde_datafd=vde_ptp_datafd,
	.vde_ctlfd=vde_ptp_ctlfd,
	.vde_close=vde_ptp_close};

struct vde_ptp_conn {
	struct vdeplug_module *module;
	int fddata;
	char *inpath;
	struct sockaddr *outsock;
	size_t outlen;
};

static char *vde_ptpf_check(char *given_sockname)
{
	static char tag[]="PTPF:";
	static char atag[]="PTPF{";
	static char tag2[]="PTP:";
	static char atag2[]="PTP{";
	int len;
	len=strlen(given_sockname);
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0 &&
			given_sockname[len-1] == '}') {
		given_sockname[strlen(atag)-1]=':';
		given_sockname[len-1] = 0;
		return given_sockname+strlen(atag);
	}
	if (strncmp(given_sockname,tag2,strlen(tag2)) == 0)
		return given_sockname+strlen(tag2);
	if (strncmp(given_sockname,atag2,strlen(atag2)) == 0 &&
			given_sockname[len-1] == '}') {
		given_sockname[strlen(atag2)-1]=':';
		given_sockname[len-1] = 0;
		return given_sockname+strlen(atag2);
	}
	if (len > 2 && given_sockname[len-1] == ']' && 
			given_sockname[len-2] == '[') {
		given_sockname[len-2] = 0;
		return given_sockname;
	}
	return NULL;
}

static char *vde_ptpm_check(char *given_sockname)
{
	static char tag[]="PTPM:";
	static char atag[]="PTPM{";
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

#define UNUSED(X) ({(void *)(X);})

static VDECONN *vde_ptpf_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	int port=0;
	char *group=NULL;
	mode_t mode=0700;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un sockout;
	struct stat sockstat;
	int res;
	struct vde_ptp_conn *newconn;

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

	UNUSED(port);

	memset(&sockun, 0, sizeof(sockun));
	if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		goto abort;
	sockun.sun_family = AF_UNIX;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path)-1, "%s", given_sockname);
	/* the socket already exists */
	if(stat(sockun.sun_path,&sockstat) == 0) {
		if (S_ISSOCK(sockstat.st_mode)) {
			/* the socket is already in use */
			res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			if (res >= 0) {
				errno = EADDRINUSE;
				goto abort;
			}
			if (errno == ECONNREFUSED)
				unlink(sockun.sun_path);
		}
	}
	res = bind(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	if (res < 0)
		goto abort;
	memset(&sockout, 0, sizeof(sockun));
	sockout.sun_family = AF_UNIX;
	snprintf(sockout.sun_path, sizeof(sockun.sun_path), "%s+", given_sockname);
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(sockun.sun_path,-1,gid);
	}
	chmod(sockun.sun_path,mode);

	if ((newconn=calloc(1,sizeof(struct vde_ptp_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_ptpf;
	newconn->fddata=fddata;
	newconn->inpath=strdup(sockun.sun_path);
	newconn->outlen = sizeof(struct sockaddr_un);
	newconn->outsock=malloc(newconn->outlen);
	memcpy(newconn->outsock,&sockout,sizeof(struct sockaddr_un));

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static VDECONN *vde_ptpm_open(char *given_sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	int port=0;
	char *group=NULL;
	mode_t mode=0700;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un sockout;
	struct stat sockstat;
	int res;
	struct vde_ptp_conn *newconn;

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

	UNUSED(port);

	memset(&sockun, 0, sizeof(sockun));
	memset(&sockout, 0, sizeof(sockun));
	sockun.sun_family = AF_UNIX;
	sockout.sun_family = AF_UNIX;
	if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		goto abort;
	snprintf(sockout.sun_path, sizeof(sockout.sun_path)-1, "%s", given_sockname);
	res = connect(fddata, (struct sockaddr *) &sockout, sizeof(sockout));
	if (res < 0)
		goto abort;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path)-1, "%s+", given_sockname);
	/* the socket already exists */
	if(stat(sockun.sun_path,&sockstat) == 0) {
		if (S_ISSOCK(sockstat.st_mode)) {
			/* the socket is already in use */
			res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			if (res >= 0) {
				errno = EADDRINUSE;
				goto abort;
			}
			if (errno == ECONNREFUSED)
				unlink(sockun.sun_path);
		}
	}
	res = bind(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	if (res < 0)
		goto abort;
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(sockun.sun_path,-1,gid);
	}
	chmod(sockun.sun_path,mode);

	if ((newconn=calloc(1,sizeof(struct vde_ptp_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_ptpm;
	newconn->fddata=fddata;
	newconn->inpath=strdup(sockun.sun_path);
	newconn->outlen = sizeof(struct sockaddr_un);
	newconn->outsock=malloc(newconn->outlen);
	memcpy(newconn->outsock,&sockout,sizeof(struct sockaddr_un));

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_ptp_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
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

static ssize_t vde_ptp_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
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

static int vde_ptp_datafd(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	return vde_conn->fddata;
}

static int vde_ptp_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_ptp_close(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	close(vde_conn->fddata);
	if (vde_conn->inpath != NULL) {
		unlink(vde_conn->inpath);
		free(vde_conn->inpath);
	}
	if (vde_conn->outsock != NULL)
		free(vde_conn->outsock);
	free(vde_conn);

	return 0;
}
