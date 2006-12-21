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

#include "libvdeplug.h"
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef VDESTDSOCK
#define VDESTDSOCK  "/var/run/vde.ctl"
#define VDETMPSOCK  "/tmp/vde.ctl"
#endif

struct vdeconn {
	int fdctl;
	int fddata;
	struct sockaddr_un inpath;
};

#define SWITCH_MAGIC 0xfeedface
#define MAXDESCR 128

enum request_type { REQ_NEW_CONTROL };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
};

VDECONN *vde_open_real(char *sockname,char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vdeconn *conn;
	struct passwd *callerpwd;
	struct request_v3 req;
	int pid = getpid();
	static struct sockaddr_un sockun;
	static struct sockaddr_un dataout;
	int port=0;
	char *group=NULL;
	int sockno=0;
	int res;
	mode_t mode=0700;

	if (open_args != NULL) {
		if (interface_version == 1) {
			port=open_args->port;
			group=open_args->group;
			mode=open_args->mode;
		}
		else {
			errno=EINVAL;
			return NULL;
		} 
	}

	if ((conn=calloc(1,sizeof(struct vdeconn)))==NULL)
	{
		errno=ENOMEM;
		return NULL;
	}
	//get the login name
	callerpwd=getpwuid(getuid());
	if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
		int err=errno;
		free(conn);
		errno=err;
		return NULL;
	}
	if((conn->fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		int err=errno;
		close(conn->fddata);
		free(conn);
		errno=err;
		return NULL;
	}
	if (sockname == NULL)
		sockname=VDESTDSOCK;
	else {
		char *split;
		if(sockname[strlen(sockname)-1] == ']' && (split=rindex(sockname,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (*sockname==0) sockname=VDESTDSOCK;
		}
	}
	sockun.sun_family = AF_UNIX;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/ctl", sockname);
	if(connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun))){
		if (sockname == VDESTDSOCK) {
			sockname=VDETMPSOCK;
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/ctl", sockname);
			if(connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun))){
				snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", sockname);
				if(connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun))){
					close(conn->fddata);
					close(conn->fdctl);
					free(conn);
					errno=ENOENT;
					return NULL;
				}
			}
		}
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=REQ_NEW_CONTROL+(port << 8);
	req.sock.sun_family=AF_UNIX;

	/* First choice, store the return socket from the switch in the control dir*/
	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	do 
	{
		sprintf(req.sock.sun_path, "%s.%05d-%05d", sockname, pid, sockno++);
		res=bind(conn->fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
	}
	while (res < 0 && errno == EADDRINUSE);
	if (res < 0){
		/* if it is not possible -> /tmp */
		memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
		do 
		{
			sprintf(req.sock.sun_path, "/tmp/vde.%05d-%05d", pid, sockno++);
			res=bind(conn->fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
		}
		while (res < 0 && errno == EADDRINUSE);

		if (res < 0){
			int err=errno;
			close(conn->fddata);
			close(conn->fdctl);
			free(conn);
			errno=err;
			return NULL;
		}
	}

	memcpy(&(conn->inpath),&req.sock,sizeof(req.sock));
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(conn->inpath.sun_path,-1,gid);
	}
	if (mode>=0)
		chmod(conn->inpath.sun_path,mode);

	snprintf(req.description,MAXDESCR,"%s user=%s PID=%d %s SOCK=%s",
			descr,callerpwd->pw_name,pid,getenv("SSH_CLIENT")?getenv("SSH_CLIENT"):"",req.sock.sun_path);

	if (send(conn->fdctl,&req,sizeof(req)-MAXDESCR+strlen(req.description),0) < 0) {
		int err=errno;
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		errno=err;
		return NULL;
	}

	if (recv(conn->fdctl,&(dataout),sizeof(struct sockaddr_un),0)<0) {
		int err=errno;
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		errno=err;
		return NULL;
	}

	if (connect(conn->fddata,(struct sockaddr *)&(dataout),sizeof(struct sockaddr_un))<0) {
		int err=errno;
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		errno=err;
		return NULL;
	}
	chmod(dataout.sun_path,mode);

	return conn;
}

ssize_t vde_recv(VDECONN *conn,char *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1))
		return recv(conn->fddata,buf,len,0);
	else {
		errno=EBADF;
		return -1;
	}
}

ssize_t vde_send(VDECONN *conn,const char *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) 
		return send(conn->fddata,buf,len,0);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_datafd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->fddata;
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_ctlfd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->fdctl;
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_close(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1)) {
		unlink(conn->inpath.sun_path);
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		return 0;
	} else {
		errno=EBADF;
		return -1;
	}
}
