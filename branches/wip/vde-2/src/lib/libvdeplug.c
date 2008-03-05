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
#include <string.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <libvdeplug.h>

/* IPN - Kernel VDE 
*/
#define USE_IPN

#ifdef USE_IPN
#ifndef AF_IPN
#define AF_IPN    34  /* IPN sockets      */
#define PF_IPN    AF_IPN
#endif
#define AF_IPN_STOLEN    33  /* IPN temporary sockets      */
#define PF_IPN_STOLEN    AF_IPN_STOLEN
#define IPN_ANY 0

#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#endif

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

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

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
	req.type = REQ_NEW_CONTROL;
	if (sockname == NULL || *sockname == '\0')
		sockname=VDESTDSOCK;
	else {
		char *split;
		if(sockname[strlen(sockname)-1] == ']' && (split=rindex(sockname,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (port == 0) 	 
				req.type = REQ_NEW_PORT0;
			if (*sockname==0) sockname=VDESTDSOCK;
		}
	}
#ifdef USE_IPN
	if((conn->fddata = socket(AF_IPN,SOCK_RAW,IPN_ANY)) >= 0) {
		/* IPN service exists */
		sockun.sun_family = AF_IPN;
	}
	if((conn->fddata = socket(AF_IPN_STOLEN,SOCK_RAW,IPN_ANY)) >= 0) {
		/* IPN_STOLEN service exists */
		sockun.sun_family = AF_IPN_STOLEN;
	}
	if (conn->fddata >= 0) {
		if (port != 0 || req.type == REQ_NEW_PORT0)
			setsockopt(conn->fddata,0,IPN_SO_PORT,&port,sizeof(port));
		snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", sockname);
		if (connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun)) == 0) {
			snprintf(req.description,MAXDESCR,"%s user=%s PID=%d %s",
					descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
					pid,getenv("SSH_CLIENT")?getenv("SSH_CLIENT"):"");
			setsockopt(conn->fddata,0,IPN_SO_DESCR,req.description,
					strlen(req.description+1));
			*(conn->inpath.sun_path)=0; /*null string, do not delete "return path"*/
			conn->fdctl=-1;
			return conn;
		}
	}
#endif
	if((conn->fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		int err=errno;
		free(conn);
		errno=err;
		return NULL;
	}
	if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0){
		int err=errno;
		close(conn->fdctl);
		free(conn);
		errno=err;
		return NULL;
	}
	sockun.sun_family = AF_UNIX;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/ctl", sockname);
	if(connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun))){
		if (!strcmp(sockname, VDESTDSOCK)) {
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
	req.type=req.type+(port << 8);
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
	chmod(conn->inpath.sun_path,mode);

	snprintf(req.description,MAXDESCR,"%s user=%s PID=%d %s SOCK=%s",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid,getenv("SSH_CLIENT")?getenv("SSH_CLIENT"):"",req.sock.sun_path);

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

ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1))
		return recv(conn->fddata,buf,len,0);
	else {
		errno=EBADF;
		return -1;
	}
}

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
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
		if (*(conn->inpath.sun_path))
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
