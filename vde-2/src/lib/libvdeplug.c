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
#include <limits.h>
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

#ifdef USE_IPN
#ifndef AF_IPN
#define AF_IPN    34  /* IPN sockets      */
#define PF_IPN    AF_IPN
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

/* Fallback names for the control socket, NULL-terminated array of absolute
 * filenames. */
char *fallback_sockname[] = {
	"/var/run/vde.ctl/ctl",
	"/tmp/vde.ctl/ctl",
	"/tmp/vde.ctl",
	NULL,
};

/* Fallback directories for the data socket, NULL-terminated array of absolute
 * directory names, with no trailing /. */
const char *fallback_dirname[] = {
	"/var/run",
	"/var/tmp",
	"/tmp",
	NULL,
};

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
} __attribute__((packed));

VDECONN *vde_open_real(char *given_sockname, char *descr,int interface_version,
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
	char real_sockname[PATH_MAX];
	char *sockname = real_sockname;

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
	if (given_sockname == NULL || *given_sockname == '\0')
		given_sockname = NULL;
	else {
		char *split;
		if(given_sockname[strlen(given_sockname)-1] == ']' && (split=rindex(given_sockname,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (port == 0)
				req.type = REQ_NEW_PORT0;
			if (*given_sockname==0)
				given_sockname = NULL;
		}
	}

	/* Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path. */
	if (given_sockname && vde_realpath(given_sockname, real_sockname) == NULL)
	{
		free(conn);
		return NULL;
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
		/* If we're given a sockname, just try it */
		if (given_sockname)
		{
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", sockname);
			res = connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
		}
		/* Else try all the fallback socknames, one by one */
		else
		{
			int i;
			for (i = 0, res = -1; fallback_sockname[i] && (res != 0); i++)
			{
				snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", fallback_sockname[i]);
				res = connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			}
		}

		/* If one of the connect succeeded, we're done */
		if (res == 0)
		{
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
		free(conn);
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

	/* If we're given a sockname, just try it (remember: sockname is the
	 * canonicalized version of given_sockname - though we don't strictly need
	 * the canonicalized versiono here). sockname should be the name of a
	 * *directory* which contains the control socket, named ctl. Older
	 * versions of VDE used a socket instead of a directory (so an additional
	 * attempt with %s instead of %s/ctl could be made), but they should
	 * really not be used anymore. */
	if (given_sockname)
	{
		snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/ctl", sockname);
		res = connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun));
	}
	/* Else try all the fallback socknames, one by one */
	else
	{
		int i;
		for (i = 0, res = -1; fallback_sockname[i] && (res != 0); i++)
		{
			/* Remember sockname for the data socket directory */
			sockname = fallback_sockname[i];
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", sockname);
			res = connect(conn->fdctl, (struct sockaddr *) &sockun, sizeof(sockun));
		}
	}

	if (res != 0)
	{
		int err = errno;
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		errno = err;
		return NULL;
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=req.type+(port << 8);
	req.sock.sun_family=AF_UNIX;

	/* First choice, store the return socket from the switch in the control
	 * dir. We assume that given_sockname (hence sockname) is a directory.
	 * Should be a safe assumption unless someone modifies the previous group
	 * of connect() attempts (see the comments above for more information). */
	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	do
	{
		/* Here sockname is the last successful one in the previous step. */
		sprintf(req.sock.sun_path, "%s/.%05d-%05d", sockname, pid, sockno++);
		res=bind(conn->fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
	}
	while (res < 0 && errno == EADDRINUSE);

	/* It didn't work. So we cycle on the fallback directories until we find a
	 * suitable one (or the list ends). */
	if (res < 0)
	{
		int i;
		for (i = 0, res = -1; fallback_dirname[i] && (res != 0); i++)
		{
			memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
			do 
			{
				sprintf(req.sock.sun_path, "%s/vde.%05d-%05d", fallback_dirname[i], pid, sockno++);
				res = bind(conn->fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
			}
			while (res < 0 && errno == EADDRINUSE);
		}
	}

	/* Nothing worked, so cleanup and return with an error. */
	if (res < 0){
		int err = errno;
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		errno = err;
		return NULL;
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
