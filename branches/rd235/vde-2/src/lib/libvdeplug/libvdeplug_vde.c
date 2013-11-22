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
#include <ctype.h>
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
#include <sys/types.h>
#include "libvdeplug_mod.h"
#include "canonicalize.h"

static char *vde_vde_check(char *given_sockname);
static VDECONN *vde_vde_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_vde_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_vde_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_vde_datafd(VDECONN *conn);
static int vde_vde_ctlfd(VDECONN *conn);
static int vde_vde_close(VDECONN *conn);

struct vdeplug_module vdeplug_vde={
	.vde_check=vde_vde_check,
	.vde_open_real=vde_vde_open,
	.vde_recv=vde_vde_recv,
	.vde_send=vde_vde_send,
	.vde_datafd=vde_vde_datafd,
	.vde_ctlfd=vde_vde_ctlfd,
	.vde_close=vde_vde_close};

struct vde_vde_conn {
	struct vdeplug_module *module;
	int fdctl;
	int fddata;
	char *inpath;
};

static char *vde_vde_check(char *given_sockname)
{
	static char tag[]="VDE:";
	static char atag[]="VDE{";
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
	"/var/run/vde.ctl/ctl",
	"/tmp/vde.ctl/ctl",
	"/tmp/vde.ctl",
	NULL,
};

/* Fallback directories for the data socket, NULL-terminated array of absolute
 * directory names, with no trailing /. */
static const char *fallback_dirname[] = {
	"/var/run",
	"/var/tmp",
	"/tmp",
	NULL,
};

#define SWITCH_MAGIC 0xfeedface
enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
} __attribute__((packed));

static VDECONN *vde_vde_open(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct request_v3 req;
	int port=0;
	char *portgroup=NULL;
	char *group=NULL;
	mode_t mode=0700;
	char real_sockname[PATH_MAX];
	int fdctl=-1;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un dataout;
	char *split;
	char *sockname=NULL;
	int res;
	int pid=getpid();
	int sockno=0;
	struct vde_vde_conn *newconn;

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
		port=atoi(split);
		if (port == 0) {
			if (isdigit(*split))
				req.type = REQ_NEW_PORT0;
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
	if (*given_sockname &&
			vde_realpath(given_sockname, real_sockname) == NULL)
		goto abort;
	sockname=real_sockname;

	req.type = REQ_NEW_CONTROL;
	strncpy(req.description, descr, MAXDESCR);
	memset(&sockun, 0, sizeof(sockun));
	memset(&dataout, 0, sizeof(dataout));

	/* connection to a vde_switch */
	if((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		goto abort;
	if((fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		goto abort;
	sockun.sun_family = AF_UNIX;

	/* If we're given a sockname, just try it (remember: sockname is the
	 * canonicalized version of given_sockname - though we don't strictly need
	 * the canonicalized versiono here). sockname should be the name of a
	 * *directory* which contains the control socket, named ctl. Older
	 * versions of VDE used a socket instead of a directory (so an additional
	 * attempt with %s instead of %s/ctl could be made), but they should
	 * really not be used anymore. */
	if (*given_sockname)
	{
		if (portgroup)
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/%s", sockname, portgroup);
		else
			snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s/ctl", sockname);
		res = connect(fdctl, (struct sockaddr *) &sockun, sizeof(sockun));
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
			res = connect(fdctl, (struct sockaddr *) &sockun, sizeof(sockun));
		}
	}

	if (res<0)
		goto abort;

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=req.type+(port << 8);
	req.sock.sun_family=AF_UNIX;

	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	do
	{
		/* Here sockname is the last successful one in the previous step. */
		sprintf(req.sock.sun_path, "%s/.%05d-%05d", sockname, pid, sockno++);
		res=bind(fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
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
				res = bind(fddata, (struct sockaddr *) &req.sock, sizeof (req.sock));
			}
			while (res < 0 && errno == EADDRINUSE);
		}
	}

	/* Nothing worked, so cleanup and return with an error. */
	if (res < 0)
		goto abort;

	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(req.sock.sun_path,-1,gid);
	} else {
		/* when group is not defined, set permission for the reverse channel */
		struct stat ctlstat;
		/* if no permission gets "voluntarily" granted to the socket */
		if ((mode & 077) == 0) {
			if (stat(sockun.sun_path, &ctlstat) == 0) {
				/* if the switch is owned by root or by the same user it should
					 work 0700 */
				if (ctlstat.st_uid != 0 && ctlstat.st_uid != geteuid()) {
					/* try to change the group ownership to the same of the switch */
					/* this call succeeds if the vde user and the owner of the switch
						 belong to the group */
					if (chown(req.sock.sun_path,-1,ctlstat.st_gid) == 0)
						mode |= 070;
					else
						mode |= 077;
				}
			}
		}
	}
	chmod(req.sock.sun_path,mode);

	if (send(fdctl,&req,sizeof(req)-MAXDESCR+strlen(req.description),0)<0) 
		goto abort_deletesock;

	if (recv(fdctl,&dataout,sizeof(struct sockaddr_un),0)<=0)
		goto abort_deletesock;

	if (connect(fddata,(struct sockaddr *)&dataout,sizeof(struct sockaddr_un))<0)
		goto abort_deletesock;

	chmod(dataout.sun_path,mode);

	if ((newconn=calloc(1,sizeof(struct vde_vde_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->module=&vdeplug_vde;
	newconn->fdctl=fdctl;
	newconn->fddata=fddata;
	newconn->inpath=strdup(req.sock.sun_path);

	return (VDECONN *)newconn;

abort_deletesock:
	unlink(req.sock.sun_path);	
abort:
	if (fdctl >= 0) close(fdctl);
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return recv(vde_conn->fddata,buf,len,0);
}

static ssize_t vde_vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return send(vde_conn->fddata,buf,len,0);
}

static int vde_vde_datafd(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return vde_conn->fddata;
}

static int vde_vde_ctlfd(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return vde_conn->fdctl;
}

static int vde_vde_close(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	if (vde_conn->inpath != NULL) {
		unlink(vde_conn->inpath);
		free(vde_conn->inpath);
	}
	close(vde_conn->fddata);
	close(vde_conn->fdctl);
	free(vde_conn);

	return 0;
}
