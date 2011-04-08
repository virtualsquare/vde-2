/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2006 Renzo Davoli, University of Bologna
 * (c) 2010 Renzo Davoli - stream + point2point
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
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <libvdeplug.h>

/* Per-User standard switch definition */
/* This will be prefixed by getenv("HOME") */
/* it can be a symbolic link to the switch dir */
#define STDSOCK "/.vde2/stdsock"

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

#ifndef MIN
#define MIN(X,Y) (((X)<(Y))?(X):(Y))
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
	struct sockaddr_un *outpath;
};

#define SWITCH_MAGIC 0xfeedface
#define MAXDESCR 128
#define VDEFLAG_P2P_SOCKET 1

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
	struct vdeconn *conn=NULL;
	struct passwd *callerpwd;
	struct request_v3 *req=NULL;
	int pid = getpid();
	struct sockaddr_un *sockun=NULL;
	struct sockaddr_un *dataout=NULL;
	int port=0;
	char *group=NULL;
	mode_t mode=0700;
	int sockno=0;
	int flags=0;
	int res;
	char *std_sockname=NULL;
	char *real_sockname=NULL;
	char *sockname=NULL;
	char *ssh_client = getenv("SSH_CLIENT");
	int descrlen;

	if (open_args != NULL) {
		if (interface_version == 1) {
			port=open_args->port;
			group=open_args->group;
			mode=open_args->mode;
			if (port == -1)
				flags |= VDEFLAG_P2P_SOCKET;
		}
		else {
			errno=EINVAL;
			goto abort;
		} 
	}

	if ((req=(struct request_v3 *)calloc(1, sizeof(struct request_v3)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}
	if ((sockun=(struct sockaddr_un *)calloc(1, sizeof(struct sockaddr_un)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}
	if ((dataout=(struct sockaddr_un *)calloc(1, sizeof(struct sockaddr_un)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}
	if ((std_sockname=(char *)calloc(PATH_MAX,sizeof(char)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}
	if ((real_sockname=(char *)calloc(PATH_MAX,sizeof(char)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}
	sockname = real_sockname;
	if ((conn=calloc(1,sizeof(struct vdeconn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}
	conn->fdctl=conn->fddata=-1;
	//get the login name
	callerpwd=getpwuid(getuid());
	req->type = REQ_NEW_CONTROL;
	if (given_sockname == NULL || *given_sockname == '\0') {
		char *homedir = getenv("HOME");
		given_sockname = NULL;
		if (homedir) {
			struct stat statbuf;
			snprintf(std_sockname, PATH_MAX, "%s%s", homedir, STDSOCK);
			if (lstat(std_sockname,&statbuf)==0)
				given_sockname = std_sockname;
		}
	} else {
		char *split;
		if(given_sockname[strlen(given_sockname)-1] == ']' && (split=rindex(given_sockname,'[')) != NULL) {
			*split=0;
			split++;
			port=atoi(split);
			if (*split==']')
				flags |= VDEFLAG_P2P_SOCKET;
			else if (port == 0)
				req->type = REQ_NEW_PORT0;
			if (*given_sockname==0)
				given_sockname = NULL;
		}
	}

	/* Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path. */
	if (given_sockname && !(flags & VDEFLAG_P2P_SOCKET) &&
			vde_realpath(given_sockname, real_sockname) == NULL)
		goto abort;

#ifdef USE_IPN
#if 0
/* AF_IPN has not been officially assigned yet
	 we "steal" unused AF_NETBEUI in the meanwhile
	 this code will be uncommented when AF_IPN is assigned. */
	if((conn->fddata = socket(AF_IPN,SOCK_RAW,IPN_ANY)) >= 0) {
		/* IPN service exists */
		sockun.sun_family = AF_IPN;
	}
#endif
	if((flags & VDEFLAG_P2P_SOCKET) == 0 &&
			(conn->fddata = socket(AF_IPN_STOLEN,SOCK_RAW,IPN_ANY)) >= 0) {
		/* IPN_STOLEN service exists */
		sockun->sun_family = AF_IPN_STOLEN;
		if (port != 0 || req->type == REQ_NEW_PORT0)
			setsockopt(conn->fddata,0,IPN_SO_PORT,&port,sizeof(port));
		/* If we're given a sockname, just try it */
		if (given_sockname)
		{
			snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s", sockname);
			res = connect(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
		}
		/* Else try all the fallback socknames, one by one */
		else
		{
			int i;
			for (i = 0, res = -1; fallback_sockname[i] && (res != 0); i++)
			{
				snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s", fallback_sockname[i]);
				res = connect(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
			}
		}

		/* If one of the connect succeeded, we're done */
		if (res == 0)
		{
			int descrlen=snprintf(req->description,MAXDESCR,"%s user=%s PID=%d",
					descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
					pid);
			if (ssh_client) {
				char *endofip=strchr(ssh_client,' ');
				if (endofip) *endofip=0;
				snprintf(req->description+descrlen,MAXDESCR-descrlen,
						" SSH=%s", ssh_client);
				if (endofip) *endofip=' ';
			}
			setsockopt(conn->fddata,0,IPN_SO_DESCR,req->description,
					strlen(req->description+1));
			*(conn->inpath.sun_path)=0; /*null string, do not delete "return path"*/
			conn->fdctl=-1;
			goto cleanup;
		} else
			close(conn->fddata);
	}
#endif
	/* define a female socket for point2point connection */
	if (flags & VDEFLAG_P2P_SOCKET) {
		struct stat sockstat;
		if(given_sockname == NULL) {
			errno = EINVAL;
			goto abort;
		}
		strcpy(sockname,given_sockname); /* XXX canonicalize should be better */
		if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
			goto abort;
		sockun->sun_family = AF_UNIX;
		memset(sockun->sun_path,0,sizeof(sockun->sun_path));
		snprintf(sockun->sun_path, sizeof(sockun->sun_path)-1, "%s", sockname);
		/* the socket already exists */
		if(stat(sockun->sun_path,&sockstat) == 0) {
			if (S_ISSOCK(sockstat.st_mode)) {
				/* the socket is already in use */
				res = connect(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
				if (res >= 0) {
					errno = EADDRINUSE;
					goto abort;
				}
				if (errno == ECONNREFUSED)
					unlink(sockun->sun_path);
			}
		}
		res = bind(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
		if (res < 0)
			goto abort;
		memcpy(&(conn->inpath),sockun,sizeof(conn->inpath));
		conn->outpath = calloc(1,sizeof(struct sockaddr_un));
		if (conn->outpath==NULL)
			goto abort;
		conn->outpath->sun_family = AF_UNIX;
		snprintf(conn->outpath->sun_path, sizeof(sockun->sun_path), "%s+", sockname);
		if (!conn->outpath)
			goto abort;
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
		goto cleanup;
	}
	if((conn->fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		goto abort;
	if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		goto abort;
	sockun->sun_family = AF_UNIX;

	/* If we're given a sockname, just try it (remember: sockname is the
	 * canonicalized version of given_sockname - though we don't strictly need
	 * the canonicalized versiono here). sockname should be the name of a
	 * *directory* which contains the control socket, named ctl. Older
	 * versions of VDE used a socket instead of a directory (so an additional
	 * attempt with %s instead of %s/ctl could be made), but they should
	 * really not be used anymore. */
	if (given_sockname)
	{
		snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s/ctl", sockname);
		res = connect(conn->fdctl, (struct sockaddr *) sockun, sizeof(*sockun));
	}
	/* Else try all the fallback socknames, one by one */
	else
	{
		int i;
		for (i = 0, res = -1; fallback_sockname[i] && (res != 0); i++)
		{
			/* Remember sockname for the data socket directory */
			sockname = fallback_sockname[i];
			snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s", sockname);
			res = connect(conn->fdctl, (struct sockaddr *) sockun, sizeof(*sockun));
		}
	}

	if (res != 0) {
		struct stat sockstat;
		/* define a male plug for point2point connection */
		if (!given_sockname)
			goto abort;
		snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s", sockname);
		res = connect(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
		if (res < 0)
			goto abort;
		snprintf(sockun->sun_path, sizeof(sockun->sun_path), "%s+", sockname);
		if(stat(sockun->sun_path,&sockstat) == 0) {
			if (S_ISSOCK(sockstat.st_mode)) {
				/* the socket is already in use */
				res = connect(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
				if (res >= 0) {
					errno = EADDRINUSE;
					goto abort;
				}
				if (errno == ECONNREFUSED)
					unlink(sockun->sun_path);
			}
		}
		res = bind(conn->fddata, (struct sockaddr *) sockun, sizeof(*sockun));
		if (res < 0)
			goto abort;
		memcpy(&(conn->inpath),sockun,sizeof(conn->inpath));
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
		close(conn->fdctl);
		conn->fdctl=-1;
		goto cleanup;
	}

	req->magic=SWITCH_MAGIC;
	req->version=3;
	req->type=req->type+(port << 8);
	req->sock.sun_family=AF_UNIX;

	/* First choice, store the return socket from the switch in the control
	 * dir. We assume that given_sockname (hence sockname) is a directory.
	 * Should be a safe assumption unless someone modifies the previous group
	 * of connect() attempts (see the comments above for more information). */
	memset(req->sock.sun_path, 0, sizeof(req->sock.sun_path));
	do
	{
		/* Here sockname is the last successful one in the previous step. */
		sprintf(req->sock.sun_path, "%s/.%05d-%05d", sockname, pid, sockno++);
		res=bind(conn->fddata, (struct sockaddr *) &req->sock, sizeof (req->sock));
	}
	while (res < 0 && errno == EADDRINUSE);

	/* It didn't work. So we cycle on the fallback directories until we find a
	 * suitable one (or the list ends). */
	if (res < 0)
	{
		int i;
		for (i = 0, res = -1; fallback_dirname[i] && (res != 0); i++)
		{
			memset(req->sock.sun_path, 0, sizeof(req->sock.sun_path));
			do 
			{
				sprintf(req->sock.sun_path, "%s/vde.%05d-%05d", fallback_dirname[i], pid, sockno++);
				res = bind(conn->fddata, (struct sockaddr *) &req->sock, sizeof (req->sock));
			}
			while (res < 0 && errno == EADDRINUSE);
		}
	}

	/* Nothing worked, so cleanup and return with an error. */
	if (res < 0)
		goto abort;

	memcpy(&(conn->inpath),&req->sock,sizeof(req->sock));
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(conn->inpath.sun_path,-1,gid);
	} else {
		/* when group is not defined, set permission for the reverse channel */
		struct stat ctlstat;
		/* if no permission gets "voluntarily" granted to the socket */
		if ((mode & 077) == 0) {
			if (stat(sockun->sun_path, &ctlstat) == 0) {
				/* if the switch is owned by root or by the same user it should
					 work 0700 */
				if (ctlstat.st_uid != 0 && ctlstat.st_uid != geteuid()) {
					/* try to change the group ownership to the same of the switch */
					/* this call succeeds if the vde user and the owner of the switch
						 belong to the group */
					if (chown(conn->inpath.sun_path,-1,ctlstat.st_gid) == 0) 
						mode |= 070;
					else
						mode |= 077;
				}
			}
		}
	}
	chmod(conn->inpath.sun_path,mode);

#ifdef DESCR_INCLUDE_SOCK
	descrlen=snprintf(req->description,MAXDESCR,"%s user=%s PID=%d SOCK=%s",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid,req->sock.sun_path);
#else
	descrlen=snprintf(req->description,MAXDESCR,"%s user=%s PID=%d",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??", pid);
#endif

	if (ssh_client) {
		char *endofip=strchr(ssh_client,' ');
		if (endofip) *endofip=0;
		snprintf(req->description+descrlen,MAXDESCR-descrlen," SSH=%s", ssh_client);
		if (endofip) *endofip=' ';
	}


	if (send(conn->fdctl,req,sizeof(*req)-MAXDESCR+strlen(req->description),0)<0) 
		goto abort;

	if (recv(conn->fdctl,dataout,sizeof(struct sockaddr_un),0)<0) 
		goto abort;

	if (connect(conn->fddata,(struct sockaddr *)dataout,sizeof(struct sockaddr_un))<0) 
		goto abort;

	chmod(dataout->sun_path,mode);

	goto cleanup;

abort:
	{
		int err=errno;
		if (conn) {
			if (conn->fdctl >= 0)
				close(conn->fdctl);
			if (conn->fddata >= 0)
				close(conn->fddata);
			if (*(conn->inpath.sun_path))
				unlink(conn->inpath.sun_path);
			if (conn->outpath != NULL)
				free(conn->outpath);
			free(conn);
		}
		conn = NULL;
		errno=err;
	}
cleanup:
	if (req) free(req);
	if (sockun) free(sockun);
	if (dataout) free(dataout);
	if (std_sockname) free(std_sockname);
	if (real_sockname) free(real_sockname);
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
	if (__builtin_expect(conn!=0,1)) {
		if (__builtin_expect(conn->outpath == NULL,1))
			return send(conn->fddata,buf,len,0);
		else 
			return sendto(conn->fddata,buf,len,0,
				(struct sockaddr *)conn->outpath,sizeof(conn->inpath));
	} else {
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
		if (conn->outpath != NULL)
			free(conn->outpath);
		close(conn->fddata);
		close(conn->fdctl);
		free(conn);
		return 0;
	} else {
		errno=EBADF;
		return -1;
	}
}

/* vdestream */

#define MAXPACKET 1521

struct vdestream {
	void *opaque;
	int fdout;
	ssize_t (*frecv)(void *opaque, void *buf, size_t count);
	void (*ferr)(void *opaque, int type, char *format, ...);
	char fragment[MAXPACKET];
	char *fragp;
	unsigned int rnx,remaining;
};

VDESTREAM *vdestream_open(void *opaque,
		int fdout,
		ssize_t (*frecv)(void *opaque, void *buf, size_t count),
		void (*ferr)(void *opaque, int type, char *format, ...)
		)
{
	VDESTREAM *vdestream;
	if ((vdestream=calloc(1,sizeof(struct vdestream)))==NULL) {
		errno=ENOMEM;
		return NULL;
	} else {
		vdestream->opaque=opaque;
		vdestream->fdout=fdout;
		vdestream->frecv=frecv;
		vdestream->ferr=ferr;
		return vdestream;
	}
}

ssize_t vdestream_send(VDESTREAM *vdestream, const void *buf, size_t len)
{
	if (len <= MAXPACKET) {
		unsigned char header[2];
		struct iovec iov[2]={{header,2},{(void *)buf,len}};
		header[0]=len >> 8;
		header[1]=len & 0xff;
		return writev(vdestream->fdout,iov,2);
	} else
		return 0;
}

void vdestream_recv(VDESTREAM *vdestream, unsigned char *buf, size_t len)
{
	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",myname,rnx,vdestream->remaining,len);
	if (len==0) return;
	if (vdestream->rnx>0) {
		register int amount=MIN(vdestream->remaining,len);
		//fprintf(stderr,"%s: fragment amount %d\n",myname,amount);
		memcpy(vdestream->fragp,buf,amount);
		vdestream->remaining-=amount;
		vdestream->fragp+=amount;
		buf+=amount;
		len-=amount;
		if (vdestream->remaining==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",myname,vdestream->rnx);
			vdestream->frecv(vdestream->opaque,vdestream->fragment,vdestream->rnx);
			vdestream->rnx=0;
		}
	}
	while (len > 1) {
		vdestream->rnx=(buf[0]<<8)+buf[1];
		len-=2;
		//fprintf(stderr,"%s %d: packet %d size %d %x %x\n",myname,getpid(),vdestream->rnx,len,buf[0],buf[1]);
		buf+=2;
		if (vdestream->rnx == 0)
			continue;
		if (vdestream->rnx > MAXPACKET) {
			if (vdestream->ferr != NULL)
				vdestream->ferr(vdestream->opaque,PACKET_LENGTH_ERROR,
						"size %d expected size %d",len,vdestream->rnx);
			vdestream->rnx=0;
			return;
		}
		if (vdestream->rnx > len) {
			//fprintf(stderr,"%s: begin defrag %d\n",myname,vdestream->rnx);
			vdestream->fragp=vdestream->fragment;
			memcpy(vdestream->fragp,buf,len);
			vdestream->remaining=vdestream->rnx-len;
			vdestream->fragp+=len;
			len=0;
		} else {
			//fprintf(stderr,"%s: deliver %d\n",myname,vdestream->rnx);
			vdestream->frecv(vdestream->opaque,buf,vdestream->rnx);
			buf+=vdestream->rnx;
			len-=vdestream->rnx;
			vdestream->rnx=0;
		}
	}
}

void vdestream_close(VDESTREAM *vdestream)
{
	free(vdestream);
}

