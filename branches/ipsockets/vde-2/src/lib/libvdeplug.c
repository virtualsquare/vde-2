/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2006 Renzo Davoli, University of Bologna
 * (c) 2010 Renzo Davoli - stream + point2point
 * (c) 2011 Renzo Davoli - udpconnect
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
 *
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
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
#include <netdb.h>
#include <netinet/in.h>
#include <assert.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <sys/syslog.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include <libvdeplug.h>
#define CONNECTED_P2P

/* Per-User standard switch definition */
/* This will be prefixed by getenv("HOME") */
/* it can be a symbolic link to the switch dir */
#define STDSWITCH "/.vde2/default.switch"
/* deprecated old name */
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
	union {
		char * inpath;
		struct sockaddr_in inaddr;
	} sock;
	size_t outlen;
	struct sockaddr *outsock;
};

#define SWITCH_MAGIC 0xfeedface
#define MAXDESCR 128
#define VDEFLAG_P2P_SOCKET	0x1
#define VDEFLAG_UDP_SOCKET	0x2
#define VDEFLAG_IPSWITCH_SOCKET	0x4

#define VDEFLAG_P2P (VDEFLAG_P2P_SOCKET | VDEFLAG_UDP_SOCKET)

#define	IPSOCK_FILE_FIELD_LEN	256

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	union {
		struct sockaddr_un sock_un;
		struct sockaddr_in sock_in;
	} socket;
	char description[MAXDESCR];
} __attribute__((packed));

static int logok = 1;
void printlog(int priority, const char *format, ...);
void print_sockinfo(int fd, char *heading);
static int read_ctl_socket_file(char *sock_filename,
	char *server_name, int *server_port);

int vde_open_ip_unix(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args, int swtchport);
int vde_open_ipsock(struct vdeconn *conn, char *server_name,
	int server_port, char *descr, struct vde_open_args *open_args,
	int swtchport);
int vde_open_udp(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args);
int vde_open_p2p(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args);
int vde_open_unixsock(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args, int swtchport);
VDECONN *vde_open_real(char *given_sockname, char *descr,
	int interface_version, struct vde_open_args *open_args);

#define MAX_RETRIES	30 /* Seconds */

int vde_open_ip_unix(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args, int swtchport)
{

	char	*gs = (char *)strdup(given_sockname);
	char	sock_filename[PATH_MAX];
	struct	stat st;
	char	*split;
	int		filetype;

	/*
	 * Because ctl file may be over NFS, when system is loaded, it can
	 * pose lag.  Therefore, retry 100 times with delay.
	 */
	int	retries = MAX_RETRIES;

	if(gs[strlen(gs)-1] == ']' &&
		(split=rindex(gs,'[')) != NULL) {
		*split = 0;
	}
	snprintf(sock_filename, PATH_MAX, "%s/ctl", gs);
	free(gs);
	while (retries) {
		if (stat(sock_filename, &st) == 0)
			break;
		sleep(1);
		retries--;
	}

	if (retries == 0) {
		printlog(LOG_ERR, "Error accessing socket file: %s (%d)"
			" after %d retries", sock_filename, errno,
			MAX_RETRIES);
		return -1;
	}

	if (retries != MAX_RETRIES) {
		printlog(LOG_WARNING, "Accessing socket file: %s (%d)"
			" success after %d retries", sock_filename, errno,
			(MAX_RETRIES - retries));
	}

	filetype = st.st_mode & S_IFMT;

	switch (filetype) {
	case S_IFREG:
	{
	/*
	 * If its a regular file, then the file contains the IP
	 * and port information where we need to connect to using
	 * IP sockets, instead of the default UNIX sockets.
	 */
		char	sock_filename[PATH_MAX];
		char	server_name[IPSOCK_FILE_FIELD_LEN];
		int	server_port;
		/*
		 * Fill in the IP and port for the control socket.
		 */
		snprintf(sock_filename, PATH_MAX, "%s/ctl", given_sockname);
		if (read_ctl_socket_file(sock_filename, server_name,
			&server_port) != 0) {
        		printlog(LOG_ERR, "VDE_OPEN: Could not open CTL file: %s",
				sock_filename);
		}
		return vde_open_ipsock(conn, server_name, server_port,
			descr, open_args, swtchport);
		break;
	}
	case S_IFSOCK:
		return vde_open_unixsock(conn, given_sockname,
			descr, open_args, swtchport);
		break;
	default:
		printlog(LOG_ERR, "Unsupported socket file type: %X", filetype);
		break;
	}
	return -1;
}

int vde_open_ipsock(struct vdeconn *conn, char *server_name,
	int server_port, char *descr, struct vde_open_args *open_args,
	int swtchport)
{
	struct passwd *callerpwd;
	struct request_v3 req;
	int pid = getpid();
	struct sockaddr_in sockin;
	struct sockaddr_in dataout;
	int res;
	struct hostent *host;
	struct sockaddr sockinfo;
	socklen_t sockinfo_sz;
	int	err = 0;

	printlog(LOG_NOTICE, "Using IP SOCKETS (%s: %d)",
		server_name, server_port);
	conn->fdctl = conn->fddata = -1;

	memset(&req, 0, sizeof(req));
	/* get the login name */
	callerpwd = getpwuid(getuid());

	if (swtchport == 0)
		req.type = REQ_NEW_PORT0;
	else
		req.type = REQ_NEW_CONTROL;

	if (swtchport < 0)
		swtchport = 0;

	if (open_args != NULL && swtchport <= 0) {
		swtchport = open_args->port;
		assert (swtchport != -1);
	}

	/*
	 * Create a ctl port and connect to advertised ctl port of the
	 * switch, so that we can send out the data port information
	 * on the ctl channel
	 */
	if((conn->fdctl = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		err = errno;
		printlog(LOG_ERR, "CTL-FD SOCKET error");
		goto fail;
	}

	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(server_port);

	host = gethostbyname(server_name);
	if (host == NULL) {
		err = errno;
		printlog(LOG_ERR, "Remote server %s not found", server_name);
		goto fail;
	}
	sockin.sin_addr = *((struct in_addr *)host->h_addr);
	if (connect(conn->fdctl, (struct sockaddr *) &sockin,
		sizeof(sockin)) != 0) {
		err = errno;
		printlog(LOG_ERR, "Connection to %s:%d failed",
			server_name, server_port);
		goto fail;
	}

	/*
	 * Get th local IP to which we are bound, and pass that information to
	 * the switch as the IP of the data socket too.
	 */
	sockinfo_sz = sizeof(sockinfo);
	if (getsockname(conn->fdctl, &sockinfo, &sockinfo_sz ) < 0 ) {
		err = errno;
		printlog(LOG_ERR, "getsockname error (IP)");
		goto fail;
	}
	req.socket.sock_in.sin_addr = ((struct sockaddr_in *)&sockinfo)->sin_addr;
	print_sockinfo(conn->fdctl, "CTRL-FD");

	/*
	 * Create a data port for actual data packet transmission
	 */
	if((conn->fddata = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		err = errno;
		printlog(LOG_ERR, "DATA-FD SOCKET error");
		goto fail;
	}

	/*
	 * Once created, we need to send this information to the switch
	 * so that it can extablish a connection with us here. The req.socket.sock_in
	 * is overloaded here. Actually this is the data that gets sent to the
	 * server for establishing connection with us
	 */
	req.magic = SWITCH_MAGIC;
	req.version = 3;
	req.type = req.type + (swtchport << 8);
	req.socket.sock_in.sin_family = AF_INET;
	req.socket.sock_in.sin_port = 0;

	res = bind(conn->fddata, (struct sockaddr *) &req.socket.sock_in,
		sizeof (req.socket.sock_in));

	/*
	 * Get th local port to which we are bound, and pass that
	 * information to the switch
	 */
	sockinfo_sz = sizeof(sockinfo);
	if (getsockname(conn->fddata, &sockinfo, &sockinfo_sz ) < 0 ) {
		err = errno;
		printlog(LOG_ERR, "getsockname error (PORT)");
		goto fail;
	}
	req.socket.sock_in.sin_port = ((struct sockaddr_in *)&sockinfo)->sin_port;

	printlog(LOG_DEBUG, "Sending information:");
	printlog(LOG_DEBUG, "\tIPADDR: %s", inet_ntoa(req.socket.sock_in.sin_addr));
	printlog(LOG_DEBUG, "\tPORT: %d", ntohs(req.socket.sock_in.sin_port));
	printlog(LOG_DEBUG, "-END-");

	/*
	 * We have stored the port information. IP will be populated
	 * by the switch when it gets this packet
	 */

	snprintf(req.description,MAXDESCR,"%s user=%s PID=%d IP=%s PORT=%d",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid, inet_ntoa(req.socket.sock_in.sin_addr),
			ntohs(req.socket.sock_in.sin_port));

	if (send(conn->fdctl, &req, sizeof(req) - MAXDESCR +
		strlen(req.description), 0) < 0) {
		err = errno;
		printlog(LOG_ERR, "SEND error");
		goto fail;
	}

	/*
	 * After sending our information, we wait to get the switch side
	 * information
	 */
	if (recv(conn->fdctl, &dataout,sizeof(struct sockaddr_in),0)<0)  {
		err = errno;
		printlog(LOG_ERR, "RECV error");
		goto fail;
	}

	printlog(LOG_DEBUG, "Received information:");
	printlog(LOG_DEBUG, "\tIPADDR: %s", inet_ntoa(dataout.sin_addr));
	printlog(LOG_DEBUG, "\tPORT: %d", ntohs(dataout.sin_port));
	printlog(LOG_DEBUG, "-END-");
	/*
	 * We received it. Connect to it. We have successfully extablished
	 * data port connectivity too
	 */
	if (connect(conn->fddata,(struct sockaddr *) &dataout,
		sizeof(struct sockaddr_in))<0) {
		err = errno;
		printlog(LOG_ERR, "Connection failed:");
		goto fail;
	}
	print_sockinfo(conn->fddata, "DATA-FD");

	printlog(LOG_DEBUG, "IP SOCKETS successful (%s: %d)",
		server_name, server_port);
	return 0;
fail:
	printlog(LOG_ERR, "IP SOCKETS failed (%s: %d)",
		server_name, server_port);
	return err;
}

/*
 * When one specifies following string for QEMU sock option,
 * this functions gets triggered
 * -netdev vde,id=netdev0,sock="1111->vhostXXX:2222"
 * -netdev vde,id=netdev0,sock="1111->192.168.1.120:2222"
 */
int vde_open_udp(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args)
{
	struct addrinfo hints;
	struct addrinfo *result,*rp;
	int s;
	char *dst = strstr(given_sockname,"->");
	char *src = given_sockname;
	char *srcport;
	char *dstport;

	printlog(LOG_NOTICE, "Using UDP connection (%s)", given_sockname);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	*dst = 0;
	dst += 2;
	dstport = rindex(dst,':');
	if (dstport == NULL) {
		return EINVAL;
	}
	*dstport = 0;
	dstport++;
	srcport = rindex(src,':');
	if (srcport == NULL) {
		srcport = src;
		src = NULL;
	}
	//fprintf(stderr,"UDP!%s:%s -> %s:%s \n",src,srcport,dst,dstport);
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(src, srcport, &hints, &result);

	if (s != 0) {
		return ECONNABORTED;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		conn->fddata = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (conn->fddata == -1)
			continue;

		if (bind(conn->fddata, rp->ai_addr, rp->ai_addrlen) == 0)
			break;                  /* Success */

		close(conn->fddata);
	}

	if (rp == NULL) {
		return ECONNABORTED;
	}

	freeaddrinfo(result);
	hints.ai_flags = 0;

	s = getaddrinfo(dst, dstport, &hints, &result);

	if (s != 0) {
		return ECONNABORTED;
	}
	/* for now it takes the first */
	conn->outlen = result->ai_addrlen;
	conn->outsock = malloc(result->ai_addrlen);
	memcpy(conn->outsock, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 0;
}

int vde_open_p2p(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args)
{
	struct stat sockstat;
	struct sockaddr_un sockun;
	struct sockaddr_un *sockout;
	char *real_sockname = NULL;
	int res;
	char *group=NULL;
	mode_t mode=0700;

	printlog(LOG_NOTICE, "Using P2P connection (%s)", given_sockname);
	if ((real_sockname=(char *)calloc(PATH_MAX,sizeof(char)))==NULL) {
		return ENOMEM;
	}
	char *sockname = real_sockname;

	if (open_args != NULL) {
		group = open_args->group;
		mode = open_args->mode;
	}

	memset(&sockun, 0, sizeof(sockun));
	if(given_sockname == NULL) {
		return EINVAL;
	}
	strcpy(sockname,given_sockname); /* XXX canonicalize should be better */
	if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		free(real_sockname);
		return ECONNREFUSED;
	}
	sockun.sun_family = AF_UNIX;
	memset(sockun.sun_path,0,sizeof(sockun.sun_path));
	snprintf(sockun.sun_path, sizeof(sockun.sun_path)-1, "%s", sockname);
	/* the socket already exists */
	if(stat(sockun.sun_path,&sockstat) == 0) {
		if (S_ISSOCK(sockstat.st_mode)) {
			/* the socket is already in use */
			res = connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			if (res >= 0) {
				return EADDRINUSE;
			}
			if (errno == ECONNREFUSED)
				unlink(sockun.sun_path);
		}
	}
	res = bind(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	if (res < 0)
		return errno;

	conn->sock.inpath=strdup(sockun.sun_path);
	conn->outlen = sizeof(struct sockaddr_un);
	conn->outsock = (struct sockaddr *) (sockout = calloc(1,sizeof(struct sockaddr_un)));
	if (conn->outsock == NULL)
		return errno;
	sockout->sun_family = AF_UNIX;
	snprintf(sockout->sun_path, sizeof(sockun.sun_path), "%s+", sockname);
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(sockun.sun_path,-1,gid);
	}
	chmod(sockun.sun_path, mode);
	return 0;
}

int vde_open_unixsock(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args, int swtchport)
{
	struct sockaddr_un sockun;
	struct sockaddr_un dataout;
	char *group=NULL;
	mode_t mode=0700;
	int res;
	char *ssh_client = getenv("SSH_CLIENT");
	int descrlen;
	struct passwd *callerpwd;
	int pid = getpid();
	struct request_v3 req;
	int sockno = 0;
	char	real_sockname[PATH_MAX];
	char *sockname = real_sockname;

	printlog(LOG_NOTICE, "Using UNIX SOCKETS (%s)", given_sockname);
	memset(&req, 0, sizeof(req));

	/* get the login name */
	callerpwd = getpwuid(getuid());

	if (swtchport == 0)
		req.type = REQ_NEW_PORT0;
	else
		req.type = REQ_NEW_CONTROL;

	if (swtchport < 0)
		swtchport = 0;

	if (open_args != NULL && swtchport <= 0) {
		swtchport = open_args->port;
		assert (swtchport != -1);
		group = open_args->group;
		mode = open_args->mode;
	}

	memset(&sockun, 0, sizeof(sockun));
	memset(&dataout, 0, sizeof(dataout));

	/* connection to a vde_switch */
	if((conn->fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return errno;
	if((conn->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		return errno;
	sockun.sun_family = AF_UNIX;

	/*
	 * Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path.
	 */
	if (given_sockname &&
			vde_realpath(given_sockname, real_sockname) == NULL) {
		return errno;
	}
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

	if (res != 0) {
		struct stat sockstat;
		/* define a male plug for point2point connection */
		if (!given_sockname)
			return errno;
		snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s", sockname);
		res = connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
		if (res < 0)
			return errno;
		snprintf(sockun.sun_path, sizeof(sockun.sun_path), "%s+", sockname);
		if(stat(sockun.sun_path,&sockstat) == 0) {
			if (S_ISSOCK(sockstat.st_mode)) {
				/* the socket is already in use */
				res = connect(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
				if (res >= 0)
					return EADDRINUSE;
				if (errno == ECONNREFUSED)
					unlink(sockun.sun_path);
			}
		}
		res = bind(conn->fddata, (struct sockaddr *) &sockun, sizeof(sockun));
		if (res < 0)
			return errno;
		conn->sock.inpath=strdup(sockun.sun_path);
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
		close(conn->fdctl);
		conn->fdctl = -1;
		return 0;
	}

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type=req.type + (swtchport << 8);
	req.socket.sock_un.sun_family=AF_UNIX;

	/* First choice, store the return socket from the switch in the control
	 * dir. We assume that given_sockname (hence sockname) is a directory.
	 * Should be a safe assumption unless someone modifies the previous group
	 * of connect() attempts (see the comments above for more information). */
	memset(req.socket.sock_un.sun_path, 0, sizeof(req.socket.sock_un.sun_path));
	do
	{
		/* Here sockname is the last successful one in the previous step. */
		sprintf(req.socket.sock_un.sun_path, "%s/.%05d-%05d",
			sockname, pid, sockno++);
		res=bind(conn->fddata, (struct sockaddr *) &req.socket.sock_un,
			sizeof (req.socket.sock_un));
	}
	while (res < 0 && errno == EADDRINUSE);

	/* It didn't work. So we cycle on the fallback directories until we find a
	 * suitable one (or the list ends). */
	if (res < 0)
	{
		int i;
		for (i = 0, res = -1; fallback_dirname[i] && (res != 0); i++)
		{
			memset(req.socket.sock_un.sun_path, 0,
				sizeof(req.socket.sock_un.sun_path));
			do 
			{
				sprintf(req.socket.sock_un.sun_path, "%s/vde.%05d-%05d",
					fallback_dirname[i], pid, sockno++);
				res = bind(conn->fddata, (struct sockaddr *)
					&req.socket.sock_un, sizeof (req.socket.sock_un));
			}
			while (res < 0 && errno == EADDRINUSE);
		}
	}

	/* Nothing worked, so cleanup and return with an error. */
	if (res < 0)
		return errno;

	conn->sock.inpath=strdup(req.socket.sock_un.sun_path);

	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		chown(req.socket.sock_un.sun_path,-1,gid);
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
					if (chown(req.socket.sock_un.sun_path,-1,ctlstat.st_gid) == 0) 
						mode |= 070;
					else
						mode |= 077;
				}
			}
		}
	}
	chmod(req.socket.sock_un.sun_path,mode);

#ifdef DESCR_INCLUDE_SOCK
	descrlen=snprintf(req.description,MAXDESCR,"%s user=%s PID=%d SOCK=%s",
		descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
		pid,req.socket.sock_un.sun_path);
#else
	descrlen=snprintf(req.description,MAXDESCR,"%s user=%s PID=%d",
		descr,(callerpwd != NULL)?callerpwd->pw_name:"??", pid);
#endif

	if (ssh_client) {
		char *endofip=strchr(ssh_client,' ');
		if (endofip) *endofip=0;
		snprintf(req.description+descrlen,MAXDESCR-descrlen," SSH=%s", ssh_client);
		if (endofip) *endofip=' ';
	}


	if (send(conn->fdctl,&req,sizeof(req)-MAXDESCR+strlen(req.description),0)<0)
		return errno;

	if (recv(conn->fdctl,&dataout,sizeof(struct sockaddr_un),0)<0)
		return errno;

	if (connect(conn->fddata,(struct sockaddr *)&dataout,sizeof(struct sockaddr_un))<0)
		return errno;

	chmod(dataout.sun_path, mode);

	return 0;
}

#ifdef USE_IPN
int vde_open_unixsock_ipn(struct vdeconn *conn, char *given_sockname,
	char *descr, struct vde_open_args *open_args, int swtchport)
{
	int res;
	struct passwd *callerpwd;
	char *ssh_client = getenv("SSH_CLIENT");
	int pid = getpid();
	struct sockaddr_un sockun;
	char real_sockname[PATH_MAX];
	char *sockname = real_sockname;
	struct request_v3 req;

	printlog(LOG_NOTICE, "Using UNIX-IPN SOCKETS (%s)", given_sockname);
	memset(&req, 0, sizeof(req));
	/* get the login name */
	callerpwd = getpwuid(getuid());

	if (swtchport == 0)
		req.type = REQ_NEW_PORT0;
	else
		req.type = REQ_NEW_CONTROL;

	if (swtchport < 0)
		swtchport = 0;

	if (open_args != NULL && swtchport <= 0) {
		swtchport = open_args->port;
	}

	/*
	 * Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path.
	 */
	if (given_sockname &&
		vde_realpath(given_sockname, real_sockname) == NULL) {
		return -1;
	}

#if 0
/* AF_IPN has not been officially assigned yet
	 we "steal" unused AF_NETBEUI in the meanwhile
	 this code will be uncommented when AF_IPN is assigned. */
	if((conn->fddata = socket(AF_IPN,SOCK_RAW,IPN_ANY)) >= 0) {
		/* IPN service exists */
		sockun.sun_family = AF_IPN;
	}
#endif
	memset(&sockun, 0, sizeof(sockun));
	conn->fddata = socket(AF_IPN_STOLEN,SOCK_RAW,IPN_ANY);
	/* IPN_STOLEN service exists */
	sockun.sun_family = AF_IPN_STOLEN;
	if (swtchport != 0 || req.type == REQ_NEW_PORT0)
		setsockopt(conn->fddata, 0, IPN_SO_PORT,
			&swtchport, sizeof(swtchport));
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
		int descrlen=snprintf(req.description,MAXDESCR,"%s user=%s PID=%d",
				descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
				pid);
		if (ssh_client) {
			char *endofip=strchr(ssh_client,' ');
			if (endofip) *endofip=0;
			snprintf(req.description+descrlen,MAXDESCR-descrlen,
					" SSH=%s", ssh_client);
			if (endofip) *endofip=' ';
		}
		setsockopt(conn->fddata,0,IPN_SO_DESCR,req.description,
				strlen(req.description+1));
		conn->fdctl = -1;
		return 0;
	} else
		close(conn->fddata);
	return -1;
}
#endif

VDECONN *vde_open_real(char *given_sockname, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vdeconn *conn=NULL;
	int swtchport = -1;
	int flags=0;
	char *std_sockname=NULL;
	int err = 0;

	if (open_args != NULL) {
		if (interface_version == 1) {
			if (open_args->port == -1)
				flags |= VDEFLAG_P2P_SOCKET;
		} else {
			err = EINVAL;
			goto end;
		}
	}

	if ((std_sockname=(char *)calloc(PATH_MAX,sizeof(char)))==NULL) {
		errno=ENOMEM;
		goto end;
	}

	if ((conn=calloc(1,sizeof(struct vdeconn)))==NULL)
	{
		err = ENOMEM;
		goto end;
	}
	conn->fdctl = conn->fddata = -1;

	if (given_sockname == NULL || *given_sockname == '\0') {
		char *homedir = getenv("HOME");
		given_sockname = NULL;
		if (homedir) {
			struct stat statbuf;
			snprintf(std_sockname, PATH_MAX, "%s%s", homedir, STDSWITCH);
			if (lstat(std_sockname,&statbuf) == 0)
				given_sockname = std_sockname;
			else {
				snprintf(std_sockname, PATH_MAX, "%s%s", homedir, STDSOCK);
				if (lstat(std_sockname,&statbuf) == 0)
					given_sockname = std_sockname;
			}
		}
	} else {
		char *split;
		if((split = strstr(given_sockname,"->")) != NULL && rindex(split,':') != NULL)
			flags |= VDEFLAG_UDP_SOCKET;
		else if((split = strstr(given_sockname,"ip")) != NULL && rindex(split,':') != NULL)
			flags = VDEFLAG_IPSWITCH_SOCKET;

		/*
		 * This is another way of specifying the port number.
		 * sock=/aab/aa/ff[3], instead of port=3,sock=/aab/aa/ff
		 * Port 0 is management port.
		 */
		if(given_sockname[strlen(given_sockname)-1] == ']'
				&& (split=rindex(given_sockname,'[')) != NULL) {
			*split=0;
			split++;
			swtchport = atoi(split);
			if (*split==']' && ((flags & VDEFLAG_IPSWITCH_SOCKET) == 0))
				flags |= VDEFLAG_P2P_SOCKET;
			if (*given_sockname==0)
				given_sockname = NULL;
		}
	}

#ifdef USE_IPN
	if((flags & VDEFLAG_P2P) == 0) {
		if ((err = vde_open_unixsock_ipn(conn, given_sockname, descr,
			open_args, swtchport)) == 0) {
			/* If successful, do not fall through */
			goto end;
		}
	}
#endif
	if (flags & VDEFLAG_UDP_SOCKET) {
		/* UDP connection */
		err = vde_open_udp(conn, given_sockname, descr, open_args);
		if (err)
        		printlog(LOG_ERR, "ERROR: vde_open_udp, RC: %d", err);
	} else if (flags & VDEFLAG_P2P_SOCKET) {
		/* define a female socket for point2point connection */
		err = vde_open_p2p(conn, given_sockname, descr, open_args);
		if (err)
        		printlog(LOG_ERR, "ERROR: vde_open_p2p, RC: %d", err);
	} else if (flags & VDEFLAG_IPSWITCH_SOCKET) {
		char *server = strstr(given_sockname, "ip");
		server += 3; /* 'ip' + 1 space */
		char *ipport = rindex(server, ':');
		*ipport = 0;
		ipport++;
		err = vde_open_ipsock(conn, server, atoi(ipport),
			descr, open_args, swtchport);
		if (err)
        		printlog(LOG_ERR, "ERROR: vde_open_ipsock, RC: %d", err);
	} else {
		err = vde_open_ip_unix(conn, given_sockname, descr,
			open_args, swtchport);
		if (err)
        		printlog(LOG_ERR, "ERROR: vde_open_ip_unix, RC: %d", err);
	}

end:
	if (err) {
		if (conn) {
			if (conn->fdctl >= 0)
				close(conn->fdctl);
			if (conn->fddata >= 0)
				close(conn->fddata);
			if (conn->sock.inpath != NULL)
				unlink(conn->sock.inpath);
			if (conn->outsock != NULL)
				free(conn->outsock);
			free(conn);
		}
		conn = NULL;
		errno = err;
	}

	if (std_sockname) free(std_sockname);
	return conn;
}


ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
#ifdef CONNECTED_P2P
	ssize_t retval;
	if (__builtin_expect(conn!=0,1)) {
		if (__builtin_expect(((retval=recv(conn->fddata,buf,len,0)) > 0), 1))
			return retval;
		else {
			if (retval == 0 && conn->outsock != NULL) {
				static struct sockaddr unspec={AF_UNSPEC};
				connect(conn->fddata,&unspec,sizeof(unspec));
			}
			return retval;
		}
	}
	else {
		errno=EBADF;
		return -1;
	}
#else
	if (__builtin_expect(conn!=0,1))
		return recv(conn->fddata,buf,len,0);
	else {
		errno=EBADF;
		return -1;
	}
#endif
}

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
#ifdef CONNECTED_P2P
	if (__builtin_expect(conn!=0,1)) {
		ssize_t retval;
		if (__builtin_expect(((retval=send(conn->fddata,buf,len,0)) >= 0),1)) 
			return retval;
		else {
			if (__builtin_expect(errno == ENOTCONN || errno == EDESTADDRREQ,0)) {
				if (__builtin_expect(conn->outsock != NULL,1)) {
					connect(conn->fddata, conn->outsock,conn->outlen);
					return send(conn->fddata,buf,len,0);
				} else
					return retval;
			} else
				return retval;
		}
	} else {
		errno=EBADF;
		return -1;
	}
#else
	if (__builtin_expect(conn!=0,1)) {
		if (__builtin_expect(conn->outsock == NULL,1))
			return send(conn->fddata,buf,len,0);
		else 
			return sendto(conn->fddata,buf,len,0,
					conn->outsock,conn->outlen);
	} else {
		errno=EBADF;
		return -1;
	}
#endif
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
#ifdef CONNECTED_P2P
		send(conn->fddata,NULL,0,0);
#endif
		if (conn->sock.inpath != NULL)
			unlink(conn->sock.inpath);
		if (conn->outsock != NULL)
			free(conn->outsock);
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


void print_sockinfo(int fd, char *heading)
{
	struct sockaddr sockinfo;
	socklen_t sockinfo_sz;
    sockinfo_sz = sizeof(sockinfo);

    if (getsockname(fd, &sockinfo, &sockinfo_sz ) < 0 ) {
        printlog(LOG_ERR, "print_sockinfo getsockname error: ");
		return;
    }
	printlog(LOG_DEBUG, "** %s **", heading);
	printlog(LOG_DEBUG, "\tIPADDR: %s",
		inet_ntoa(((struct sockaddr_in *)&sockinfo)->sin_addr));
	printlog(LOG_DEBUG, "\tPORT: %d",
		ntohs(((struct sockaddr_in *)&sockinfo)->sin_port));
	printlog(LOG_DEBUG, "-- %s --", heading);
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static int
read_ctl_socket_file(char *sock_filename, char *server_name, int *server_port)
{
	FILE	*fp;
	char 	field_name[IPSOCK_FILE_FIELD_LEN];
	int	rc = -1;

	if ((fp = fopen(sock_filename, "r")) == NULL) {
		return(EIO);
	}
	if (fscanf(fp, "%s%s", field_name, server_name) == 2)
		if (fscanf(fp, "%s%d", field_name, server_port) == 2)
			rc = 0;
	fclose(fp);
	return (rc);
}
