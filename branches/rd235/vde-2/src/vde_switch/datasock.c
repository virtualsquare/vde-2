/* Copyright 2005 Renzo Davoli - VDE-2
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
 * -g option (group management) by Daniel P. Berrange
 * dir permission patch by Alessio Caprari 2006
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdint.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <net/if.h>
#include <stdarg.h>
#include <limits.h>
#include <grp.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "port.h"
#include "switch.h"
#include "sockutils.h"
#include "consmgmt.h"

static struct swmodule swmi;
static struct mod_support modfun;
static unsigned int ctl_type;
static unsigned int wd_type;
static unsigned int data_type;

static char *rel_ctl_socket = NULL;
static char ctl_socket[PATH_MAX];

static int mode = -1;
static int dirmode = -1;
static gid_t grp_owner = -1;

#define MODULENAME "unix prog"

#define DATA_BUF_SIZE 131072
#define SWITCH_MAGIC 0xfeedface
#define REQBUFLEN 256

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v1 {
	uint32_t magic;
	enum request_type type;
	union {
		struct {
			unsigned char addr[ETH_ALEN];
			struct sockaddr_un name;
		} new_control;
	} u;
	char description[];
} __attribute__((packed));

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[];
} __attribute__((packed));

union request {
	struct request_v1 v1;
	struct request_v3 v3;
};

static int send_datasock(int fd_ctl, int fd_data, void *packet, int len, int port)
{
	int n;

	n = len - send(fd_data, packet, len, 0);
	if(n){
		int rv=errno;
#ifndef VDE_PQ
		if(errno != EAGAIN && errno != EWOULDBLOCK) printlog(LOG_WARNING,"send_sockaddr port %d: %s",port,strerror(errno));
#endif
		if (n>len)
			return -rv;
		else
			return n;
	}
	return 0;
}

#define GETFILEOWNER(PATH) ({\
		struct stat s; \
		(stat((PATH),&s)?-1:s.st_uid); \
		})

static struct endpoint *new_port_v1_v3(int fd_ctl, int type_port,
		struct sockaddr_un *sun_out)
{
	int n, portno;
	struct endpoint *ep;
	enum request_type type = type_port & 0xff;
	int port_request=type_port >> 8;
	uid_t user=-1;
	int fd_data;
#ifdef VDE_DARWIN
	int sockbufsize = DATA_BUF_SIZE;
	int optsize = sizeof(sockbufsize);
#endif
	struct sockaddr_un sun_in;
	switch(type){
		case REQ_NEW_PORT0:
			port_request= -1;
			/* no break: falltrough */
		case REQ_NEW_CONTROL:
			if (sun_out->sun_path[0] != 0) { //not for unnamed sockets
				if (access(sun_out->sun_path,R_OK | W_OK) != 0) { //socket error
					remove_fd(fd_ctl);
					return NULL;
				}
				user=GETFILEOWNER(sun_out->sun_path);
			}

			if((fd_data = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
				printlog(LOG_ERR,"socket: %s",strerror(errno));
				remove_fd(fd_ctl);
				return NULL;
			}
			if(fcntl(fd_data, F_SETFL, O_NONBLOCK) < 0){
				printlog(LOG_ERR,"Setting O_NONBLOCK on data fd %s",strerror(errno));
				close(fd_data);
				remove_fd(fd_ctl);
				return NULL;
			}

#ifdef VDE_DARWIN
			if(setsockopt(fd_data, SOL_SOCKET, SO_SNDBUF, &sockbufsize, optsize) < 0)
				printlog(LOG_WARNING, "Warning: setting send buffer size on data fd %d to %d failed, expect packet loss: %s",
						fd_data, sockbufsize, strerror(errno));
			if(setsockopt(fd_data, SOL_SOCKET, SO_RCVBUF, &sockbufsize, optsize) < 0)
				printlog(LOG_WARNING, "Warning: setting send buffer size on data fd %d to %d failed, expect packet loss: %s",
						fd_data, sockbufsize, strerror(errno));
#endif

			if (connect(fd_data, (struct sockaddr *) sun_out, sizeof(struct sockaddr_un)) < 0) {
				printlog(LOG_ERR,"Connecting to client data socket %s",strerror(errno));
				close(fd_data);
				remove_fd(fd_ctl);
				return NULL;
			}

			ep = setup_ep(port_request, fd_ctl, fd_data, user, &modfun); 
			if(ep == NULL)
				return NULL;
			portno=ep_get_port(ep);
			add_fd(fd_data,data_type,ep);
			sun_in.sun_family = AF_UNIX;
			snprintf(sun_in.sun_path,sizeof(sun_in.sun_path),"%s/%03d.%d",ctl_socket,portno,fd_data);

			if ((unlink(sun_in.sun_path) < 0 && errno != ENOENT) ||
					bind(fd_data, (struct sockaddr *) &sun_in, sizeof(struct sockaddr_un)) < 0){
				printlog(LOG_ERR,"Binding to data socket %s",strerror(errno));
				close_ep(ep);
				return NULL;
			}
			if (geteuid() != 0)
				user = -1;
			if (user != -1)
				chmod(sun_in.sun_path,mode & 0700);
			else
				chmod(sun_in.sun_path,mode);
			if(chown(sun_in.sun_path,user,grp_owner) < 0) {
				printlog(LOG_ERR, "chown: %s", strerror(errno));
				unlink(sun_in.sun_path);
				close_ep(ep);
				return NULL;
			}

			n = write(fd_ctl, &sun_in, sizeof(sun_in));
			if(n != sizeof(sun_in)){
				printlog(LOG_WARNING,"Sending data socket name %s",strerror(errno));
				close_ep(ep);
				return NULL;
			}
			if (type==REQ_NEW_PORT0)
				setmgmtperm(sun_in.sun_path);
			return ep;
			break;
		default:
			printlog(LOG_WARNING,"Bad request type : %d", type);
			remove_fd(fd_ctl); 
			return NULL;
	}
}

static void handle_input(unsigned char type,int fd,int revents,void *arg)
{
	struct endpoint *ep=arg;
	if (type == data_type) {
		struct bipacket packet;
		int len;

		len=recv(fd, &(packet.p), sizeof(struct packet),0);
		if(len < 0){
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			printlog(LOG_WARNING,"Reading  data: %s",strerror(errno));
		}
		else if(len == 0) 
			printlog(LOG_WARNING,"EOF data port: %s",strerror(errno));
		else if(len >= ETH_HEADER_SIZE)
			handle_in_packet(ep, &(packet.p), len);
	}
	else if (type == wd_type) {
		char reqbuf[REQBUFLEN+1];
		union request *req=(union request *)reqbuf;
		int len;

		len = read(fd, reqbuf, REQBUFLEN);
		if (len < 0) {
			if(errno != EAGAIN && errno != EWOULDBLOCK){
				printlog(LOG_WARNING,"Reading request %s", strerror(errno));
				remove_fd(fd); 
			}
			return;
		} else if (len > 0) {
			reqbuf[len]=0;
			if(req->v1.magic == SWITCH_MAGIC){
				if(req->v3.version == 3) {
					ep=new_port_v1_v3(fd, req->v3.type, &(req->v3.sock));
					if (ep != NULL) {
						mainloop_set_private_data(fd,ep);
						setup_description(ep,strdup(req->v3.description));
					}
				}
				else if(req->v3.version > 2 || req->v3.version == 2) {
					printlog(LOG_ERR, "Request for a version %d port, which this "
							"vde_switch doesn't support", req->v3.version);
					remove_fd(fd); 
				}
				else {
					ep=new_port_v1_v3(fd, req->v1.type, &(req->v1.u.new_control.name));
					if (ep != NULL) {
						mainloop_set_private_data(fd,ep);
						setup_description(ep,strdup(req->v1.description));
					}
				}
			}
			else {
				printlog(LOG_WARNING,"V0 request not supported");
				remove_fd(fd); 
				return;
			}
		} else {
			if (ep != NULL)
				close_ep(ep);
			else
				remove_fd(fd);
		}
	}
	else /*if (type == ctl_type)*/ {
		struct sockaddr addr;
		socklen_t len;
		int new;

		len = sizeof(addr);
		new = accept(fd, &addr, &len);
		if(new < 0){
			printlog(LOG_WARNING,"accept %s",strerror(errno));
			return;
		}
		/*
			if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
			printlog(LOG_WARNING,"fcntl - setting O_NONBLOCK %s",strerror(errno));
			close(new);
			return;
		}*/

		add_fd(new,wd_type,NULL);
	}
}

static void cleanup(unsigned char type,int fd,void *arg)
{
	struct sockaddr_un clun;
	int test_fd;

	if (fd < 0) {
		if (!strlen(ctl_socket)) {
			/* ctl_socket has not been created yet */
			return;
		}
		if((test_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
			printlog(LOG_ERR,"socket %s",strerror(errno));
		}
		clun.sun_family=AF_UNIX;
		snprintf(clun.sun_path,sizeof(clun.sun_path),"%s/ctl",ctl_socket);
		if(connect(test_fd, (struct sockaddr *) &clun, sizeof(clun))){
			close(test_fd);
			if(unlink(clun.sun_path) < 0)
				printlog(LOG_WARNING,"Could not remove ctl socket '%s': %s", ctl_socket, strerror(errno));
			else if(rmdir(ctl_socket) < 0)
				printlog(LOG_WARNING,"Could not remove ctl dir '%s': %s", ctl_socket, strerror(errno));
		}
		else printlog(LOG_WARNING,"Cleanup not removing files");
	} else {
		if (type == data_type && arg != NULL) {
			int portno=ep_get_port(arg);
			snprintf(clun.sun_path,sizeof(clun.sun_path),"%s/%03d.%d",ctl_socket,portno,fd);
			unlink(clun.sun_path);
		}
		close(fd);
	}
}

#define DIRMODEARG	0x100

static struct option long_options[] = {
	{"sock", 1, 0, 's'},
	{"vdesock", 1, 0, 's'},
	{"unix", 1, 0, 's'},
	{"mod", 1, 0, 'm'},
	{"mode", 1, 0, 'm'},
	{"dirmode", 1, 0, DIRMODEARG},
	{"group", 1, 0, 'g'},
};

#define Nlong_options (sizeof(long_options)/sizeof(struct option));

static void usage(void)
{
	printf(
			"(opts from datasock module)\n"
			"  -s, --sock SOCK            control directory pathname\n"
			"  -s, --vdesock SOCK         Same as --sock SOCK\n"
			"  -s, --unix SOCK            Same as --sock SOCK\n"
			"  -m, --mode MODE            Permissions for the control socket (octal)\n"
			"      --dirmode MODE         Permissions for the sockets directory (octal)\n"
			"  -g, --group GROUP          Group owner for comm sockets\n"
			);
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	struct group *grp;
	switch (c) {
		case 's':
			if (!(rel_ctl_socket = strdup(optarg))) {
				fprintf(stderr, "Memory error while parsing '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'm':
			sscanf(optarg,"%o",&mode);
			break;
		case 'g':
			if (!(grp = getgrnam(optarg))) {
				fprintf(stderr, "No such group '%s'\n", optarg);
				exit(1);
			}
			grp_owner=grp->gr_gid;
			break;
		case DIRMODEARG:
			sscanf(optarg, "%o", &dirmode);
			break;
		default:
			outc=c;
	}
	return outc;
}

static void init(void)
{
	int connect_fd;
	struct sockaddr_un sun;
	int one = 1;

	/* Set up default modes */
	if (mode < 0 && dirmode < 0)
	{
		/* Default values */
		mode = 00600;    /* -rw------- for the ctl socket */
		dirmode = 02700; /* -rwx--S--- for the directory */
	}
	else if (mode >= 0 && dirmode < 0)
	{
		/* If only mode (-m) has been specified, we guess the dirmode from it,
		 * adding the executable bit where needed */

#		define ADDBIT(mode, conditionmask, add) ((mode & conditionmask) ? ((mode & conditionmask) | add) : (mode & conditionmask))

		dirmode = 02000 | /* Add also setgid */
			ADDBIT(mode, 0600, 0100) |
			ADDBIT(mode, 0060, 0010) |
			ADDBIT(mode, 0006, 0001);
	}
	else if (mode < 0 && dirmode >= 0)
	{
		/* If only dirmode (--dirmode) has been specified, we guess the ctl
		 * socket mode from it, turning off the executable bit everywhere */
		mode = dirmode & 0666;
	}

	if((connect_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		printlog(LOG_ERR,"Could not obtain a BSD socket: %s", strerror(errno));
		return;
	}
	if(setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		printlog(LOG_ERR,"Could not set socket options on %d: %s", connect_fd, strerror(errno));
		return;
	}
	if(fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Could not set O_NONBLOCK on connection fd %d: %s", connect_fd, strerror(errno));
		return;
	}
	/* resolve ctl_socket, eventually defaulting to standard paths */
	if (rel_ctl_socket == NULL) {
		rel_ctl_socket = (geteuid()==0)?VDESTDSOCK:VDETMPSOCK;
	}
	if (((mkdir(rel_ctl_socket, 0777) < 0) && (errno != EEXIST))) {
		fprintf(stderr,"Cannot create ctl directory '%s': %s\n",
			rel_ctl_socket, strerror(errno));
		exit(-1);
	}
	if (!vde_realpath(rel_ctl_socket, ctl_socket)) {
		fprintf(stderr,"Cannot resolve ctl dir path '%s': %s\n",
			rel_ctl_socket, strerror(errno));
		exit(1);
	}

	if(chown(ctl_socket,-1,grp_owner) < 0) {
		rmdir(ctl_socket);
		printlog(LOG_ERR, "Could not chown socket '%s': %s", sun.sun_path, strerror(errno));
		exit(-1);
	}
	if (chmod(ctl_socket, dirmode) < 0) {
		printlog(LOG_ERR,"Could not set the VDE ctl directory '%s' permissions: %s", ctl_socket, strerror(errno));
		exit(-1);
	}
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s/ctl",ctl_socket);
	if(bind(connect_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		if((errno == EADDRINUSE) && still_used(&sun)){
			printlog(LOG_ERR, "Could not bind to socket '%s/ctl': %s", ctl_socket, strerror(errno));
			exit(-1);
		}
		else if(bind(connect_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
			printlog(LOG_ERR, "Could not bind to socket '%s/ctl' (second attempt): %s", ctl_socket, strerror(errno));
			exit(-1);
	 	}
	} 
	chmod(sun.sun_path,mode);
	if(chown(sun.sun_path,-1,grp_owner) < 0) {
		printlog(LOG_ERR, "Could not chown socket '%s': %s", sun.sun_path, strerror(errno));
		exit(-1);
	}
	if(listen(connect_fd, 15) < 0){
		printlog(LOG_ERR,"Could not listen on fd %d: %s", connect_fd, strerror(errno));
		exit(-1);
	}
	ctl_type=add_type(&swmi,0);
	wd_type=add_type(&swmi,0);
	data_type=add_type(&swmi,1);
	add_fd(connect_fd,ctl_type,NULL);
}

static int showinfo(FILE *fd)
{
	printoutc(fd,"ctl dir %s",ctl_socket);
	printoutc(fd,"std mode 0%03o",mode);
	return 0;
}

static struct comlist cl[]={
	{"ds","============","DATA SOCKET MENU",NULL,NOARG},
	{"ds/showinfo","","show ds info",showinfo,NOARG|WITHFILE},
};

static void delep (int fd_ctl, int fd_data, void *descr)
{
	if (fd_data>=0) remove_fd(fd_data);
	if (fd_ctl>=0) remove_fd(fd_ctl);
	if (descr) free(descr);
}

void start_datasock(void)
{
	modfun.modname=swmi.swmname=MODULENAME;
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_input=handle_input;
	swmi.cleanup=cleanup;
	modfun.sender=send_datasock;
	modfun.delep=delep;
	ADDCL(cl);
	add_swm(&swmi);
}
