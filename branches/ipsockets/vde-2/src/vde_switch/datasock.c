/* Copyright 2005 Renzo Davoli - VDE-2
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
 * -g option (group management) by Daniel P. Berrange
 * dir permission patch by Alessio Caprari 2006
 *
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
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
#include <sys/un.h>
#include <net/if.h>
#include <stdarg.h>
#include <limits.h>
#include <grp.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <pwd.h>
#include <netdb.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

//#include <netinet/in.h>
#include <arpa/inet.h>

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
#define	IPSOCK_FILE_FIELD_LEN	256
#define	MAXDESCR  128

int use_ip_sockets = 0;
static char data_eth_dev[ETH_DEV_LEN] = "eth0";

/* Function Prototypes */
static void cleanup_ipsock(unsigned char type,int fd,void *arg);
static void cleanup_unixsock(unsigned char type,int fd,void *arg);

static void init_ipsock(void);
static void init_unixsock(void);

static struct endpoint * new_port_v1_v3_ipsock(int fd, int type_port,
		struct sockaddr_in *sip_out);
static struct endpoint * new_port_v1_v3_unixsock(int fd, int type_port,
		struct sockaddr_un *sun_out);

static int read_ctl_socket_file(char *sock_filename, char *server_name,
		int *server_port);

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v1 {
	uint32_t magic;
	enum request_type type;
	union {
		struct {
			unsigned char addr[ETH_ALEN];
			union {
				struct sockaddr_in name_in;
				struct sockaddr_un name_un;
			} socket;
		} new_control;
	} u;
	char description[];
} __attribute__((packed));

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
 	union {
 		struct sockaddr_in sock_in;
 		struct sockaddr_un sock_un;
 	} socket;
	char description[];
} __attribute__((packed));

union request {
	struct request_v1 v1;
	struct request_v3 v3;
};

static int send_datasock(int fd_ctl, int fd_data, void *packet, int len, int port)
{
	if (send(fd_data, packet, len, 0) < 0) {
		int rv=errno;
		if(rv != EAGAIN && rv != EWOULDBLOCK)
			printlog(LOG_WARNING,"send_sockaddr port %d: %s",port,strerror(errno));
		else
			rv=EWOULDBLOCK;
		return -rv;
	}
	return 0;
}

static inline uid_t get_file_owner(char *path)
{
		struct stat s;
		return ((stat((path),&s)?-1:s.st_uid));
}

static struct endpoint *new_port_v1_v3_ipsock(int fd_ctl, int type_port,
		struct sockaddr_in *sip_out)
{
	int n, portno;
	struct endpoint *ep;
	enum request_type type = type_port & 0xff;
	int port_request = type_port >> 8;
	uid_t user = -1;
	int fd_data;
#ifdef VDE_DARWIN
	int sockbufsize = DATA_BUF_SIZE;
	int optsize = sizeof(sockbufsize);
#endif
	struct sockaddr_in sip_in;
	struct sockaddr sockinfo;
	socklen_t sockinfo_sz;

	// init sun_in memory
	memset(&sip_in, 0, sizeof(sip_in));

	switch (type){
		case REQ_NEW_PORT0: /* For IP sockets, it has no significance */
			/* no break: falltrough */
		case REQ_NEW_CONTROL:
			if((fd_data = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
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
			if(setsockopt(fd_data, SOL_SOCKET, SO_SNDBUF,
				&sockbufsize, optsize) < 0)
				printlog(LOG_WARNING, "Warning: setting send "
				"buffer size on data fd %d to %d failed, expect "
				"packet loss: %s", fd_data, sockbufsize,
				strerror(errno));
			if(setsockopt(fd_data, SOL_SOCKET, SO_RCVBUF,
				&sockbufsize, optsize) < 0)
				printlog(LOG_WARNING, "Warning: setting send "
				"buffer size on data fd %d to %d failed, "
				" expect packet loss: %s", fd_data, sockbufsize,
				strerror(errno));
#endif

			if (connect(fd_data, (struct sockaddr *)sip_out,
				sizeof(struct sockaddr_in)) < 0) {
				printlog(LOG_ERR,"Connecting to client data socket %s",strerror(errno));
				close(fd_data);
				remove_fd(fd_ctl);
				return NULL;
			}

			ep = setup_ep(port_request, fd_ctl, fd_data, user, &modfun); 
			if(ep == NULL)
				return NULL;

			portno = ep_get_port(ep);
			add_fd(fd_data, data_type, ep);

			/*
			 * Get th local IP to which we are bound, and pass that
			 * information back as the IP of the data socket.
			 */
			sockinfo_sz = sizeof(sockinfo);
			if (getsockname(fd_data, &sockinfo, &sockinfo_sz ) < 0 ) {
				perror("getsockname error: ");
				close_ep(ep);
				return NULL;
			}
			get_port_ip_info(portno, &sip_in);
			sip_in.sin_family = AF_INET;
			sip_in.sin_addr = ((struct sockaddr_in *)&sockinfo)->sin_addr;

			n = write(fd_ctl, &sip_in, sizeof(sip_in));
			if(n != sizeof(sip_in)){
				printlog(LOG_WARNING,"Sending data socket name %s",
					strerror(errno));
				close_ep(ep);
				return NULL;
			}
			return ep;
			break;
		default:
			printlog(LOG_WARNING,"Bad request type : %d", type);
			remove_fd(fd_ctl); 
			return NULL;
	}
}

static struct endpoint *new_port_v1_v3_unixsock(int fd_ctl, int type_port,
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
	// init sun_in memory
	memset(&sun_in,0,sizeof(sun_in));
	switch (type){
		case REQ_NEW_PORT0:
			port_request= -1;
			/* no break: falltrough */
		case REQ_NEW_CONTROL:
			if (sun_out->sun_path[0] != 0) { //not for unnamed sockets
				if (access(sun_out->sun_path,R_OK | W_OK) != 0) { //socket error
					remove_fd(fd_ctl);
					return NULL;
				}
				user=get_file_owner(sun_out->sun_path);
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

static void handle_io(unsigned char type,int fd,int revents,void *arg)
{
	struct endpoint *ep=arg;
	if (type == data_type) {
#ifdef VDE_PQ2
		if (revents & POLLOUT)
			handle_out_packet(ep);
#endif
		if (revents & POLLIN) {
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
					if (use_ip_sockets == 0) {
						ep=new_port_v1_v3_unixsock(fd, req->v3.type,
							&(req->v3.socket.sock_un));
					} else {
						ep=new_port_v1_v3_ipsock(fd, req->v3.type,
							&(req->v3.socket.sock_in));
					}
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
					if (use_ip_sockets == 0) {
						ep=new_port_v1_v3_unixsock(fd, req->v1.type,
							&(req->v1.u.new_control.socket.name_un));
					} else {
						ep=new_port_v1_v3_ipsock(fd, req->v1.type,
							&(req->v1.u.new_control.socket.name_in));
					}
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
			if (ep) {
				printlog(LOG_WARNING,"Closing endpoint");
				close_ep(ep);
			} else {
				remove_fd(fd);
			}
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
	if (use_ip_sockets != 0)
		return cleanup_ipsock(type, fd, arg);
	else
		return cleanup_unixsock(type, fd, arg);
}

static void cleanup_ipsock(unsigned char type,int fd,void *arg)
{
	struct sockaddr_in cip;
	int	test_fd;
	char	sock_filename[PATH_MAX];
	char	server[IPSOCK_FILE_FIELD_LEN];
	int	port;

	if (fd < 0) {
		if((test_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			printlog(LOG_ERR,"socket %s",strerror(errno));
		}

		snprintf(sock_filename, PATH_MAX, "%s/ctl", ctl_socket);
		if (read_ctl_socket_file(sock_filename, server, &port) != 0) {
			printlog(LOG_ERR, "Cleanup: Could not open CTL file: %s",
				sock_filename);
		}
		cip.sin_family=AF_INET;
    	/* short, network byte order */
	    cip.sin_port = htons(port);
    	/* automatically fill with my IP */
	    cip.sin_addr.s_addr = INADDR_ANY;
    	/* zero the rest of the struct */
	    memset(&(cip.sin_zero), '\0', 8);

		if(connect(test_fd, (struct sockaddr *) &cip, sizeof(cip))){
			close(test_fd);
		} else printlog(LOG_WARNING,"Connection failed: %s:%d\n",
			server, port);

		if (unlink(sock_filename) < 0)
			printlog(LOG_WARNING,"Could not remove ctl file '%s': %s",
				sock_filename, strerror(errno));
		if(rmdir(ctl_socket) < 0) {
			printlog(LOG_WARNING,"Could not remove ctl dir '%s': %s",
				ctl_socket, strerror(errno));
		} else
			printlog(LOG_INFO, "VDE_SWITCH clean up successful %s", ctl_socket);
	} else {
		/* We are closing individual switch ports */
		close(fd);
	}
}

static void cleanup_unixsock(unsigned char type,int fd,void *arg)
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
	{"ip", 1, 0, 'i'},
	{"mod", 1, 0, 'm'},
	{"mode", 1, 0, 'm'},
	{"dirmode", 1, 0, DIRMODEARG},
	{"group", 1, 0, 'g'},
	{"eth", 1, 0, 'e'},
};

#define Nlong_options (sizeof(long_options)/sizeof(struct option));

static void usage(void)
{
	printf(
			"(opts from datasock module)\n"
			"  -s, --sock SOCK            control directory pathname\n"
			"  -s, --vdesock SOCK         Same as --sock SOCK\n"
			"  -s, --unix SOCK            Same as --sock SOCK\n"
			"  -i, --ip SOCK              Use IP sockets\n"
			"  -m, --mode MODE            Permissions for the control socket (octal)\n"
			"      --dirmode MODE         Permissions for the sockets directory (octal)\n"
			"  -g, --group GROUP          Group owner for comm sockets\n"
			"  -e, --eth DEV              eth device to use\n"
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
		case 'i':
			if (!(rel_ctl_socket = strdup(optarg))) {
				fprintf(stderr, "Memory error while parsing '%s'\n", optarg);
				exit(1);
			}
			use_ip_sockets = 1;
			break;
		case 'e':
			strncpy(data_eth_dev, optarg, sizeof(data_eth_dev)-1);
			data_eth_dev[sizeof(data_eth_dev)-1] = '\0';
			if (strcmp(data_eth_dev, optarg) != 0) {
				fprintf(stderr, "Length of eth interface (%s) > maxlen: %d\n",
					optarg, ETH_DEV_LEN);
				exit( -1);
			}
			break;
		default:
			outc=c;
	}
	return outc;
}

#define ADDBIT(mode, conditionmask, add) ((mode & conditionmask) ? \
	((mode & conditionmask) | add) : (mode & conditionmask))

static void init(void)
{
	if (use_ip_sockets != 0)
		return init_ipsock();
	else
		return init_unixsock();
}

static void init_ipsock(void)
{
	int connect_fd;
	struct sockaddr_in sip;
	int one = 1;
	FILE	*fp;
	char	filename[PATH_MAX];

	struct ifreq ifr;

	printlog(LOG_INFO, "VDE_SWITCH ctl using IP sockets (%s)", ctl_socket);

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

	/* resolve ctl_socket, eventually defaulting to standard paths */
	if (rel_ctl_socket == NULL) {
		rel_ctl_socket = (geteuid()==0)?VDESTDSOCK:VDETMPSOCK;
	}

	/* Actually Creating the ctrl directory */
	if (((mkdir(rel_ctl_socket, 0777) < 0) && (errno != EEXIST))){
		printlog(LOG_ERR,"Could not create the VDE ctl directory '%s': %s",
			rel_ctl_socket, strerror(errno));
		exit(-1);
	}

	if (!vde_realpath(rel_ctl_socket, ctl_socket)) {
		fprintf(stderr,"Cannot resolve ctl dir path '%s': %s\n",
			rel_ctl_socket, strerror(errno));
		exit(1);
	}

	if(chown(ctl_socket, -1, grp_owner) < 0) {
		rmdir(ctl_socket);
		printlog(LOG_ERR, "Could not chown socket '%s': %s",
			ctl_socket, strerror(errno));
		exit(-1);
	}

	if (chmod(ctl_socket, dirmode) < 0) {
		printlog(LOG_ERR,"Could not set the VDE ctl directory '%s' permissions: %s",
			ctl_socket, strerror(errno));
		exit(-1);
	}

	if((connect_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printlog(LOG_ERR,"Could not obtain a IP socket: %s",
			strerror(errno));
		return;
	}

	if(setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		printlog(LOG_ERR,"Could not set socket options on %d: %s",
			connect_fd, strerror(errno));
		return;
	}

	if(fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Could not set O_NONBLOCK on connection fd %d: %s",
			connect_fd, strerror(errno));
		return;
	}

	strncpy(ifr.ifr_name, data_eth_dev, IFNAMSIZ);
	/* Get the IP address of the eth device specified */
	if (ioctl(connect_fd, SIOCGIFADDR, &ifr) == -1) {
		printlog(LOG_ERR,"Could not find eth: %s", data_eth_dev);
		exit( -1);
	}

	sip.sin_family = AF_INET;
	sip.sin_port = 0; /* automatically fill with my PORT */
	memcpy(&(sip.sin_addr.s_addr), (void *)&(ifr.ifr_addr.sa_data[2]), 4);
	/* zero the rest of the struct */
	memset(&(sip.sin_zero), '\0', 8);

	if(bind(connect_fd, (struct sockaddr *) &sip, sizeof(sip)) < 0){
		if((errno == EADDRINUSE) && still_used_ipsock(&sip)){
			printlog(LOG_ERR, "Could not bind to socket: %s",
				strerror(errno));
			exit(-1);
		}
		else if(bind(connect_fd, (struct sockaddr *) &sip, sizeof(sip)) < 0){
			printlog(LOG_ERR, "Could not bind to socket (second attempt): %s",
				strerror(errno));
			exit(-1);
	 	}
	}
	if(listen(connect_fd, 15) < 0){
		printlog(LOG_ERR,"Could not listen on fd %d: %s",
			connect_fd, strerror(errno));
		exit(-1);
	}
	ctl_type=add_type(&swmi,0);
	wd_type=add_type(&swmi,0);
	data_type=add_type(&swmi,1);

	/*
	 * Get the IP and port information for this switch
	 */
	fd2ip(connect_fd, &sip);
	snprintf(filename, PATH_MAX, "%s/ctl",ctl_socket);
	if ((fp = fopen(filename, "w")) == NULL) {
		printlog(LOG_ERR, "Could not open CTL file for writting: %s",
			filename);
		exit(-1);
	}
	fprintf(fp, "IP:\t%s\n", inet_ntoa(sip.sin_addr));
	fprintf(fp, "PORT:\t%d\n", ntohs(sip.sin_port));
	fclose(fp);
	chmod(filename, mode);
	if(chown(filename, -1, grp_owner) < 0) {
		printlog(LOG_ERR, "Could not chown socket file '%s': %s",
			filename, strerror(errno));
		exit(-1);
	}
	add_fd(connect_fd, ctl_type, NULL);
}

static void init_unixsock(void)
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

/*
 * Below functions are used for connecting two VDE switches together
 */
static int connect_remote_ctl_sock(FILE *fp, char *server_name, int server_port,
	int *ctl_sock)
{
	struct sockaddr_in *sockaddr=NULL;
	struct hostent *host;

	if((*ctl_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printoutc(fp, "CTL-FD SOCKET error");
		printlog(LOG_ERR, "CTL-FD SOCKET error");
		return (errno);
	}

	if ((sockaddr=(struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in)))
			==NULL) {
		return(ENOMEM);
	}
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(server_port);
	host = gethostbyname(server_name);
	if (host == NULL) {
		printoutc(fp, "Remote server %s not found", server_name);
		printlog(LOG_ERR, "Remote server %s not found", server_name);
		free(sockaddr);
		return(ENETUNREACH);
	}

	sockaddr->sin_addr = *((struct in_addr *)host->h_addr);
	if (connect(*ctl_sock, (struct sockaddr *) sockaddr,
		sizeof(*sockaddr)) != 0) {
		printoutc(fp, "Connection to %s:%d failed",
			server_name, server_port);
		printlog(LOG_ERR, "Connection to %s:%d failed",
			server_name, server_port);
		free(sockaddr);
		return(EHOSTUNREACH);
	}

	free(sockaddr);
	return (0);
}

/*
 * connect_remote_data_sock
 *
 * Main connecting function where handshake between two vde switches happen
 */
static	int connect_remote_data_sock(FILE *fp, int ctl_sock, char *server_name,
	int server_port)
{
	struct	request_v3 *req = NULL;
	struct	sockaddr_in dataout;
	struct sockaddr sockinfo;
	socklen_t sockinfo_sz;
	struct passwd *callerpwd;
	char	local_server_name[IPSOCK_FILE_FIELD_LEN];
	int	local_server_port;
	char	sock_filename[PATH_MAX];
	char	*remote_description = NULL;
	int	rc;
	int	pid = getpid();
	struct endpoint *ep = NULL;
	int	fd_data;

	/*
	 * Create a data port for actual data packet transmission
	 */
	if((fd_data = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		printlog(LOG_ERR,"socket: %s",strerror(errno));
		rc = EIO;
		goto con_rdsock_err;
	}

	if(fcntl(fd_data, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Setting O_NONBLOCK on data fd %s",strerror(errno));
		close(fd_data);
		rc = EIO;
		goto con_rdsock_err;
	}

	memset(&dataout, 0, sizeof(dataout));
	dataout.sin_family = AF_INET;
	/* automatically fill with my IP & PORT*/
	dataout.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd_data, (struct sockaddr *) &dataout, sizeof(dataout)) < 0) {
		printlog(LOG_ERR,"Binding to data socket %s",strerror(errno));
		rc = EIO;
		goto con_rdsock_err;
	}

	/*
	 * We need to send this information to the remote switch so that it can
	 * establish a connection with us here.
	 */
	if ((req=(struct request_v3 *)calloc(1, sizeof(struct request_v3)
		+ MAXDESCR)) == NULL) {
		rc = ENOMEM;
		goto con_rdsock_err;
	}

	callerpwd=getpwuid(getuid());
	req->type = REQ_NEW_CONTROL;
	req->magic = SWITCH_MAGIC;
	req->version = 3;
	req->type = req->type + (0 << 8);

	/*
	 * Get the local data port to which we are bound, and pass that
	 * information to the remote switch.
	 */
	fd2ip(fd_data, &(req->socket.sock_in));

	/*
	 * Get th local control socket IP to which we are bound, and pass
	 * that information to the switch as the IP of the data socket too.
	 */
	sockinfo_sz = sizeof(sockinfo);
	if (getsockname(ctl_sock, &sockinfo, &sockinfo_sz ) < 0 ) {
		printoutc(fp, "getsockname error (IP)\n");
		printlog(LOG_ERR, "getsockname error (IP)\n");
		rc = EINVAL;
		goto con_rdsock_err;
	}
	req->socket.sock_in.sin_addr = ((struct sockaddr_in *)&sockinfo)->sin_addr;
	req->socket.sock_in.sin_family = AF_INET;

	printlog(LOG_DEBUG, "Sending information:\n");
	printlog(LOG_DEBUG, "\tIPADDR: %s\n", inet_ntoa(req->socket.sock_in.sin_addr));
	printlog(LOG_DEBUG, "\tPORT: %d\n", ntohs(req->socket.sock_in.sin_port));
	printlog(LOG_DEBUG, "-END-\n");

	snprintf(sock_filename, PATH_MAX, "%s/ctl", ctl_socket);
	if (read_ctl_socket_file(sock_filename, local_server_name,
		&local_server_port) != 0) {
		printoutc(fp, "Could not read ctl file: '%s'", sock_filename);
		printlog(LOG_ERR, "Could not read ctl file: '%s'", sock_filename);
		rc = EIO;
		goto con_rdsock_err;
	}

	/* Description of us to the remote switch */
	snprintf(req->description,MAXDESCR,"%s user=%s PID=%d IP=%s PORT=%d RVDE=%s:%d",
			"VDE-SWITCH",(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid, inet_ntoa(req->socket.sock_in.sin_addr),
			ntohs(req->socket.sock_in.sin_port),
			local_server_name, local_server_port);

	if (send(ctl_sock, req, sizeof(*req) +
		strlen(req->description), 0) < 0) {
		printoutc(fp, "SEND error");
		printlog(LOG_ERR, "SEND error");
		rc = EINVAL;
		goto con_rdsock_err;
	}

	/*
	 * After sending our information, we wait to get the remote switch
	 * information. This gets freed when the endpoint gets closed.
	 */
	if (recv(ctl_sock, &dataout, sizeof(struct sockaddr_in),0) < 0)  {
		printoutc(fp, "RECV error");
		printlog(LOG_ERR, "RECV error");
		rc = EINVAL;
		goto con_rdsock_err;
	}

	printlog(LOG_DEBUG, "Received information:\n");
	printlog(LOG_DEBUG, "\tIPADDR: %s\n", inet_ntoa(dataout.sin_addr));
	printlog(LOG_DEBUG, "\tPORT: %d\n", ntohs(dataout.sin_port));
	printlog(LOG_DEBUG, "-END-\n");

	/* This gets freed when the endpoint gets closed. */
	if ((remote_description = (char *)calloc(1, MAXDESCR)) == NULL) {
		rc = ENOMEM;
		goto con_rdsock_err;
	}

	ep = setup_ep(0, ctl_sock, 0, 0, &modfun);
	if (ep == NULL) {
		rc = ENOMEM;
		goto con_rdsock_err;
	}

	/* Description of the remote switch to which we are connected */
	snprintf(remote_description,MAXDESCR,"* %s user=%s PID=%d IP=%s PORT=%d RVDE=%s:%d",
			"VDE-SWITCH",(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid, inet_ntoa(dataout.sin_addr), ntohs(dataout.sin_port),
			server_name, server_port);

	setup_description(ep, remote_description);

	if (connect(fd_data, (struct sockaddr *)&dataout,
		sizeof(struct sockaddr_in)) < 0) {
		printlog(LOG_ERR,"Connecting to client data socket %s",strerror(errno));
		close(fd_data);
		rc = EIO;
		goto con_rdsock_err;
	}

	setup_destination(ep, fd_data);
	add_fd(ctl_sock, ctl_type, ep);
	add_fd(fd_data, data_type, ep);

	free(req);
	return (0);

con_rdsock_err:
	if (ep) close_ep(ep);
	if (req) free(req);
	if (remote_description) free (remote_description);
	return(rc);
}

static int connect2remoteswitch(FILE *fp, char *server_name, int server_port)
{
	int	ctl_sock;
	int	ec;

	if((ec = connect_remote_ctl_sock(fp, server_name, server_port, &ctl_sock)) != 0)
		return (ec);

	if((ec = connect_remote_data_sock(fp, ctl_sock, server_name, server_port)) != 0) {
		close(ctl_sock);
		return (ec);
	}

	/*
	 * If control socket (ctl_sock) is closed, then remote switch will close
	 * the data sockets associated with this control socket. Therefore, do
	 * not close it
	 */
	return (0);
}

static int
get_server_port(FILE *fp, char *given_sockname, char *server_name, int *server_port)
{
	char	*gs = (char *)strdup(given_sockname);
	char	sock_filename[PATH_MAX];
	struct	stat st;
	char	*split;
	int	filetype;
	int	rc = 0;

	if(gs[strlen(gs)-1] == ']' &&
		(split=rindex(gs,'[')) != NULL) {
		*split = 0;
	}
	snprintf(sock_filename, PATH_MAX, "%s/ctl", gs);
	free(gs);
	if (stat(sock_filename, &st) != 0) {
		printoutc(fp, "Error accessing socket file: %s (%d)",
			sock_filename, errno);
		printlog(LOG_ERR, "Error accessing socket file: %s (%d)",
			sock_filename, errno);
		return (EIO);
	}
	filetype = st.st_mode & S_IFMT;

	switch (filetype) {
		case S_IFREG:
		/*
		 * If its a regular file, then the file contains the IP
		 * and port information where we need to connect to using
		 * IP sockets, instead of the default UNIX sockets.
		 */
			rc = read_ctl_socket_file(sock_filename, server_name,
				server_port);
			break;
		case S_IFSOCK:
			printoutc(fp, "Bridging is not supported for UNIX SOCKETS");
			printlog(LOG_ERR, "Bridging is not supported for UNIX SOCKETS");
			rc = EOPNOTSUPP;
			break;
		default:
			printoutc(fp, "Unsupported socket file type: %X", filetype);
			printlog(LOG_ERR, "Unsupported socket file type: %X", filetype);
			rc = EOPNOTSUPP;
			break;
	}
	return(rc);
}

static int switch_connect_ip_port (FILE *fp, char *server)
{
	int	remote_ctl_port, ec;
	char	*split;

	if ((split = rindex(server, ':')) == NULL) {
		printoutc(fp, "Invalid format: '%s'", server);
		return (EINVAL);
	}

	*split = 0;
	split++;
	remote_ctl_port = atoi(split);
	if((ec = connect2remoteswitch(fp, server, remote_ctl_port)) != 0)
		return (ec);

	printoutc(fp,"Connected to vde switch at %s:%d", server, remote_ctl_port);
	return (0);
}

static int switch_connect_ctl (FILE *fp, char *given_sockname)
{
	int	remote_ctl_port, ec;
	char	server[128];

	if ((ec = get_server_port(fp, given_sockname, server, &remote_ctl_port)) != 0)
		return (ec);

	if((ec = connect2remoteswitch(fp, server, remote_ctl_port)) != 0)
		return (ec);

	printoutc(fp,"Connected to vde switch at %s:%d", server, remote_ctl_port);
	return (0);
}
/* ------------------ END connecting two VDE switches ------------------ */

static struct comlist cl[]={
	{"ds","============","DATA SOCKET MENU",NULL,NOARG},
	{"ds/showinfo","","show ds info",showinfo,NOARG|WITHFILE},
	{"ds/connectvde/ip","server:port","connect to remote switch",switch_connect_ip_port,STRARG|WITHFILE},
	{"ds/connectvde/ctl","ctrl filename","connect to remote switch",switch_connect_ctl,STRARG|WITHFILE},
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
	swmi.handle_io=handle_io;
	swmi.cleanup=cleanup;
	modfun.sender=send_datasock;
	modfun.delep=delep;
	ADDCL(cl);
	add_swm(&swmi);
}
