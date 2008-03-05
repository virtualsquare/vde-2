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
#include <grp.h>
#define _GNU_SOURCE
#include <getopt.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

#include <port.h>
#include <switch.h>
#include <sockutils.h>
#include <consmgmt.h>

static struct swmodule swmi;
static struct mod_support modfun;
static unsigned int ctl_type;
static unsigned int wd_type;
static unsigned int data_type;
static int mode = 0700;

static char *ctl_socket;
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
};

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[];
};

union request {
	struct request_v1 v1;
	struct request_v3 v3;
};

static int send_datasock(int fd, int ctl_fd, void *packet, int len, void *data, int port)
{
	int n;
	struct sockaddr *dst=(struct sockaddr *)data;

	n = len - sendto(fd, packet, len, 0, dst, sizeof(struct sockaddr_un));
	if(n){
		int rv=errno;
#ifndef VDE_PQ
		if(errno != EAGAIN) printlog(LOG_WARNING,"send_sockaddr port %d: %s",port,strerror(errno));
#endif
		if (n>len)
			return -rv;
		else
			return n;
	}
	return 0;
}

static void closeport(int fd, int portno)
{
	if (fd>0) 
		remove_fd(fd);
}

static int newport(int fd, int portno)
{
	int data_fd;
	struct sockaddr_un sun;
#ifdef VDE_DARWIN
	int sockbufsize = DATA_BUF_SIZE;
	int optsize = sizeof(sockbufsize);
#endif
	
	if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
		printlog(LOG_ERR,"socket: %s",strerror(errno));
		return -1;
	}
	if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Setting O_NONBLOCK on data fd %s",strerror(errno));
		return -1;
	}

#ifdef VDE_DARWIN
	if(setsockopt(data_fd, SOL_SOCKET, SO_SNDBUF, &sockbufsize, optsize) < 0)
		printlog(LOG_WARNING, "Warning: setting send buffer size on data fd %d to %d failed, expect packet loss: %s",
				data_fd, sockbufsize, strerror(errno));
	if(setsockopt(data_fd, SOL_SOCKET, SO_RCVBUF, &sockbufsize, optsize) < 0)
		printlog(LOG_WARNING, "Warning: setting send buffer size on data fd %d to %d failed, expect packet loss: %s",
				data_fd, sockbufsize, strerror(errno));
#endif
	
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s/%03d",ctl_socket,portno);
	if ((unlink(sun.sun_path) < 0 && errno != ENOENT) ||
			bind(data_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		printlog(LOG_ERR,"Binding to data socket %s",strerror(errno));
		close_ep(portno-1,fd);
		return -1;
	}
	chmod(sun.sun_path,mode);
	if(chown(sun.sun_path,-1,grp_owner) < 0) {
		printlog(LOG_ERR, "chown: %s", strerror(errno));
		close_ep(portno-1,fd);
		return -1;
	}

	add_fd(data_fd,data_type,portno);

	return data_fd;
}

static void *memdup(void *src,int size)
{
	void *dst=malloc(size);
	if (dst != NULL) 
		memcpy(dst,src,size);
	return dst;
}

#define GETFILEOWNER(PATH) ({\
		struct stat s; \
		(stat((PATH),&s)?-1:s.st_uid); \
		})

static int checksockperm(char *path,char *lpath)
{
	int rvuid=0;
	if (access(path,R_OK | W_OK) != 0)
		return -1;
	if (geteuid() == 0) { /* switch run by root */
		int luid;
		if ((rvuid=GETFILEOWNER(path)) < 0)
			return -1;
		luid=GETFILEOWNER(lpath);
		if (luid > 0 && luid != rvuid) {
			errno=EADDRINUSE;
			return -1;
		}
	}
	return rvuid;
}

static int new_port_v1_v3(int fd, int type_port,
		struct sockaddr_un *sun_out)
{
	int n, port;
	enum request_type type = type_port & 0xff;
	int port_request=type_port >> 8;
	int cluid=-1;
	struct sockaddr_un sun_in;
	switch(type){
		case REQ_NEW_PORT0:
			port_request= -1;
			/* no break: falltrough */
		case REQ_NEW_CONTROL:
			port = setup_ep(port_request, fd, memdup(sun_out,sizeof(struct sockaddr_un)), &modfun); 
			if(port<0) {
				remove_fd(fd); 
				return -1;
			}
			sun_in.sun_family = AF_UNIX;
			snprintf(sun_in.sun_path,sizeof(sun_in.sun_path),"%s/%03d",ctl_socket,port);
			if (sun_out->sun_path[0] != 0) { //not for unnamed sockets
				if ((cluid=checksockperm(sun_out->sun_path,sun_in.sun_path)) < 0) {
					printlog(LOG_WARNING,"Data_out socket permission: %s",strerror(errno));
					close_ep(port,fd);
					return -1;
				}
			}
			n = write(fd, &sun_in, sizeof(sun_in));
			if(n != sizeof(sun_in)){
				printlog(LOG_WARNING,"Sending data socket name %s",strerror(errno));
				close_ep(port,fd);
				return -1;
			}
			if (type==REQ_NEW_PORT0)
				setmgmtperm(sun_in.sun_path);
			else if (cluid > 0) {
				chown(sun_in.sun_path,cluid,-1);
				chmod(sun_in.sun_path,mode & 0700);
			}
			return port;
			break;
		default:
			printlog(LOG_WARNING,"Bad request type : %d", type);
			remove_fd(fd); 
			return -1;
	}
}

static void handle_input(unsigned char type,int fd,int revents,int *arg)
{
	if (type == data_type) {
		struct bipacket packet;
		struct sockaddr sock;
		int len;
		socklen_t socklen = sizeof(sock);

		len=recvfrom(fd, &(packet.p), sizeof(struct packet),0, &sock, &socklen);
		if(len < 0){
			if (errno == EAGAIN) return;
			printlog(LOG_WARNING,"Reading  data: %s",strerror(errno));
		}
		else if(len == 0) 
			printlog(LOG_WARNING,"EOF data port: %s",strerror(errno));
		else if(len >= ETH_HEADER_SIZE)
			handle_in_packet(*arg, &(packet.p), len);
	}
	else if (type == wd_type) {
		char reqbuf[REQBUFLEN+1];
		union request *req=(union request *)reqbuf;
		int len;

		len = read(fd, reqbuf, REQBUFLEN);
		if (len < 0) {
			if(errno != EAGAIN){
				printlog(LOG_WARNING,"Reading request %s", strerror(errno));
				remove_fd(fd); 
			}
			return;
		} else if (len > 0) {
			reqbuf[len]=0;
			if(req->v1.magic == SWITCH_MAGIC){
				int port=-1;
				if(req->v3.version == 3) {
					port=new_port_v1_v3(fd, req->v3.type, &(req->v3.sock));
					if (port>=0) {
						*arg=port;
						setup_description(*arg,fd,strdup(req->v3.description));
					}
				}
				else if(req->v3.version > 2 || req->v3.version == 2) {
					printlog(LOG_ERR, "Request for a version %d port, which this "
							"vde_switch doesn't support", req->v3.version);
					remove_fd(fd); 
				}
				else {
					*arg=port=new_port_v1_v3(fd, req->v1.type, &(req->v1.u.new_control.name));
					setup_description(*arg,fd,strdup(req->v1.description));
				}
			}
			else {
				printlog(LOG_WARNING,"V0 request not supported");
				remove_fd(fd); 
				return;
			}
		} else {
			if (*arg >= 0)
				close_ep(*arg,fd);
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
		if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
			printlog(LOG_WARNING,"fcntl - setting O_NONBLOCK %s",strerror(errno));
			close(new);
			return;
		}

		add_fd(new,wd_type,-1);
	}
}

static void cleanup(unsigned char type,int fd,int arg)
{
	struct sockaddr_un clun;
	int test_fd;

	if (fd < 0) {
		if((test_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
			printlog(LOG_ERR,"socket %s",strerror(errno));
		}
		clun.sun_family=AF_UNIX;
		snprintf(clun.sun_path,sizeof(clun.sun_path),"%s/ctl",ctl_socket);
		if(connect(test_fd, (struct sockaddr *) &clun, sizeof(clun))){
			close(test_fd);
			if(unlink(clun.sun_path) < 0)
				printlog(LOG_WARNING,"Couldn't remove ctl socket '%s' : %s", ctl_socket, strerror(errno));
			else if(rmdir(ctl_socket) < 0)
				printlog(LOG_WARNING,"Couldn't remove ctl dir '%s' : %s", ctl_socket, strerror(errno));
		}
		else printlog(LOG_WARNING,"cleanup not removing files");
	} else {
		if (type == data_type && arg>=0) {
			snprintf(clun.sun_path,sizeof(clun.sun_path),"%s/%03d",ctl_socket,arg);
			unlink(clun.sun_path);
		}
		close(fd);
	}
}

static struct option long_options[] = {
	{"sock", 1, 0, 's'},
	{"vdesock", 1, 0, 's'},
	{"unix", 1, 0, 's'},
	{"mod", 1, 0, 'm'},
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
			"  -m, --mod MODE             Standard access mode for comm sockets (octal)\n"
			"  -g, --group GROUP          Group owner for comm sockets\n"
			);
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	struct group *grp;
	switch (c) {
		case 's':
			ctl_socket=strdup(optarg);
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

	if((connect_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		printlog(LOG_ERR,"socket: %s",strerror(errno));
		return;
	}
	if(setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		printlog(LOG_ERR,"setsockopt: %s",strerror(errno));
		return;
	}
	if(fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Setting O_NONBLOCK on connection fd: %s",strerror(errno));
		return;
	}
	if (((mkdir(ctl_socket, 0777) < 0) && (errno != EEXIST))){
		printlog(LOG_ERR,"creating vde ctl dir: %s",strerror(errno));
		exit(-1);
	}
	if ((chmod(ctl_socket, 02000 | (mode & 0700 ? 0700 : 0) | (mode & 0070 ? 0070 : 0) | (mode & 0007 ? 0005 : 0)) < 0)) {
		printlog(LOG_ERR,"setting up vde ctl dir: %s",strerror(errno));
		exit(-1);
	}
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s/ctl",ctl_socket);
	if(bind(connect_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		if((errno == EADDRINUSE) && still_used(&sun)){
			printlog(LOG_ERR, "bind %s", strerror(errno));
			exit(-1);
		}
		else if(bind(connect_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
			printlog(LOG_ERR,"bind %s",strerror(errno));
			exit(-1);
	 	}
	} 
	chmod(sun.sun_path,mode);
	if(chown(sun.sun_path,-1,grp_owner) < 0) {
		printlog(LOG_ERR, "chown: %s", strerror(errno));
		exit(-1);
	}
	if(listen(connect_fd, 15) < 0){
		printlog(LOG_ERR,"listen: %s",strerror(errno));
		exit(-1);
	}
	ctl_type=add_type(&swmi,0);
	wd_type=add_type(&swmi,0);
	data_type=add_type(&swmi,1);
	add_fd(connect_fd,ctl_type,-1);
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

static void delep (int fd, void* data, void *descr)
{
	if (fd>=0) remove_fd(fd);
	if (data) free(data);
	if (descr) free(descr);
}

void start_datasock(void)
{
	ctl_socket = (geteuid()==0)?VDESTDSOCK:VDETMPSOCK;
	modfun.modname=swmi.swmname=MODULENAME;
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_input=handle_input;
	swmi.cleanup=cleanup;
	modfun.sender=send_datasock;
	modfun.newport=newport;
	modfun.delep=delep;
	modfun.delport=closeport;
	ADDCL(cl);
	add_swm(&swmi);
}
