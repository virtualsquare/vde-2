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

#include "../vde_switch/switch.h"
#include "sockutils.h"
#include "consmgmt.h"

/* will be inserted in a af_ipn.h include */
#ifndef AF_IPN
#define AF_IPN    34  /* IPN sockets      */
#define PF_IPN    AF_IPN
#endif
#define AF_IPN_STOLEN    AF_NETBEUI  /* IPN temporary sockets      */
#define PF_IPN_STOLEN    AF_IPN_STOLEN

#define IPN_ANY 0
#define IPN_BROADCAST 1
#define IPN_HUB 1
#define IPN_VDESWITCH 2
#define IPN_VDESWITCH_L3 3

#define IPN_SO_PREBIND 0x80
#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#define IPN_SO_CHANGE_NUMNODES 2
#define IPN_SO_HANDLE_OOB 3
#define IPN_SO_WANT_OOB_NUMNODES 4
#define IPN_SO_MTU (IPN_SO_PREBIND | 0)
#define IPN_SO_NUMNODES (IPN_SO_PREBIND | 1)
#define IPN_SO_MSGPOOLSIZE (IPN_SO_PREBIND | 2)
#define IPN_SO_FLAGS (IPN_SO_PREBIND | 3)
#define IPN_SO_MODE (IPN_SO_PREBIND | 4)

#define IPN_PORTNO_ANY -1

#define IPN_DESCRLEN 128

#define IPN_FLAG_LOSSLESS 1
#define IPN_FLAG_TERMINATED 0x1000

#define IPN_NODEFLAG_TAP   0x10    /* This is a tap interface */
#define IPN_NODEFLAG_GRAB  0x20    /* This is a grab of a real interface */

/* Ioctl defines */
#define IPN_SETPERSIST_NETDEV   _IOW('I', 200, int) 
#define IPN_CLRPERSIST_NETDEV   _IOW('I', 201, int) 
#define IPN_CONN_NETDEV          _IOW('I', 202, int) 
#define IPN_JOIN_NETDEV          _IOW('I', 203, int) 
#define IPN_SETPERSIST           _IOW('I', 204, int) 

static struct swmodule swmi;
static unsigned int ctl_type;
static int mode = 0700;

static char real_ctl_socket[PATH_MAX];
static char *ctl_socket = real_ctl_socket;
static gid_t grp_owner = -1;

#define MODULENAME "kernel module interface"

static void handle_input(unsigned char type,int fd,int revents,int *arg)
{
	/*here OOB messages will be delivered for debug options */
}

static void cleanup(unsigned char type,int fd,int arg)
{
	unlink(ctl_socket);
}

static struct option long_options[] = {
	{"sock", 1, 0, 's'},
	{"vdesock", 1, 0, 's'},
	{"unix", 1, 0, 's'},
	{"mod", 1, 0, 'm'},
	{"group", 1, 0, 'g'},
	{"tap", 1, 0, 't'},
	{"grab", 1, 0, 'g'},

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
	    "  -t, --tap TAP           Enable routing through TAP tap interface\n"
	    "  -G, --grab INT          Enable routing grabbing an existing interface\n");
}

struct extinterface {
	  char type;
		  char *name;
			  struct extinterface *next;
};

static struct extinterface *extifhead;
static struct extinterface **extiftail=&extifhead;

static void addextinterface(char type,char *name)
{
	struct extinterface *new=malloc(sizeof (struct extinterface));
	if (new) {
		new->type=type;
		new->name=strdup(name);
		new->next=NULL;
		*extiftail=new;
		extiftail=&(new->next);
	}
}

static void runextinterfaces(int kvdefd)
{
	struct extinterface *iface,*oldiface;
	struct ifreq ifr;
	for (iface=extifhead;iface != NULL;iface=oldiface)
	{
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name,iface->name,IFNAMSIZ);
		if (iface->type == 't')
			ifr.ifr_flags=IPN_NODEFLAG_TAP;
		else
			ifr.ifr_flags=IPN_NODEFLAG_GRAB;
		//  printf("ioctl\n");
		if (ioctl(kvdefd, IPN_CONN_NETDEV, (void *) &ifr) < 0) {
			printlog(LOG_ERR, "%s interface %s error: %s", iface->name,
					(iface->type == 't')?"tap":"grab",strerror(errno));
			exit(-1);
		}
		free(iface->name);
		oldiface=iface->next;
		free(iface);
	}
	extifhead=NULL;
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	struct group *grp;
	switch (c) {
		case 's':
			/* This should returns NULL as the path probably does not exist */
			realpath(optarg, ctl_socket);
			break;
		case 'm':
			sscanf(optarg,"%o",&mode);
			break;
		case 'g':
			if (!(grp = getgrnam(optarg))) {
				printlog(LOG_ERR, "No such group '%s'", optarg);
				exit(1);
			}
			grp_owner=grp->gr_gid;
			break;
		case 't':
		case 'G':
			addextinterface(c,optarg);
			break;
		default:
			outc=c;
	}
	return outc;
}

static void init(void)
{
	int kvdefd;
	struct sockaddr_un sun;
	int family = AF_IPN;
	kvdefd = socket(AF_IPN,SOCK_RAW,IPN_VDESWITCH);
	if (kvdefd < 0) {
		family=AF_IPN_STOLEN;
		kvdefd = socket(AF_IPN_STOLEN,SOCK_RAW,IPN_VDESWITCH);
		if (kvdefd < 0) {
			printlog(LOG_ERR,"kvde_switch requires ipn and kvde_switch kernel modules loaded");
			exit(-1);
		}
	}
	sun.sun_family = family;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",ctl_socket);
	if(bind(kvdefd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		printlog(LOG_ERR,"cannot bind socket %s",ctl_socket);
		exit(-1);
	}
	if(chmod(ctl_socket, mode) <0) {
		printlog(LOG_ERR, "chmod: %s", strerror(errno));
		exit(1);
	}
	if(chown(ctl_socket,-1,grp_owner) < 0) {
		printlog(LOG_ERR, "chown: %s", strerror(errno));
		exit(1);
	}
	runextinterfaces(kvdefd);
	add_fd(kvdefd,ctl_type,-1);
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

/*
static void delep (int fd, void* data, void *descr)
{
	if (fd>=0) remove_fd(fd);
	if (data) free(data);
	if (descr) free(descr);
}
*/

void start_datasock(void)
{
	ctl_socket = (geteuid()==0)?VDESTDSOCK:VDETMPSOCK;
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_input=handle_input;
	swmi.cleanup=cleanup;
	ADDCL(cl);
	add_swm(&swmi);
}
