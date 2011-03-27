/* Copyright 2005 Renzo Davoli - VDE-2
 * --pidfile/-p and cleanup management by Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005 (OSX tuntap support)
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "port.h"
#include "switch.h"
#include "consmgmt.h"

#ifdef HAVE_TUNTAP

#ifdef VDE_LINUX
#include <net/if.h>
#include <linux/if_tun.h>
#endif

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
#define TAP_PREFIX "/dev/"
#endif

#define MAXCMD 128
#define MODULENAME "tuntap"

static struct swmodule swmi;
static struct mod_support modfun;
static unsigned int tap_type;

struct init_tap {
	char *tap_dev;
	struct init_tap *next;
};

struct init_tap *hinit_tap=NULL;

static int send_tap(int fd_ctl, int fd_data, void *packet, int len, int port)
{
	int n;

	n = len - write(fd_ctl, packet, len);
	if(n){
		int rv=errno;
#ifndef VDE_PQ
		if(errno != EAGAIN && errno != EWOULDBLOCK) 
			printlog(LOG_WARNING,"send_tap port %d: %s",port,strerror(errno));
#endif
		if (n > len)
			return -rv;
		else
			return n;
	}
	return 0;
}

static void handle_io(unsigned char type,int fd,int revents,void *private_data)
{
	struct endpoint *ep=private_data;
	struct bipacket packet;
	int len=read(fd, &(packet.p), sizeof(struct packet));

	if(len < 0){
		if(errno != EAGAIN && errno != EWOULDBLOCK) 
			printlog(LOG_WARNING,"Reading tap data: %s",strerror(errno));
	}
	else if(len == 0) {
		if(errno != EAGAIN && errno != EWOULDBLOCK) 
			printlog(LOG_WARNING,"EOF tap data port: %s",strerror(errno));
		/* close tap! */
	} else if (len >= ETH_HEADER_SIZE)
		handle_in_packet(ep, &(packet.p), len);
}


static void cleanup(unsigned char type,int fd,void *private_data)
{
	if (fd >= 0)
		close(fd);
}

static struct option long_options[] = {
	{"tap", 1, 0, 't'},
};
#define Nlong_options (sizeof(long_options)/sizeof(struct option));

static void usage(void)
{
	printf(
			"(opts from tuntap module)\n"
			"  -t, --tap TAP              Enable routing through TAP tap interface\n"
#ifdef VDE_DARWIN
			"                             TAP can be an absolute file name or a relative\n"
			"                             one (and will be prefixed with %s). The TAP\n"
			"                             device must already exist.\n", TAP_PREFIX
#endif
			);
}

static struct init_tap *add_init_tap(struct init_tap *p,char *arg)
{
	if (p == NULL) {
		p=malloc(sizeof(struct init_tap));
		if (p==NULL)
			printlog(LOG_WARNING,"Malloc Tap init:%s\n",strerror(errno));
		else {
			p->tap_dev=strdup(optarg);
			p->next=NULL;
		}
	} else
		p->next=add_init_tap(p->next,arg);
	return(p);
}

static struct init_tap *free_init_tap(struct init_tap *p)
{
	if (p != NULL) {
		free_init_tap(p->next);
		free(p);
	}
	return NULL;
}

static int parseopt(int c, char *optarg)
{
	int outc=0;
	switch (c) {
		case 't': 
			hinit_tap=add_init_tap(hinit_tap,optarg);
			break;
		default:
			outc=c;
	}
	return outc;
}

#ifdef VDE_LINUX
int open_tap(char *dev)
{
	struct ifreq ifr;
	int fd;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0){
		printlog(LOG_ERR,"Failed to open /dev/net/tun %s",strerror(errno));
		return(-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
	/*printf("dev=\"%s\", ifr.ifr_name=\"%s\"\n", ifr.ifr_name, dev);*/
	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0){
		printlog(LOG_ERR,"TUNSETIFF failed %s",strerror(errno));
		close(fd);
		return(-1);
	}
#ifdef VDE_PQ
	/* tuntap should be "fast", but if there is a packetq we can manage
		 a tuntap which is "not fast enough" */
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
	return(fd);
}
#endif

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
int open_tap(char *dev)
{
	int fd;
	int prefixlen = strlen(TAP_PREFIX);
	char *path = NULL;
	if (*dev == '/')
		fd=open(dev, O_RDWR);
	else
	{
		path = malloc(strlen(dev) + prefixlen + 1);
		if (path != NULL)
		{ 
			snprintf(path, strlen(dev) + prefixlen + 1, "%s%s", TAP_PREFIX, dev);
			fd=open(path, O_RDWR);
			free(path);
		}
		else
			fd = -1;
	}
	
	if (fd < 0)
	{
		printlog(LOG_ERR,"Failed to open tap device %s: %s", (*dev == '/') ? dev : path, strerror(errno));
		return(-1);
	}
	return fd;
}
#endif

static struct endpoint *newtap(char *dev)
{
	int tap_fd;
	tap_fd = open_tap(dev);
	if (tap_fd>0) {
		struct endpoint *ep=setup_ep(0,tap_fd,tap_fd,-1,&modfun);
		if (ep != NULL) {
			setup_description(ep,dev);
			add_fd(tap_fd,tap_type,ep);
		} 
		return ep;
	} else
		return NULL;
}

static void init(void)
{
	if(hinit_tap != NULL) {
		struct init_tap *p;
		tap_type=add_type(&swmi,1);
		for(p=hinit_tap;p != NULL;p=p->next) {
			if (newtap(p->tap_dev) == NULL)
				printlog(LOG_ERR,"ERROR OPENING tap interface: %s",p->tap_dev);
		}
		hinit_tap=free_init_tap(hinit_tap);
	}
}

static void delep (int fd_ctl, int fd_data, void *descr)
{
	if (fd_ctl>=0)
		remove_fd(fd_ctl);
	if (descr) free(descr);
}

void start_tuntap(void)
{
	modfun.modname=swmi.swmname=MODULENAME;
	swmi.swmnopts=Nlong_options;
	swmi.swmopts=long_options;
	swmi.usage=usage;
	swmi.parseopt=parseopt;
	swmi.init=init;
	swmi.handle_io=handle_io;
	swmi.cleanup=cleanup;
	modfun.sender=send_tap;
	modfun.delep=delep;
	add_swm(&swmi);
}

#endif
