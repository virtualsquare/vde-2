/*
 * VDE - libvdeplug_vx modules 
 * Copyright (C) 2014 Renzo Davoli VirtualSquare
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
#include <string.h>
#include <libvdeplug.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "libvdeplug_mod.h"
#include "libvdeplug_vxhash.h"

#define STDPORTSTR "4879"
#define STDTTL 1
#define STDVNI 1
#define STDHASHSIZE 1023
#define STDEXPIRETIME 128

#define ETH_ALEN 6
#define ETH_HEADER_SIZE 14
#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))
#define hton24(p, v) { \
	p[0] = (((v) >> 16) & 0xFF); \
	p[1] = (((v) >> 8) & 0xFF); \
	p[2] = ((v) & 0xFF); \
}

struct eth_hdr {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

struct vxlan_hdr {
	unsigned char flags;
	unsigned char priv1[3];
	unsigned char id[3];
	unsigned char priv2[1];
};

static char *vde_vxlan_check(char *given_sockname);
static VDECONN *vde_vxlan_open(char *given_sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args);
static ssize_t vde_vxlan_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_vxlan_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_vxlan_datafd(VDECONN *conn);
static int vde_vxlan_ctlfd(VDECONN *conn);
static int vde_vxlan_close(VDECONN *conn);

struct vde_vxlan_conn {
	struct vdeplug_module *module;
	void *table;
	int hash_mask; // hash table size - 1. This must be 2^n-1 
	int vni;
	union {
		struct sockaddr vx;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} multiaddr;
	int multifd;
	int expiretime;
};

struct vdeplug_module vdeplug_vxlan={
	.flags=ONLY_BY_CHECK,
	.vde_check=vde_vxlan_check,
	.vde_open_real=vde_vxlan_open,
	.vde_recv=vde_vxlan_recv,
	.vde_send=vde_vxlan_send,
	.vde_datafd=vde_vxlan_datafd,
	.vde_ctlfd=vde_vxlan_ctlfd,
	.vde_close=vde_vxlan_close
};

static char *vde_vxlan_check(char *given_sockname) {
	static char tag[]="VXLAN:";
	static char atag[]="VXLAN/";
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0) {
		given_sockname[strlen(atag)-1]=':';
		return given_sockname+strlen(atag);
	}
	return NULL;
}

static VDECONN *vde_vxlan_open(char *given_sockname, char *descr,int interface_version,
		        struct vde_open_args *open_args)
{
	struct vde_vxlan_conn *newconn;
	struct addrinfo hints;
	struct addrinfo *result,*rp;
	int s;
	char *portstr;
	char *vnistr;
	char *sockname;
	struct sockaddr *multiaddr=NULL;
	int multifd=-1;
	int ttl=STDTTL;

	/* TODO a more complete parsing of options: hash table size */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_protocol = 0;          /* Any protocol */
	sockname=strsep(&given_sockname,":/");
	vnistr=strsep(&given_sockname,":/");
	if ((portstr=strsep(&given_sockname,":/")) == NULL)
		portstr=STDPORTSTR;
	s = getaddrinfo(sockname, portstr, &hints, &result);
	if (s < 0) {
		fprintf(stderr, "vxlan getaddrinfo: %s\n", gai_strerror(s));
		errno=ENOENT;
		return NULL;
	}

	/* TODO scan the list of results */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		switch (rp->ai_family) {
			case AF_INET6:
				// currently unsupported
				continue;
			case AF_INET: {
											struct sockaddr_in *addr=(struct sockaddr_in *)(rp->ai_addr);
											struct ip_mreq mc_req;
											multiaddr = (struct sockaddr *) addr;
											struct sockaddr_in bindaddr;
											int loop = 0;

											multifd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
											if (multifd < 0)
												return NULL;
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_TTL,
													&ttl, sizeof(ttl))) < 0) {
												close(multifd);
												multifd=-1;
												return NULL;
											}
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_LOOP,
													&loop, sizeof(loop))) < 0) {
												close(multifd);
												multifd=-1;
												return NULL;
											}
											memset(&bindaddr, 0, sizeof(bindaddr));
											bindaddr.sin_family      = AF_INET;
											bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
											bindaddr.sin_port        = addr->sin_port;
											if ((bind(multifd, (struct sockaddr *) &bindaddr, 
															sizeof(bindaddr))) < 0) {
												close(multifd);
												multifd=-1;
												continue;
											}
											mc_req.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
											mc_req.imr_interface.s_addr = htonl(INADDR_ANY);
											if ((setsockopt(multifd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
															&mc_req, sizeof(mc_req))) < 0) {
												close(multifd);
												multifd=-1;
												return NULL;
											}
										}
		}
	}
	if (multifd < 0)
		return NULL;

	if ((newconn=calloc(1,sizeof(struct vde_vxlan_conn)))==NULL)
	{
		errno=ENOMEM;
		close(multifd);
		return NULL;
	}

	newconn->module=&vdeplug_vxlan;
	newconn->hash_mask=STDHASHSIZE;
  newconn->table=vx_hash_init(AF_INET, newconn->hash_mask);
	newconn->vni=vnistr?atoi(vnistr):STDVNI;
	newconn->expiretime=STDEXPIRETIME;
	switch (multiaddr->sa_family) {
		case AF_INET:
			memcpy(&(newconn->multiaddr.v4), multiaddr, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			memcpy(&(newconn->multiaddr.v6), multiaddr, sizeof(struct sockaddr_in6));
			break;
	}
	newconn->multifd=multifd;
	return (VDECONN *) newconn;
}

static ssize_t vde_vxlan_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	struct vxlan_hdr vhdr;
	struct iovec iov[]={{&vhdr, sizeof(vhdr)},{buf, len}};
	struct msghdr msg;
	struct sockaddr_in6 sender;
	int retval;
	msg.msg_name=&sender;
	switch (vde_conn->multiaddr.vx.sa_family) {
		case AF_INET: msg.msg_namelen = sizeof(struct sockaddr_in);
									break;
		case AF_INET6: msg.msg_namelen = sizeof(struct sockaddr_in6);
									 break;
		default:
									 msg.msg_namelen = 0;
	}
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	msg.msg_control=NULL;
	msg.msg_control=0;
	msg.msg_flags=0;
	if (__builtin_expect(((retval=recvmsg(vde_conn->multifd, &msg, 0)
						-sizeof(struct vxlan_hdr))>ETH_HEADER_SIZE), 1)) {
		struct eth_hdr *ehdr=(struct eth_hdr *) buf;
		if (vhdr.flags != (1<<0) || ntoh24(vhdr.id) != vde_conn->vni)
		vx_find_in_hash_update(vde_conn->table, vde_conn->hash_mask,
				ehdr->src, 1, msg.msg_name, time(NULL));
		return retval;
	}
	return 0;
}

static ssize_t vde_vxlan_send(VDECONN *conn,const void *buf, size_t len,int flags) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	struct vxlan_hdr vhdr;
	struct iovec iov[]={{&vhdr, sizeof(vhdr)},{(char *)buf, len}};
	struct sockaddr *destaddr;
	static struct msghdr msg;
	int retval;
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	struct eth_hdr *ehdr=(struct eth_hdr *) buf;
	if (len < ETH_HEADER_SIZE)
		return len; // discard packets shorter than an ethernet header
	if (IS_BROADCAST(ehdr->dest) || 
			(destaddr=vx_find_in_hash(vde_conn->table, vde_conn->multiaddr.vx.sa_family,
				vde_conn->hash_mask, ehdr->dest, 1, time(NULL)- vde_conn->expiretime)) == NULL)
		/* MULTICAST */
		msg.msg_name = &(vde_conn->multiaddr.vx);
	else
		/* UNICAST */
		msg.msg_name = destaddr;
	switch (vde_conn->multiaddr.vx.sa_family) {
		case AF_INET: msg.msg_namelen = sizeof(struct sockaddr_in);
									break;
		case AF_INET6: msg.msg_namelen = sizeof(struct sockaddr_in6);
									 break;
		default:
									 msg.msg_namelen = 0;
	}
	memset(&vhdr, 0, sizeof(vhdr));
	vhdr.flags = (1 << 3);

	hton24(vhdr.id, vde_conn->vni);

	if ((retval=sendmsg(vde_conn->multifd, &msg, 0)) < 0)
		return -1;
	retval -= sizeof(struct vxlan_hdr);
	if (retval < 0)
		retval = 0;
	return retval;
}

static int vde_vxlan_datafd(VDECONN *conn) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	return vde_conn->multifd;
}

static int vde_vxlan_ctlfd(VDECONN *conn) {
	return -1;
}

static int vde_vxlan_close(VDECONN *conn) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	close(vde_conn->multifd);
	vx_hash_fini(vde_conn->table);
	free(vde_conn);
	return 0;
}
