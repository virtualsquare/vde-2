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
#include <sys/epoll.h>
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

struct vxvde_hdr {
	unsigned char flags;
	unsigned char priv1[3];
	unsigned char id[3];
	unsigned char priv2[1];
};

static char *vde_vxvde_check(char *given_sockname);
static VDECONN *vde_vxvde_open(char *given_sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args);
static ssize_t vde_vxvde_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_vxvde_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_vxvde_datafd(VDECONN *conn);
static int vde_vxvde_ctlfd(VDECONN *conn);
static int vde_vxvde_close(VDECONN *conn);

struct vde_vxvde_conn {
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
	int unifd;
	int pollfd;
	in_port_t multiport;
	in_port_t uniport;
	int expiretime;
};

struct vdeplug_module vdeplug_vxvde={
	.flags=ONLY_BY_CHECK,
	.vde_check=vde_vxvde_check,
	.vde_open_real=vde_vxvde_open,
	.vde_recv=vde_vxvde_recv,
	.vde_send=vde_vxvde_send,
	.vde_datafd=vde_vxvde_datafd,
	.vde_ctlfd=vde_vxvde_ctlfd,
	.vde_close=vde_vxvde_close
};

static char *vde_vxvde_check(char *given_sockname) {
	static char tag[]="VXVDE:";
	static char atag[]="VXVDE/";
	if (strncmp(given_sockname,tag,strlen(tag)) == 0)
		return given_sockname+strlen(tag);
	if (strncmp(given_sockname,atag,strlen(atag)) == 0) {
		given_sockname[strlen(atag)-1]=':';
		return given_sockname+strlen(atag);
	}
	return NULL;
}

static VDECONN *vde_vxvde_open(char *given_sockname, char *descr,int interface_version,
		        struct vde_open_args *open_args)
{
	struct vde_vxvde_conn *newconn=NULL;
	struct addrinfo hints;
	struct addrinfo *result,*rp;
	int s;
	char *portstr;
	char *vnistr;
	char *sockname;
	struct sockaddr *multiaddr=NULL;
	int multifd=-1;
	int unifd=-1;
	int pollfd=-1;
	int ttl=STDTTL;
	in_port_t uniport;

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
		fprintf(stderr, "vxvde getaddrinfo: %s\n", gai_strerror(s));
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
											struct ip_mreqn mc_req;
											multiaddr = (struct sockaddr *) addr;
											struct sockaddr_in bindaddr;
											socklen_t bindaddrlen;
											int one = 1;

											if ((multifd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												goto error;
											if ((unifd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												goto error;
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_TTL,
													&ttl, sizeof(ttl))) < 0) 
												goto error;
											int loop=0;
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_LOOP,
															&loop, sizeof(loop))) < 0) 
												goto error;
											if ((setsockopt(multifd, IPPROTO_IP, IP_PKTINFO,
													&one, sizeof(one))) < 0)
												goto error;
#ifdef SO_REUSEPORT
											if ((setsockopt(multifd, SOL_SOCKET, SO_REUSEPORT,
													&one, sizeof(one))) < 0) 
												goto error;
#endif
											memset(&bindaddr, 0, sizeof(bindaddr));
											memset(&bindaddr, 0, sizeof(bindaddr));
											bindaddr.sin_family      = AF_INET;
											bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
											bindaddr.sin_port        = addr->sin_port;
											if ((bind(multifd, (struct sockaddr *) &bindaddr, 
															sizeof(bindaddr))) < 0) {
												close(multifd);
												close(unifd);
												multifd=unifd=-1;
												continue;
											}
											mc_req.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
											mc_req.imr_address.s_addr = htonl(INADDR_ANY);
											mc_req.imr_ifindex = 0;
											if ((setsockopt(multifd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
															&mc_req, sizeof(mc_req))) < 0)
												goto error;
											bindaddr.sin_port        = 0;
											if ((bind(unifd, (struct sockaddr *) &bindaddr,
															sizeof(bindaddr))) < 0) {
												close(multifd);
												close(unifd);
												multifd=unifd=-1;
												continue;
											}
											bindaddrlen=sizeof(bindaddr);
											if (getsockname(unifd, (struct sockaddr *) &bindaddr,
														&bindaddrlen) < 0)
												goto error;
											uniport=bindaddr.sin_port;
											//fprintf(stderr,"local port %d\n",ntohs(bindaddr.sin_port));
											/*static char buf[]="test";
											socklen_t addrs=sizeof(struct sockaddr_in);
											sendto(unifd, buf, strlen(buf)+1, 0, (struct sockaddr *) addr, addrs);*/
										}
		}
	}
	if (multifd < 0)
		return NULL;

	if ((pollfd = epoll_create1(0)) < 0)
		goto error;
	else {
		struct epoll_event ev;
		ev.events = EPOLLIN;
		ev.data.fd = multifd;
		if (epoll_ctl(pollfd, EPOLL_CTL_ADD, multifd, &ev) < 0)
			goto error; 
		ev.data.fd = unifd;
		if (epoll_ctl(pollfd, EPOLL_CTL_ADD, unifd, &ev) < 0)
			goto error; 
	}

	if ((newconn=calloc(1,sizeof(struct vde_vxvde_conn)))==NULL) {
		errno=ENOMEM;
		goto error;
	}

	newconn->module=&vdeplug_vxvde;
	newconn->hash_mask=STDHASHSIZE;
  newconn->table=vx_hash_init(AF_INET, newconn->hash_mask);
	newconn->vni=vnistr?atoi(vnistr):STDVNI;
	newconn->expiretime=STDEXPIRETIME;
	switch (multiaddr->sa_family) {
		case AF_INET:
			memcpy(&(newconn->multiaddr.v4), multiaddr, sizeof(struct sockaddr_in));
			newconn->multiport = newconn->multiaddr.v4.sin_port;
			break;
		case AF_INET6:
			memcpy(&(newconn->multiaddr.v6), multiaddr, sizeof(struct sockaddr_in6));
			newconn->multiport = newconn->multiaddr.v6.sin6_port;
			break;
	}
	newconn->multifd=multifd;
	newconn->unifd=unifd;
	newconn->uniport=uniport;
	newconn->pollfd=pollfd;
	return (VDECONN *) newconn;

error:
	if (multifd >= 0) close(multifd);
	if (unifd >= 0) close(unifd);
	if (pollfd >= 0) close(pollfd);
	if (newconn != NULL) free(newconn);
	return NULL;
}

static ssize_t vde_vxvde_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_vxvde_conn *vde_conn = (struct vde_vxvde_conn *)conn;
	struct epoll_event events[1];
	int nfd = epoll_wait(vde_conn->pollfd, events, 1, 0);
	if (nfd > 0) {
		if (events[0].data.fd == vde_conn->unifd) {
			int retval;
			struct sockaddr_in sender;
			socklen_t senderlen=sizeof(sender);
			retval = recvfrom(vde_conn->unifd, buf, len, 0, 
					(struct sockaddr *) &sender, &senderlen);
			//fprintf(stderr, "<- unicast packet len %d\n",retval);
			if (__builtin_expect((retval > ETH_HEADER_SIZE), 1)) {
				struct eth_hdr *ehdr=(struct eth_hdr *) buf;
				vx_find_in_hash_update(vde_conn->table, vde_conn->hash_mask,
						ehdr->src, 1, (struct sockaddr *) &sender, time(NULL));
				return retval;
			} else 
				goto error;
		} else /*if (events[0].data.fd == vde_conn->multifd)*/ {
			struct vxvde_hdr vhdr;
			struct iovec iov[]={{&vhdr, sizeof(vhdr)},{buf, len}};
			struct msghdr msg;
			struct sockaddr_in sender;

			char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))+1024];
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
			msg.msg_control=cmsg;
			msg.msg_controllen=sizeof(cmsg);
			msg.msg_flags=0;
			retval=recvmsg(vde_conn->multifd, &msg, 0)-sizeof(struct vxvde_hdr);
			//fprintf(stderr, "<- multicast packet len %d\n",retval);
			if (__builtin_expect((retval > ETH_HEADER_SIZE), 1)) {
				struct eth_hdr *ehdr=(struct eth_hdr *) buf;
				if (sender.sin_port == vde_conn->uniport) {
					struct cmsghdr *cmsgptr=CMSG_FIRSTHDR(&msg);
					struct in_pktinfo *pki=(struct in_pktinfo*)(CMSG_DATA(cmsgptr));
					if (sender.sin_addr.s_addr == pki->ipi_spec_dst.s_addr) {
						//fprintf(stderr,"self packet, rejected \n");
						goto error;
					}
				}
				if (vhdr.flags != (1<<0) || ntoh24(vhdr.id) != vde_conn->vni)
					vx_find_in_hash_update(vde_conn->table, vde_conn->hash_mask,
							ehdr->src, 1, msg.msg_name, time(NULL));
				return retval;
			}
			/*
			struct cmsghdr *cmsgptr=CMSG_FIRSTHDR(&msg);
			struct in_pktinfo *pki=(struct in_pktinfo*)(CMSG_DATA(cmsgptr));
			fprintf(stderr,"%d %s ",msg.msg_controllen, inet_ntoa(pki->ipi_spec_dst));
			fprintf(stderr,"%s- ",inet_ntoa(pki->ipi_addr));
			fprintf(stderr,"%s port %d\n",inet_ntoa(sender.sin_addr),ntohs(sender.sin_port));
			*/
			goto error;
		}
	} 
error:
	errno = EAGAIN;
	*((unsigned char *)buf)=0;
	return 1;
}

static ssize_t vde_vxvde_vxsend(struct vde_vxvde_conn *vde_conn,
		struct sockaddr *destaddr, const void *buf, size_t len,int flags) {
	struct vxvde_hdr vhdr;
	struct iovec iov[]={{&vhdr, sizeof(vhdr)},{(char *)buf, len}};
	static struct msghdr msg;
	int retval;
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	msg.msg_name = destaddr;
	switch (destaddr->sa_family) {
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

	if ((retval=sendmsg(vde_conn->unifd, &msg, 0)) < 0)
		return -1;
	retval -= sizeof(struct vxvde_hdr);
	if (retval < 0)
		retval = 0;
	return retval;
}

static ssize_t vde_vxvde_send(VDECONN *conn,const void *buf, size_t len,int flags) {
	struct vde_vxvde_conn *vde_conn = (struct vde_vxvde_conn *)conn;
	struct eth_hdr *ehdr=(struct eth_hdr *) buf;
	struct sockaddr *destaddr;
	if (len < ETH_HEADER_SIZE)
		return len; // discard packets shorter than an ethernet header
	if (__builtin_expect(
				(IS_BROADCAST(ehdr->dest) ||
			(destaddr=vx_find_in_hash(vde_conn->table, vde_conn->multiaddr.vx.sa_family,
				vde_conn->hash_mask, ehdr->dest, 1, time(NULL)- vde_conn->expiretime)) == NULL),
			 0))	{
		return vde_vxvde_vxsend(vde_conn, &(vde_conn->multiaddr.vx), buf, len, flags);
	} else {
		socklen_t destlen;
		in_port_t destport;
		switch (destaddr->sa_family) {
			case AF_INET: destlen = sizeof(struct sockaddr_in);
										destport = ((struct sockaddr_in *) destaddr)->sin_port;
										break;
			case AF_INET6: destlen = sizeof(struct sockaddr_in6);
										destport = ((struct sockaddr_in6 *) destaddr)->sin6_port;
										 break;
			default:
										 destlen = 0;
										 destport = 0;
		}
		if (__builtin_expect(destport != vde_conn->multiport, 1)) {
			return sendto(vde_conn->unifd, buf, len, 0, destaddr, destlen);
		} else { /* compatibility with vxlan! */
			return vde_vxvde_vxsend(vde_conn, destaddr, buf, len, flags);
		}
	}
}

static int vde_vxvde_datafd(VDECONN *conn) {
	struct vde_vxvde_conn *vde_conn = (struct vde_vxvde_conn *)conn;
	return vde_conn->pollfd;
}

static int vde_vxvde_ctlfd(VDECONN *conn) {
	return -1;
}

static int vde_vxvde_close(VDECONN *conn) {
	struct vde_vxvde_conn *vde_conn = (struct vde_vxvde_conn *)conn;
	close(vde_conn->multifd);
	free(vde_conn);
	return 0;
}
