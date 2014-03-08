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
#include <time.h>
#include <sys/epoll.h>
#define __USE_GNU
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "libvdeplug_mod.h"
#include "libvdeplug_vxhash.h"
/* two alternatives to check whether an ip addr is local:
LOCALBIND: try to open and bind a socket to the same addr (any port), if it succeeds it is local!
!LOCALBIND: use getifaddrs and look through the list */

//#define LOCALBIND
#ifndef LOCALBIND
#include <ifaddrs.h>
#endif

//#define DEBUGADDR
#define STDPORTSTR "14879"
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

union sockaddr46 {
	struct sockaddr vx;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct vde_vxvde_conn {
	struct vdeplug_module *module;
	void *table;
	int hash_mask; // hash table size - 1. This must be 2^n-1 
	int vni;
	union sockaddr46 multiaddr;
	union sockaddr46 localaddr; 
	in_port_t multiport;
	in_port_t uniport;
	int multifd;
	int unifd;
	int pollfd;
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

static inline socklen_t fam2socklen(void *sockaddr)
{
	struct sockaddr *s=sockaddr;
	switch (s->sa_family) {
		case AF_INET: return sizeof(struct sockaddr_in);
		case AF_INET6: return sizeof(struct sockaddr_in6);
		default: return 0;
	}
}

static int is_a_localaddr(void *sockaddr)
{
	struct sockaddr *s=sockaddr;
	int retval=0;
#ifdef LOCALBIND
	switch (s->sa_family) {
		case AF_INET: {
										int tmpfd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
										if (tmpfd >= 0) {
											struct sockaddr_in s4=*((struct sockaddr_in *)s);
											s4.sin_port = 0;
											if (bind(tmpfd, (struct sockaddr *) &s4, sizeof(s4))==0)
												retval=1;
											close(tmpfd);
										}
									}
									break;
		case AF_INET6: {
										 int tmpfd=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
										 if (tmpfd >= 0) {
											 struct sockaddr_in6 s6=*((struct sockaddr_in6 *)s);
											 s6.sin6_port = 0;
											 if (bind(tmpfd, (struct sockaddr *) &s6, sizeof(s6))==0)
												 retval=1;
											 close(tmpfd);
										 }
									 }
									 break;
	}
#else /* GETIFADDRS */
	struct ifaddrs *addrs;
	if (getifaddrs(&addrs) == 0) {
		struct ifaddrs *ifa;
		for (ifa = addrs; ifa != NULL && retval == 0; ifa = ifa->ifa_next){
			if (s->sa_family == ifa->ifa_addr->sa_family) {
				switch (s->sa_family) {
					case AF_INET: {
													struct sockaddr_in *s6=(struct sockaddr_in *)s;
													struct sockaddr_in *i6=(struct sockaddr_in *)ifa->ifa_addr;
													if (s6->sin_addr.s_addr == i6->sin_addr.s_addr)
														retval=1;
												 }
												 break;
					case AF_INET6: {
													struct sockaddr_in6 *s6=(struct sockaddr_in6 *)s;
													struct sockaddr_in6 *i6=(struct sockaddr_in6 *)ifa->ifa_addr;
													if (memcmp(&s6->sin6_addr,&i6->sin6_addr,sizeof(struct in6_addr)) == 0)
														retval=1;
												 }
												 break;
				}
			}
		}
		freeifaddrs(addrs);
	}
#endif
	return retval;
}

#ifdef DEBUGADDR
static inline void printaddr(char *msg, void *sockaddr)
{
	struct sockaddr *s=sockaddr;
	struct sockaddr_in *s4=sockaddr;
	struct sockaddr_in6 *s6=sockaddr;
	char saddr[INET6_ADDRSTRLEN];
	switch (s->sa_family) {
		case AF_INET: 
			fprintf(stderr,"%s %s\n",msg,inet_ntop(AF_INET, &s4->sin_addr, saddr, sizeof(*s4)));     
			break;
		case AF_INET6: 
			fprintf(stderr,"%s %s\n",msg,inet_ntop(AF_INET6, &s6->sin6_addr, saddr, sizeof(*s6)));     
			break;
		default:
			fprintf(stderr,"%s UNKNOWN FAMILY %d\n",msg,s->sa_family);     
			break;
	}
}
#endif

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
	sockname=strsep(&given_sockname,"/");
	vnistr=strsep(&given_sockname,"/");
	if ((portstr=strsep(&given_sockname,"/")) == NULL)
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
			case AF_INET6: {
											 struct sockaddr_in6 *addr=(struct sockaddr_in6 *)(rp->ai_addr);
											 struct ipv6_mreq mc_req;
											 struct sockaddr_in6 bindaddr;
											 socklen_t bindaddrlen;
											 int one = 1;
											 multiaddr = (struct sockaddr *) addr;

											 if ((multifd=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												 goto error;
											 if ((unifd=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												 goto error;
											 if ((setsockopt(unifd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
															 &ttl, sizeof(ttl))) < 0)
												 goto error;
											 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
															 &one, sizeof(one))) < 0)
												 goto error;
#ifdef SO_REUSEPORT
											 if ((setsockopt(multifd, SOL_SOCKET, SO_REUSEPORT,
															 &one, sizeof(one))) < 0)
												 goto error;
#endif
											 memset(&bindaddr, 0, sizeof(bindaddr));
											 bindaddr.sin6_family      = AF_INET6;
											 memcpy(&bindaddr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
											 bindaddr.sin6_port        = addr->sin6_port;
											 if ((bind(multifd, (struct sockaddr *) &bindaddr,
															 sizeof(bindaddr))) < 0) {

												 close(multifd);
												 close(unifd);
												 multifd=unifd=-1;
												 continue;
											 }
											 memcpy(&mc_req.ipv6mr_multiaddr, &addr->sin6_addr, 
													 sizeof(addr->sin6_addr));
											 mc_req.ipv6mr_interface = 0;
											 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
															 &mc_req, sizeof(mc_req))) < 0)
												 goto error;
											 bindaddr.sin6_port        = 0;
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
											 uniport=bindaddr.sin6_port;
										 }
										 break;
			case AF_INET: {
											struct sockaddr_in *addr=(struct sockaddr_in *)(rp->ai_addr);
											struct ip_mreqn mc_req;
											struct sockaddr_in bindaddr;
											socklen_t bindaddrlen;
											int one = 1;
											multiaddr = (struct sockaddr *) addr;

											if ((multifd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												goto error;
											if ((unifd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
												goto error;
											if ((setsockopt(unifd, IPPROTO_IP, IP_MULTICAST_TTL,
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
										}
										break;
			default:
										uniport=0;
		}
	}
	freeaddrinfo(result);
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
			memcpy(&(newconn->localaddr.v4), multiaddr, sizeof(struct sockaddr_in));
			newconn->multiport = newconn->multiaddr.v4.sin_port;
			break;
		case AF_INET6:
			memcpy(&(newconn->multiaddr.v6), multiaddr, sizeof(struct sockaddr_in6));
			memcpy(&(newconn->localaddr.v6), multiaddr, sizeof(struct sockaddr_in6));
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
			struct sockaddr_storage sender;
			socklen_t senderlen=sizeof(sender);
			retval = recvfrom(vde_conn->unifd, buf, len, 0, 
					(struct sockaddr *) &sender, &senderlen);
			//fprintf(stderr, "<- unicast packet len %d\n",retval);
			//printaddr("recv uni",&sender);
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
			struct sockaddr_storage sender;
			char cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo)+sizeof(struct in_pktinfo))];
			int retval;
			msg.msg_name=&sender;
			msg.msg_namelen = sizeof(sender);
			msg.msg_iov=iov;
			msg.msg_iovlen=2;
			msg.msg_control=cmsg;
			msg.msg_controllen=sizeof(cmsg);
			msg.msg_flags=0;
			retval=recvmsg(vde_conn->multifd, &msg, 0)-sizeof(struct vxvde_hdr);
			//fprintf(stderr, "<- multicast packet len %d\n",retval);
			//printaddr("recv multi",&sender);
			if (__builtin_expect((retval > ETH_HEADER_SIZE), 1)) {
				struct eth_hdr *ehdr=(struct eth_hdr *) buf;
				if (vhdr.flags != (1<<3) || ntoh24(vhdr.id) != vde_conn->vni) {
					//fprintf(stderr,"wrong net id or flags: rejected \n");
					goto error;
				}
				switch (sender.ss_family) {
					case AF_INET: {
													struct sockaddr_in *sender4=(struct sockaddr_in *)&sender;
													if (sender4->sin_port == vde_conn->uniport) {
														struct cmsghdr *cmsgptr=CMSG_FIRSTHDR(&msg);
														struct in_pktinfo *pki=(struct in_pktinfo *)(CMSG_DATA(cmsgptr));
														if (sender4->sin_addr.s_addr == pki->ipi_spec_dst.s_addr) {
															//fprintf(stderr,"self packet, rejected \n");
															goto error;
														}
													}
												}
					case AF_INET6: {
													 /* workaround: there is not (yet) an ancillary msg for IPv6 returning
															the IP address of the local interface where the packet was received,
															i.e. the IPV6 counterpart of ipi_spec_dst	*/
													struct sockaddr_in6 *sender6=(struct sockaddr_in6 *)&sender;
													if (sender6->sin6_port == vde_conn->uniport) {
														if (memcmp(&sender6->sin6_addr, &vde_conn->localaddr.v6.sin6_addr,
																	sizeof(struct in6_addr)) == 0) {
															//fprintf(stderr,"self packet short path, rejected \n");
															goto error;
														} 
														else if (is_a_localaddr(sender6)) {
															memcpy(&vde_conn->localaddr, sender6, sizeof(struct sockaddr_in6));
															//fprintf(stderr,"self packet long path, rejected \n");
															goto error;
														}
													}
												 }
				}
				vx_find_in_hash_update(vde_conn->table, vde_conn->hash_mask,
						ehdr->src, 1, msg.msg_name, time(NULL));
				return retval;
			}
			goto error;
		}
	} 
error:
	errno = EAGAIN;
	*((unsigned char *)buf)=0;
	return 1;
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
		struct vxvde_hdr vhdr;
		struct iovec iov[]={{&vhdr, sizeof(vhdr)},{(char *)buf, len}};
		struct msghdr msg;
		int retval;
		destaddr=&(vde_conn->multiaddr.vx);
		msg.msg_iov=iov;
		msg.msg_iovlen=2;
		msg.msg_name = destaddr;
		msg.msg_namelen = fam2socklen(destaddr);
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		//printaddr("send multi",destaddr);
		memset(&vhdr, 0, sizeof(vhdr));
		vhdr.flags = (1 << 3);

		hton24(vhdr.id, vde_conn->vni);

		if ((retval=sendmsg(vde_conn->unifd, &msg, 0)) < 0)
			return -1;
		retval -= sizeof(struct vxvde_hdr);
		if (retval < 0)
			retval = 0;
		return retval;
	} else {
		socklen_t destlen = fam2socklen(destaddr);
		//printaddr("send uni",destaddr);
		return sendto(vde_conn->unifd, buf, len, 0, destaddr, destlen);
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
	close(vde_conn->unifd);
	close(vde_conn->multifd);
	vx_hash_fini(vde_conn->table);
	free(vde_conn);
	return 0;
}
