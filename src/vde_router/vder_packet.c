/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */

#include <config.h>

#include "vder_datalink.h"
#include "vder_arp.h"
#include "vder_icmp.h"
#include "vder_udp.h"
#include <sys/poll.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 2000

char *vder_ntoa(uint32_t addr)
{
	struct in_addr a;
	char *res;
	a.s_addr = addr;
	res = inet_ntoa(a);
	return res;
}

/*
 * Forward the ip packet to next hop. TTL is decreased,
 * checksum is set again for coherence, and TTL overdue
 * packets are not forwarded.
 */
int vder_ip_decrease_ttl(struct vde_buff *vdb){
	struct iphdr *iph=iphead(vdb);
	iph->ttl--;
	/* The caller (vder_packet_forward) recomputes the whole header checksum.
	 * The incremental update that used to live here was wrong anyway: a TTL
	 * decrement is a change in the high byte of a 16 bit word, so RFC 1624
	 * calls for adding 0x0100 in ones' complement, not for ++.
	 */
	if(iph->ttl < 1)
		return -1; /* TODO: send ICMP with TTL expired */
	else
		return 0;
}
/**
 * Calculate checksum of a given string
 */
uint16_t net_checksum(void *inbuf, int len)
{
	uint8_t *buf = (uint8_t *) inbuf;
	uint32_t sum = 0, carry=0;
	int i=0;
	for(i=0; i<len; i++){
		if (i%2){
			sum+=buf[i];
		}else{
			sum+=( buf[i] << 8);
		}
	}
	carry = (sum&0xFFFF0000) >>16;
	sum = (sum&0x0000FFFF);
	return (uint16_t) ~(sum + carry)  ;
}

/**
 * Calculate ip-header checksum. it's a wrapper for checksum();
 */
uint16_t vder_ip_checksum(struct iphdr *iph)
{
	iph->check = 0U;
	return net_checksum((uint8_t*)iph,sizeof(struct iphdr));
}

#define DEFAULT_TTL 64

int vder_ip_input(struct vde_buff *vb)
{
	struct iphdr *iph = iphead(vb);
	int recvd = 0;
	int is_broadcast = vder_ipaddress_is_broadcast(iph->daddr);

	if (!vder_ipaddress_is_local(iph->daddr) && !is_broadcast)
		return 0;

	switch(iph->protocol) {
		case PROTO_ICMP:
			vder_icmp_recv(vb);
			recvd=1;
			break;
		case PROTO_UDP:
			if (vder_udp_recv(vb) == 1)
				recvd=1;
			break;
	}
	if (!recvd && !is_broadcast)
		vder_icmp_service_unreachable((uint32_t)iph->saddr, footprint(vb));
	return 1;
}

int vder_packet_send(struct vde_buff *vdb, uint32_t dst_ip, uint8_t protocol)
{
	struct iphdr *iph=iphead(vdb);
	struct vde_ethernet_header *eth = ethhead(vdb);
	struct vder_route *ro;
	struct vder_arp_entry *ae;

	uint32_t destination = dst_ip;

	eth->buftype = htons(PTYPE_IP);

	memset(iph,0x45,1);
	iph->tos = 0;
	iph->frag_off=htons(0x4000); // Don't fragment.
	iph->tot_len = htons(vdb->len - sizeof(struct vde_ethernet_header));
	iph->id = 0;
	iph->protocol = protocol;
	iph->ttl = DEFAULT_TTL;
	iph->daddr = dst_ip;
	ro = vder_get_route(dst_ip);
	if (!ro)
		return -1;

	if (ro->gateway != 0) {
		destination = ro->gateway;
	}
	iph->saddr = vder_get_right_localip(ro->iface, destination);
	iph->check = htons(vder_ip_checksum(iph));
	ae = vder_get_arp_entry(ro->iface, destination);
	if (!ae) {
		vder_arp_query(ro->iface, destination);
		return -1;
	}
	return vder_sendto(ro->iface, vdb, ae->macaddr);
}

/**
 * Send a packet that is being routed, as opposed to one this router originated.
 *
 * vder_packet_send() builds a fresh IP header because it serves packets the
 * router itself creates: it overwrites saddr with one of our own addresses and
 * resets ttl, id, tos and frag_off.  Using it to forward rewrites the sender
 * out of the datagram, and since the L4 checksum still covers the original
 * address the packet is discarded downstream.
 *
 * Forwarding therefore only looks up the route and refreshes the IP checksum,
 * which the TTL decrement in the caller has just invalidated.
 */
int vder_packet_forward(struct vde_buff *vdb, uint32_t dst_ip)
{
	struct iphdr *iph = iphead(vdb);
	struct vde_ethernet_header *eth = ethhead(vdb);
	struct vder_route *ro;
	struct vder_arp_entry *ae;
	uint32_t destination = dst_ip;

	eth->buftype = htons(PTYPE_IP);

	ro = vder_get_route(dst_ip);
	if (!ro)
		return -1;
	if (ro->gateway != 0)
		destination = ro->gateway;

	iph->check = htons(vder_ip_checksum(iph));

	ae = vder_get_arp_entry(ro->iface, destination);
	if (!ae) {
		vder_arp_query(ro->iface, destination);
		return -1;
	}
	return vder_sendto(ro->iface, vdb, ae->macaddr);
}

int vder_packet_broadcast(struct vde_buff *vdb, struct vder_iface *iface, uint32_t dst_ip, uint8_t protocol)
{
	struct iphdr *iph=iphead(vdb);
	struct vde_ethernet_header *eth = ethhead(vdb);
	uint8_t bcast_macaddr[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	eth->buftype = htons(PTYPE_IP);

	memset(iph,0x45,1);
	iph->tos = 0;
	iph->frag_off=htons(0x4000); // Don't fragment.
	iph->tot_len = htons(vdb->len - sizeof(struct vde_ethernet_header));
	iph->id = 0;
	iph->protocol = protocol;
	iph->ttl = DEFAULT_TTL;
	iph->daddr = dst_ip;
	if (dst_ip != (htonl((uint32_t) -1)))
		iph->saddr = vder_get_right_localip(iface, iph->daddr);
	else
		iph->saddr = 0;
	iph->check = htons(vder_ip_checksum(iph));
	return vder_sendto(iface, vdb, bcast_macaddr);
}

void vder_packet_recv(struct vder_iface *vif, int timeout)
{
	struct pollfd pfd;
	int pollr;
	struct vde_buff *vb = NULL, *packet = NULL;
	char temp_buffer[MAX_PACKET_SIZE];
	pfd.events = POLLIN;
	pfd.fd = vde_datafd(vif->vdec);
	pollr = poll(&pfd, 1, timeout);
	if (pollr <= 0)
		return;
	vb = (struct vde_buff *) temp_buffer;
	if (vder_recv(vif, vb, MAX_PACKET_SIZE - sizeof(struct vde_buff)) >= 0) {
		struct vde_ethernet_header *eth = ethhead(vb);

		/* 0. Drop frames that are too short for the header they claim.
		 *
		 * ethhead(), arphead() and iphead() are plain fixed-offset macros over
		 * vb->data: they do not look at vb->len.  Passing a short frame on makes
		 * vder_parse_arp() and vder_ip_input() read past the end of the receive
		 * buffer.  A well-formed 34 byte IP frame with no payload trips this too,
		 * because the footprint copy below wants 14 + sizeof(iphdr) + 8 bytes.
		 */
		if ((size_t)vb->len < sizeof(struct vde_ethernet_header))
			return;

		/* 1. Filter out packets that are not for us */
		if (memcmp(eth->dst, vif->macaddr, 6) &&
			memcmp(eth->dst, ETH_BCAST, 6) ) {
				return;
		}

		if (ntohs(eth->buftype) == PTYPE_ARP) {
			if ((size_t)vb->len < sizeof(struct vde_ethernet_header) + sizeof(struct vde_arp_header))
				return;
			/* Parse ARP information */
			vder_parse_arp(vif, vb);
		} else if (ntohs(eth->buftype) == PTYPE_IP) {
			if ((size_t)vb->len < sizeof(struct vde_ethernet_header) + sizeof(struct iphdr))
				return;

			if (vder_filter(vb)) {
				return;
			}
			/* If there is some interesting payload, allocate a packet buffer */
			packet = malloc(vb->len + sizeof(struct vde_buff));
			if (!packet)
				return;
			memcpy(packet, vb, vb->len + sizeof(struct vde_buff));

			/** TODO: input packet filter here **/
			packet->priority = PRIO_BESTEFFORT;

			if (vder_ip_input(packet)) {
				/* If the packet is for us, process it here. */
				free(packet);
				return;
			} else {
				struct iphdr *hdr = iphead(packet);
				uint32_t sender = hdr->saddr;
				uint8_t foot[sizeof(struct iphdr) + 8];
				size_t avail = (size_t)packet->len - sizeof(struct vde_ethernet_header);
				size_t footlen = (avail < sizeof(foot)) ? avail : sizeof(foot);

				/* The leading bytes of the offending datagram, to be quoted back
				 * in an ICMP error.  The length check above guarantees the IP
				 * header, but not the 8 bytes that should follow it: a packet
				 * with no payload has none.  Copy what is there, zero the rest.
				 */
				memset(foot, 0, sizeof(foot));
				memcpy(foot, footprint(packet), footlen);
				/* On success the queue takes ownership and the sender loop
				 * frees the buffer.  On failure nobody does, so we must.
				 */
				if (vder_ip_decrease_ttl(packet)) {
					vder_icmp_ttl_expired(sender, foot);
					free(packet);
					return;
				}
				if (vder_packet_forward(packet, hdr->daddr) < 0) {
					vder_icmp_host_unreachable(sender, foot);
					free(packet);
					return;
				} else {
					/* success, packet is routed. */
					return;
				}
			}
		} else {
			/**  buffer type not supported. **/
			/** place your IPV6 code here :) **/
		}
	}
}
