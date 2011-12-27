/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
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
	iph->check++;
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
	iph->saddr = vder_get_right_localip(ro->iface, iph->daddr);
	iph->check = htons(vder_ip_checksum(iph));
	ae = vder_get_arp_entry(ro->iface, iph->daddr);
	if (!ae) {
		vder_arp_query(ro->iface, iph->daddr);
		return -1;
	}
	return vder_sendto(ro->iface, vdb, ae->macaddr);
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
		/* 1. Filter out packets that are not for us */
		if (memcmp(eth->dst, vif->macaddr, 6) && 
			memcmp(eth->dst, ETH_BCAST, 6) ) {
				return;
		}

		if (ntohs(eth->buftype) == PTYPE_ARP) {
			/* Parse ARP information */
			vder_parse_arp(vif, vb);
		} else if (ntohs(eth->buftype) == PTYPE_IP) {

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
				//free(packet);
				return;
			} else {
				struct iphdr *hdr = iphead(packet);
				uint32_t sender = hdr->saddr;
				uint8_t foot[sizeof(hdr) + 8];

				memcpy(foot, footprint(packet), sizeof(struct iphdr) + 8);
				if (vder_ip_decrease_ttl(packet)) {
					vder_icmp_ttl_expired(sender, foot);
					return;
				}
				if (vder_packet_send(packet, hdr->daddr, hdr->protocol) < 0) {
					vder_icmp_host_unreachable(sender, foot);
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

