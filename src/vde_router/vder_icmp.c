/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */

#include <config.h>

#include "vde_router.h"
#include "vde_headers.h"
#include "vder_packet.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static int vder_icmp_send(uint32_t dest, uint8_t type, uint8_t code, uint8_t *foot)
{
	struct icmp *ich;
	struct vde_buff *vdb;
	uint8_t *dst_footprint;

	vdb = malloc(sizeof(struct vde_buff) + sizeof(struct vde_ethernet_header) +
		sizeof(struct iphdr) + 8 + sizeof(struct iphdr) + 8);

	vdb->len = sizeof(struct vde_ethernet_header) + sizeof(struct iphdr) + 8 + sizeof(struct iphdr) + 8;

	ich = (struct icmp *)payload(vdb);
	ich->icmp_type = type;
	ich->icmp_code = code;
    ich->icmp_hun.ih_pmtu.ipm_void = 0;
	ich->icmp_hun.ih_pmtu.ipm_nextmtu = htons(1500);
	dst_footprint = (uint8_t *)payload(vdb) + 8;
	memcpy(dst_footprint, foot, sizeof(struct iphdr) + 8);

	ich->icmp_cksum = 0;
	ich->icmp_cksum = htons(net_checksum(payload(vdb), vdb->len - sizeof(struct iphdr) - 14));

	vdb->priority = 31;
	vder_packet_send(vdb, dest, PROTO_ICMP);
	return 0;
}

/**
 * Send a ICMP_PROTOCOL_UNREACHABLE if so.
 *
 */
int vder_icmp_service_unreachable(uint32_t dst, uint8_t *foot)
{
	return vder_icmp_send(dst, ICMP_UNREACH, ICMP_UNREACH_PROTOCOL, foot);
}
int vder_icmp_host_unreachable(uint32_t dst, uint8_t *foot)
{
	return vder_icmp_send(dst, ICMP_UNREACH, ICMP_UNREACH_HOST, foot);
}

int vder_icmp_ttl_expired(uint32_t dst, uint8_t *foot)
{
	return vder_icmp_send(dst, ICMP_TIME_EXCEEDED, ICMP_TIMXCEED_INTRANS, foot);
}

int vder_icmp_filter(uint32_t dst, uint8_t *foot)
{
	return vder_icmp_send(dst, ICMP_UNREACH, ICMP_UNREACH_FILTER_PROHIB, foot);
}

/* Parse an incoming icmp packet
 */
int vder_icmp_recv(struct vde_buff *vdb)
{
	struct icmp *ich;
	ich = (struct icmp *) payload(vdb);
	if (ich->icmp_type == ICMP_ECHO){
		struct vde_buff *vdb_copy = malloc(vdb->len + sizeof(struct vde_buff));
		struct icmp *ich_copy;
		struct iphdr *iph_copy;
		uint32_t tmp_ipaddr;

		if (!vdb_copy)
			return -1;
		memcpy(vdb_copy, vdb, sizeof(struct vde_buff) + vdb->len);

		ich_copy = (struct icmp *) payload(vdb_copy);
		iph_copy = iphead(vdb_copy);
		tmp_ipaddr = iph_copy->saddr;
		iph_copy->saddr = iph_copy->daddr;
		iph_copy->daddr = tmp_ipaddr;
		ich_copy->icmp_type = ICMP_ECHOREPLY;
		ich_copy->icmp_cksum = 0;
		ich_copy->icmp_cksum = htons(net_checksum(payload(vdb_copy), vdb_copy->len - sizeof(struct iphdr) - 14));
		iph_copy->check = htons(vder_ip_checksum(iph_copy));
		vder_packet_send(vdb_copy, iph_copy->daddr, PROTO_ICMP);
	}
	return 0;
}
