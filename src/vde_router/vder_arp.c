/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "vde_router.h"
#include "vder_arp.h"
#include "vde_headers.h"
#include "vder_datalink.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "rbtree.h"

void vder_add_arp_entry(struct vder_iface *vif, struct vder_arp_entry *p)
{
	struct rb_node **link, *parent;
	uint32_t hostorder_ip = ntohl(p->ipaddr);
	link = &vif->arp_table.rb_node;
	parent = *link;
	while (*link) {
		struct vder_arp_entry *entry;
		parent = *link;
		entry = rb_entry(parent, struct vder_arp_entry, rb_node);
		if (ntohl(entry->ipaddr) > hostorder_ip) {
			link = &(*link)->rb_left;
		} else if (ntohl(entry->ipaddr) < hostorder_ip){
			link = &(*link)->rb_right;
		} else {
			/* Update existing entry */
			memcpy(entry->macaddr,p->macaddr,6);
			return;
		}
	}
	rb_link_node(&p->rb_node, parent, link);
	rb_insert_color(&p->rb_node, &vif->arp_table);
}

struct vder_arp_entry *vder_get_arp_entry(struct vder_iface *vif, uint32_t addr)
{
	struct rb_node *node;
	struct vder_arp_entry *found=NULL;
	uint32_t hostorder_ip = ntohl(addr);
	node = vif->arp_table.rb_node;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (ntohl(entry->ipaddr) > hostorder_ip)
			node = node->rb_left;
		else if (ntohl(entry->ipaddr) < hostorder_ip)
			node = node->rb_right;
		else {
			found = entry;
			break;
		}
	}
	return found;
}

/**
 * Prepare and send an arp query
 */
size_t vder_arp_query(struct vder_iface *oif, uint32_t tgt)
{
	struct vde_ethernet_header *vdeh;
	struct vde_arp_header *ah;
	struct vde_buff *vdb;

	vdb = (struct vde_buff *) malloc(sizeof(struct vde_buff) + 60);
	vdb->len = 60;

	/* set frame type to ARP */
	vdeh = ethhead(vdb);
	vdeh->buftype = htons(PTYPE_ARP);

	/* build arp payload */
	ah = arphead(vdb);
	ah->htype = htons(HTYPE_ETH);
	ah->ptype = htons(PTYPE_IP);
	ah->hsize = ETHERNET_ADDRESS_SIZE;
	ah->psize = IP_ADDRESS_SIZE;
	ah->opcode = htons(ARP_REQUEST);
	memcpy(ah->s_mac, oif->macaddr,6);
	ah->s_addr = vder_get_right_localip(oif, tgt); 
	if (ah->s_addr == 0) {
		if (oif->address_list) 
			ah->s_addr = oif->address_list->address;
		else
			return -1;
	}
	memset(ah->d_mac,0,6);
	ah->d_addr = tgt;
	vdb->priority = PRIO_ARP;
	return vder_sendto(oif, vdb, ETH_BCAST);
}

extern struct vde_router Router;

/**
 * Decide whether this ARP request is ours to answer.
 *
 * The router used to answer every request on every interface, without ever
 * looking at the target address.  Two rules are enough:
 *
 *   1. the target is one of our own addresses;
 *   2. the target routes out of a *different* interface - proxy ARP.
 *
 * Rule 2 is what makes routing work: when the upstream side asks for a host on
 * the downstream segment, we must answer or the return traffic has nowhere to
 * go.  An address that belongs to the same interface's own subnet is for its
 * owner to claim, so we stay quiet.
 */
static int vder_arp_should_reply(struct vder_iface *vif, uint32_t target)
{
	struct vder_ip4address *cur;
	struct vder_iface *iface;
	struct vder_route *ro;

	if (target == 0 || target == (uint32_t)(-1))
		return 0;

	/* 1. one of ours?  (-1 marks an interface waiting for DHCP, not an address) */
	for (iface = Router.iflist; iface; iface = iface->next) {
		for (cur = iface->address_list; cur; cur = cur->next) {
			if (cur->address == (uint32_t)(-1))
				continue;
			if (cur->address == target)
				return 1;
		}
	}

	/* 2. reachable through another interface? */
	ro = vder_get_route(target);
	if (ro && ro->iface && ro->iface != vif)
		return 1;

	return 0;
}

/**
 * Reply to given arp request, if needed
 */
size_t vder_arp_reply(struct vder_iface *oif, struct vde_buff *vdb)
{
	struct vde_arp_header *ah;
	uint32_t ipaddr_tmp;
	struct vde_buff *vdb_copy;
	ah = arphead(vdb);
	ah->opcode = htons(ARP_REPLY);
	memcpy(ah->d_mac, ah->s_mac, 6);
    memcpy(ah->s_mac, oif->macaddr,6);
	ipaddr_tmp = ah->s_addr;
	ah->s_addr = ah->d_addr;
	ah->d_addr = ipaddr_tmp;
	vdb_copy = malloc(sizeof(struct vde_buff) + vdb->len);
	if (!vdb_copy)
		return 0;
	memcpy(vdb_copy, vdb, (sizeof(struct vde_buff) + vdb->len));
	vdb_copy->priority = PRIO_ARP;
	return vder_sendto(oif, vdb_copy, ah->d_mac);
}

/* Parse an incoming arp packet */
int vder_parse_arp(struct vder_iface *vif, struct vde_buff *vdb)
{
	struct vde_arp_header *ah = arphead(vdb);
	struct vder_arp_entry *ae;

	/* An ARP probe (RFC 5227) carries a sender address of 0.0.0.0.  Learning it
	 * leaves that MAC recorded as owning 0.0.0.0, and the DHCP server looks a
	 * client up by MAC: it then finds an address outside its pool, bails out of
	 * dhcp_recv() and never answers that client again.  Do not learn from those.
	 */
	if (ah->s_addr != 0) {
		/* This used to malloc an entry for every ARP packet and hand it to
		 * vder_add_arp_entry(), which updates the existing node when the address
		 * is already known and does not free what it was given - one leaked
		 * entry per ARP packet from an address we have already seen.  Update in
		 * place instead, and allocate only for addresses that are new.
		 */
		ae = vder_get_arp_entry(vif, ah->s_addr);
		if (ae) {
			memcpy(ae->macaddr, ah->s_mac, 6);
		} else {
			ae = (struct vder_arp_entry *) malloc(sizeof(struct vder_arp_entry));
			if (!ae)
				return -1;
			memcpy(ae->macaddr, ah->s_mac, 6);
			ae->ipaddr = ah->s_addr;
			vder_add_arp_entry(vif, ae);
		}
	}

	if(ntohs(ah->opcode) == ARP_REQUEST && vder_arp_should_reply(vif, ah->d_addr))
		vder_arp_reply(vif, vdb);
	return 0;
}

struct vder_arp_entry *vder_arp_get_record_by_macaddr(struct vder_iface *vif, uint8_t *mac)
{
	struct rb_node *node;

	for (node = rb_first(&vif->arp_table); node; node = rb_next(node)) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (memcmp(entry->macaddr, mac, ETHERNET_ADDRESS_SIZE) == 0)
			return entry;
	}

	return NULL;
}

int vder_arp_get_neighbors(struct vder_iface *vif, uint32_t *neighbors, int vector_size)
{
	int i = 0;
	struct rb_node *node;
	if (vector_size <= 0)
		return -EINVAL;

	for (node = rb_first(&vif->arp_table); node; node = rb_next(node)) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		neighbors[i++] = entry->ipaddr;
		if (i == vector_size)
			return i;
	}

	return i;
}
