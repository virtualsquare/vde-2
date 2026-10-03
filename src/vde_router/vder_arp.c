/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "vde_router.h"
#include "vder_arp.h"
#include "vde_headers.h"
#include "vder_datalink.h"
#include "vder_dhcp.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include "rbtree.h"

extern struct vde_router Router;

void vder_add_arp_entry(struct vder_iface *vif, struct vder_arp_entry *p)
{
	struct rb_node **link, *parent;
	uint32_t hostorder_ip = ntohl(p->ipaddr);

	pthread_mutex_lock(&vif->arp_lock);
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
			/* A DHCP lease is the authoritative binding for its IP:
			 * do not let an unauthenticated ARP packet point the
			 * address at a different MAC (poisoning). The MAC is
			 * copied out: the lease node may be evicted after. */
			uint8_t lease_mac[6];
			if (vder_dhcp_lease_mac(p->ipaddr, lease_mac) == 0 &&
			    memcmp(lease_mac, p->macaddr, 6) != 0) {
				pthread_mutex_unlock(&vif->arp_lock);
				return;
			}
			/* Update existing entry */
			memcpy(entry->macaddr,p->macaddr,6);
			entry->last_seen = time(NULL);
			pthread_mutex_unlock(&vif->arp_lock);
			return;
		}
	}
	p->last_seen = time(NULL);
	rb_link_node(&p->rb_node, parent, link);
	rb_insert_color(&p->rb_node, &vif->arp_table);
	pthread_mutex_unlock(&vif->arp_lock);
}

/*
 * Copy the MAC of the ARP entry for this IP into mac_out; return
 * 0 if found, -1 otherwise. The MAC is copied under the table
 * lock: the entry may be evicted by the GC thread after return.
 */
int vder_get_arp_entry_mac(struct vder_iface *vif, uint32_t addr,
			   uint8_t *mac_out)
{
	struct rb_node *node;
	uint32_t hostorder_ip = ntohl(addr);
	int found = -1;

	pthread_mutex_lock(&vif->arp_lock);
	node = vif->arp_table.rb_node;
	while (node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (ntohl(entry->ipaddr) > hostorder_ip)
			node = node->rb_left;
		else if (ntohl(entry->ipaddr) < hostorder_ip)
			node = node->rb_right;
		else {
			memcpy(mac_out, entry->macaddr, 6);
			found = 0;
			break;
		}
	}
	pthread_mutex_unlock(&vif->arp_lock);
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
		/* vder_add_arp_entry() updates the existing node in place when the
		 * address is already known; the lookup API hands out pointers the
		 * GC thread can free, so the entry is always handed to it owned. */
		ae = (struct vder_arp_entry *) malloc(sizeof(struct vder_arp_entry));
		if (!ae)
			return -1;
		memcpy(ae->macaddr, ah->s_mac, 6);
		ae->ipaddr = ah->s_addr;
		vder_add_arp_entry(vif, ae);
	}

	if(ntohs(ah->opcode) == ARP_REQUEST && vder_arp_should_reply(vif, ah->d_addr))
		vder_arp_reply(vif, vdb);
	return 0;
}

struct vder_arp_entry *vder_arp_get_record_by_macaddr(struct vder_iface *vif, uint8_t *mac)
{
	struct rb_node *node;
	struct vder_arp_entry *found = NULL;

	/* The caller (DHCP insert) keeps the pointer only while the
	 * lease is alive; arp_gc_iface never evicts a leased IP, so
	 * the entry outlives every live lease node. */
	pthread_mutex_lock(&vif->arp_lock);
	for (node = rb_first(&vif->arp_table); node; node = rb_next(node)) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (memcmp(entry->macaddr, mac, ETHERNET_ADDRESS_SIZE) == 0) {
			found = entry;
			break;
		}
	}
	pthread_mutex_unlock(&vif->arp_lock);
	return found;
}

int vder_arp_get_neighbors(struct vder_iface *vif, uint32_t *neighbors, int vector_size)
{
	int i = 0;
	struct rb_node *node;
	if (vector_size <= 0)
		return -EINVAL;

	pthread_mutex_lock(&vif->arp_lock);
	for (node = rb_first(&vif->arp_table); node; node = rb_next(node)) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		neighbors[i++] = entry->ipaddr;
		if (i == vector_size)
			break;
	}
	pthread_mutex_unlock(&vif->arp_lock);
	return i;
}

/*
 * Evict entries of one interface unseen for longer than
 * ARP_GC_TIMEOUT. DHCP-leased IPs are kept: the lease record is
 * the authoritative binding. Iterative walk: the table can be
 * large.
 */
static void arp_gc_iface(struct vder_iface *vif, time_t now)
{
	struct vder_arp_entry **stack = NULL;
	int top = 0, cap = 0;
	uint8_t lease_mac[6];
	struct rb_node *node = vif->arp_table.rb_node;

	pthread_mutex_lock(&vif->arp_lock);
	while (node || top > 0) {
		while (node) {
			if (top == cap) {
				int ncap = cap ? cap * 2 : 16;
				struct vder_arp_entry **ns = realloc(stack, ncap * sizeof *ns);
				if (!ns) {
					free(stack);
					pthread_mutex_unlock(&vif->arp_lock);
					return;
				}
				stack = ns;
				cap = ncap;
			}
			stack[top++] = rb_entry(node, struct vder_arp_entry, rb_node);
			node = node->rb_left;
		}
		struct vder_arp_entry *ae = stack[--top];
		node = ae->rb_node.rb_right;
		if ((now - ae->last_seen) > ARP_GC_TIMEOUT &&
		    vder_dhcp_lease_mac(ae->ipaddr, lease_mac) != 0) {
			rb_erase(&ae->rb_node, &vif->arp_table);
			free(ae);
		}
	}
	pthread_mutex_unlock(&vif->arp_lock);
	free(stack);
}

void vder_arp_gc(void)
{
	struct vder_iface *vif = Router.iflist;
	time_t now = time(NULL);

	while (vif) {
		arp_gc_iface(vif, now);
		vif = vif->next;
	}
}

void *vder_arp_gc_loop(void *arg)
{
	(void) arg;
	for (;;) {
		sleep(60);
		vder_arp_gc();
	}
	return NULL;
}
