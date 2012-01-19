#include "vder_udp.h"
#include "vder_arp.h"
#include "vder_olsr.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


#define OLSR_MSG_INTERVAL 2000
#define HOST_NETMASK (htonl(0xFFFFFFFF))
#define MAX_HOPS 256

struct olsr_route_entry
{
	struct olsr_route_entry *next;
	unsigned long 		time_left;
	uint32_t			destination;
	struct olsr_route 	*gateway;
	struct vder_iface 	*iface;
	uint16_t			metric;
};

static struct olsr_route_entry *Routes[MAX_HOPS] = {};
static struct vder_udp_socket *udpsock;
static struct olsr_setup *settings;

static struct olsr_route_entry *get_route_by_address(uint32_t ip)
{
	struct olsr_route_entry *cur;
	int i;

	for (i = 0; i < MAX_HOPS; i++) {
		cur = Routes[i];
		while(cur) {
			if (cur->destination == ip)
				return cur;
			cur = cur->next;
		}
	}
	return NULL;
}

static void refresh_neighbors(struct vder_iface *iface)
{
	struct olsr_route_entry *cur;
	uint32_t neighbors[256];
	int i;
	unsigned char found = 0;
	int n_vec_size = vder_arp_get_neighbors(iface, neighbors, 256);
	for (i = 0; i < n_vec_size; i++) {
		cur = Routes[1];
		while(cur) {
			if (cur->destination == neighbors[i]) {
				cur->time_left = (OLSR_MSG_INTERVAL << 2);
				found = 1;
				break;
			}
			cur = cur->next;
		}
		if (!found) {
			struct olsr_route_entry *e = malloc(sizeof (struct olsr_route_entry));
			if (!e) {
				perror("olsr: adding local route entry");
				return;
			}
			e->destination = neighbors[i];
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->gateway = NULL;
			e->iface = iface;
			e->metric = 1;
			e->next = Routes[1];
			Routes[1] = e;
		}
	}
}


static void refresh_routes(void)
{
	int i;
	struct olsr_route_entry *cur, *prev = NULL;

	/* Refresh local entries */

	/* Step 1: set zero expire time for local addresses and neighbors*/
	for (i = 0; i < 2; i++) {
		cur = Routes[i];
		while(cur) {
			cur->time_left = (OLSR_MSG_INTERVAL << 2);
			cur = cur->next;
		}
	}


	/* Step 2: refresh timer for entries that are still valid. 
	 * Add new entries.
	 */
	for (i = 0; i < settings->n_ifaces; i++) {
		struct vder_iface *icur = settings->ifaces[i];
		struct vder_ip4address *addr = icur->address_list;
		while (addr) {
			unsigned char found = 0;
			cur = Routes[0];
			while(cur) {
				if (cur->destination == addr->address) {
					cur->time_left = (OLSR_MSG_INTERVAL << 2);
					found = 1;
					break;
				}
				cur = cur->next;
			}
			if (!found) {
				struct olsr_route_entry *e = malloc(sizeof (struct olsr_route_entry));
				if (!e) {
					perror("olsr: adding local route entry");
					return;
				}
				e->destination = addr->address;
				e->time_left = (OLSR_MSG_INTERVAL << 2);
				e->gateway = NULL;
				e->iface = icur;
				e->metric = 0;
				e->next = Routes[0];
				Routes[0] = e;
			}
			refresh_neighbors(icur);
			addr = addr->next;
		}
	}

	/* Remove expired entries */

	for (i = 0; i < MAX_HOPS; i++) {
		cur = Routes[i], prev = NULL; 
		while(cur) {
			if (cur->time_left < OLSR_MSG_INTERVAL) {
				if (!prev)
					Routes[i] = cur->next;
				else
					prev->next = cur->next;
				if (i > 1)
					vder_route_del(cur->destination, HOST_NETMASK, i);
				free(cur);
			} else {
				prev = cur;
			}
			cur = cur->next;
		}
	}
}

static void olsr_make_dgram(struct vder_iface *vif)
{
	uint8_t dgram[2000];
	int size = 0;
	struct vder_ip4address *ep;
	struct olsrhdr *ohdr;
	uint32_t netmask, bcast;
	struct olsrmsg *msg_hello, *msg_mid;
	struct olsr_hmsg_hello *hello;

	struct olsr_link *hlink;
	struct olsr_route_entry *entry;
	uint32_t neighbors[256];
	int n_vec_size, i, mid_count = 0;

	static uint8_t hello_counter = 0, mid_counter = 0, tc_counter = 0;
	static uint16_t pkt_counter = 0;

	ohdr = (struct olsrhdr *)dgram;
	size += sizeof(struct olsrhdr);

	ep = vif->address_list; /* Take first address */
	if (!ep)
		return;
	netmask = vder_get_netmask(vif, ep->address);
	bcast = vder_get_broadcast(ep->address, netmask);



	/* HELLO Message */

	msg_hello = (struct olsrmsg *) (dgram + size);
	size += sizeof(struct olsrmsg);
	msg_hello->type = OLSRMSG_HELLO;
	msg_hello->vtime = 60; /* one hot minute */
	msg_hello->orig = ep->address;
	msg_hello->ttl = 1;
	msg_hello->hop = 0;
	msg_hello->seq = htons(hello_counter++);

	hello = (struct olsr_hmsg_hello *)(dgram + size);
	size += sizeof(struct olsr_hmsg_hello);
	hello->reserved = 0;
	hello->htime = 0x05; /* Todo: find and define values */
	hello->willingness = 0x07;

	n_vec_size = vder_arp_get_neighbors(vif, neighbors, 256);
	msg_hello->size = htons(sizeof(struct olsrmsg) +
		sizeof(struct olsr_hmsg_hello) +  n_vec_size * ((sizeof(struct olsr_link) + sizeof(struct olsr_neighbor))));

	if (n_vec_size > 0) {
		for (i = 0; i < n_vec_size; i ++) {
			struct olsr_neighbor *neigh;
			hlink = (struct olsr_link *) (dgram + size);
			size += (sizeof(struct olsr_link));
			hlink->reserved = 0;
			hlink->link_code = OLSRLINK_SYMMETRIC;
			hlink->link_msg_size = htons(sizeof(struct olsr_link) + sizeof(struct olsr_neighbor));
			neigh = (struct olsr_neighbor *) (dgram + size);
			size += (sizeof(struct olsr_neighbor));
			neigh->addr = neighbors[i];
			neigh->lq = 0xFF; /* Todo: Read quality from node */
			neigh->nlq = 0xFF;
		}
	}


	/* MID Message */

	entry = Routes[0];
	msg_mid = (struct olsrmsg *)(dgram + size);
	size += sizeof(struct olsrmsg);
	msg_mid->type = OLSRMSG_MID;
	msg_mid->vtime = 60; /* one hot minute */
	msg_mid->orig = ep->address;
	msg_mid->ttl = 0xFF;
	msg_mid->hop = 0;

	while(entry) {
		uint32_t mid_address;
		if (entry->iface != vif) {
			mid_address = entry->destination;
			memcpy(dgram + size, &mid_address, sizeof(uint32_t));
			size += sizeof(uint32_t);
			mid_count++;
		}
		entry = entry->next;
	}
	if (mid_count == 0) {
		size -= (sizeof(struct olsrmsg));
	} else {
		msg_mid->seq = htons(mid_counter++);
		msg_mid->size = htons(sizeof(struct olsrmsg) + sizeof(uint32_t) * mid_count);
	}

	/* TODO: Add TC msg */


	/* Finalize olsr packet */
	ohdr->len = htons(size);
	ohdr->seq = htons(pkt_counter++);

	/* Send the thing out */
	if ( 0 > vder_udpsocket_sendto_broadcast(udpsock, dgram, size, vif, bcast, OLSR_PORT) ) {
		perror("olsr send");
	}
}

static void olsr_recv(uint8_t *buffer, int len)
{
	struct olsrhdr *oh = (struct olsrhdr *) buffer;
	if (len != oh->len) {
		/* Invalid packet size, silently discard */
		return;
	}
	/* TODO: Implement parser. */
}


void *vder_olsr_loop(void *olsr_settings)
{
	uint32_t from_ip;
	uint16_t from_port;
	unsigned char buffer[2000];
	int len;
	int i;
	struct timeval now, last_out;

	settings = (struct olsr_setup *) olsr_settings;
	if(settings->n_ifaces <= 0)
		return NULL;
	if (!udpsock)
		udpsock = vder_udpsocket_open(OLSR_PORT);
	if (!udpsock)
		return NULL;


	gettimeofday(&last_out, NULL);

	while(1) {
		len = vder_udpsocket_recvfrom(udpsock, buffer, OLSR_MSG_INTERVAL, &from_ip, &from_port, -1);
		if (len < 0) {
			perror("udp recv");
			return NULL;
		}
		if ((len > 0) && (from_port == OLSR_PORT)) {
			olsr_recv(buffer, len);
		}
		sleep(1);
		gettimeofday(&now, NULL);
		if ((now.tv_sec - last_out.tv_sec) >= (OLSR_MSG_INTERVAL / 1000)) {
			refresh_routes();
			for (i = 0; i < settings->n_ifaces; i++)
				olsr_make_dgram(settings->ifaces[i]);
			last_out = now;
		}
	}
}

