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
	uint32_t			gateway;
	struct vder_iface 	*iface;
	uint16_t			metric;
	uint8_t				link_type;
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

static void route_change_metric(struct olsr_route_entry *r, int new_metric, uint32_t new_gateway)
{
	struct olsr_route_entry *cur, *prev;
	cur = Routes[r->metric], prev = NULL;
	while(cur) {
		if (cur == r) {
			/* found */
			if (!prev)
				Routes[r->metric] = cur->next;
			else
				prev->next = cur->next;

			if (r->metric > 1)
				vder_route_del(cur->destination, HOST_NETMASK, r->metric);

			r->metric = new_metric;
			r->gateway = new_gateway;

			if (r->metric > 1) {
				vder_route_add(cur->destination, HOST_NETMASK, new_gateway, new_metric, NULL);
				r->next = Routes[r->metric];
				Routes[r->metric] = r;
			}
			return;
		}

		prev = cur;
		cur = cur->next;
	}
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
			/* look on bigger metrics */
			struct olsr_route_entry *e = get_route_by_address(neighbors[i]);
			if (e) {
				route_change_metric(e, 0U, 1);
			} else {
				e = malloc(sizeof (struct olsr_route_entry));
				if (!e) {
					perror("olsr: adding local route entry");
					return;
				}
			}
			e->destination = neighbors[i];
			e->link_type = OLSRLINK_SYMMETRIC;
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->gateway = 0U;
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
				e->gateway = 0U;
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
				printf("Route expired!\n");
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


	entry = Routes[1];
	n_vec_size = 0;
	while(entry) {
		struct olsr_neighbor *neigh;
		hlink = (struct olsr_link *) (dgram + size);
		size += (sizeof(struct olsr_link));
		hlink->reserved = 0;
		hlink->link_code = entry->link_type;
		hlink->link_msg_size = htons(sizeof(struct olsr_link) + sizeof(struct olsr_neighbor));
		neigh = (struct olsr_neighbor *) (dgram + size);
		size += (sizeof(struct olsr_neighbor));
		neigh->addr = entry->destination;
		neigh->lq = 0xFF;
		neigh->nlq = 0xFF;
		n_vec_size++;
		entry = entry->next;
	}
	msg_hello->size = htons(sizeof(struct olsrmsg) +
		sizeof(struct olsr_hmsg_hello) +  n_vec_size * ((sizeof(struct olsr_link) + sizeof(struct olsr_neighbor))));



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

static inline void arp_storm(uint32_t addr)
{
	int i;
	for (i = 0; i < settings->n_ifaces; i++) {
		vder_arp_query(settings->ifaces[i], addr);
	}
}

static void recv_hello(uint8_t *buffer, int len, uint32_t origin)
{
	struct olsr_link *li;
	uint32_t *address;
	struct olsr_route_entry *e;
	int parsed = 0;

	while (len > parsed) {
		li = (struct olsr_link *) buffer;
		address = (uint32_t *)(buffer + parsed + sizeof(struct olsr_link));
		parsed += ntohs(li->link_msg_size);
		e = get_route_by_address(*address);
		if (!e) {
			e = malloc(sizeof(struct olsr_route_entry));
			if (!e) {
				perror("olsr allocating route");
				return;
			}
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->destination = *address;
			e->gateway = origin;
			e->iface = NULL;
			e->metric = 2;
			e->next = Routes[2];
			Routes[2] = e;
			arp_storm(e->destination);
			vder_route_add(*address, HOST_NETMASK, origin, 2, NULL);
		} else if (e->metric > 2) {
			route_change_metric(e, origin, 2);
		}
	}
}

static void olsr_recv(uint8_t *buffer, int len)
{
	struct olsrhdr *oh = (struct olsrhdr *) buffer;
	int parsed = 0;
	if (len != ntohs(oh->len)) {
		return;
	}
	parsed += sizeof(struct olsrhdr);

	struct olsrmsg *msg;
	while (len > parsed) {
		struct olsr_route_entry *origin;
		msg = (struct olsrmsg *) (buffer + parsed);
		origin = get_route_by_address(msg->orig);
		if (!origin) {
			arp_storm(msg->orig);
		} else {
			origin->link_type = OLSRLINK_MPR;
		}
		switch(msg->type) {
			case OLSRMSG_HELLO:
				recv_hello(buffer + parsed + sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello),
					ntohs(msg->size) - (sizeof(struct olsrmsg)) - sizeof(struct olsr_hmsg_hello),
					msg->orig);
				break;
			case OLSRMSG_MID:
				break;
			case OLSRMSG_TC:
				break;
			default:
				return;
		}
		parsed += ntohs(msg->size);
	}
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
	refresh_routes();

	while(1) {
		len = vder_udpsocket_recvfrom(udpsock, buffer, 100, &from_ip, &from_port, -1);
		if (len < 0) {
			perror("udp recv");
			return NULL;
		}
		if ((len > 0) && (from_port == OLSR_PORT)) {
			olsr_recv(buffer, len);
		}
		usleep(500000);
		gettimeofday(&now, NULL);
		refresh_routes();
		last_out = now;
		for (i = 0; i < settings->n_ifaces; i++)
			olsr_make_dgram(settings->ifaces[i]);
	}
}

