#include "vder_udp.h"
#include "vder_arp.h"
#include "vder_olsr.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


#define OLSR_MSG_INTERVAL 2000

struct olsr_route_entry
{
	struct olsr_route_entry *next;
	unsigned long 	time_left;
	uint32_t		destination;
	uint32_t		gateway;
	struct vder_iface *iface;
	uint16_t		metric;
};

struct olsr_mid_entry
{
	struct olsr_mid_entry *next;
	struct vder_iface *iface;
	uint32_t	addr;
};

struct olsr_hello_entry
{
	struct olsr_hello_entry *next;
	struct vder_iface *iface;
	uint32_t	addr;
};

static struct olsr_route_entry *or_list = NULL;

static struct vder_udp_socket *udpsock;
static struct olsr_setup *settings;

/* return a list of other interfaces local ip addresses */
static struct olsr_mid_entry *mid_list_alloc(struct vder_iface *dst_if)
{
	struct olsr_mid_entry *list = NULL, *p;
	int i;

	for (i = 0; i < settings->n_ifaces; i++) {
		struct vder_iface *cur = settings->ifaces[i];
		if (cur != dst_if) {
			struct vder_ip4address *addr = cur->address_list;
			while (addr) {
				p = malloc(sizeof(struct olsr_mid_entry));
				if (!p)
					return list;
				p->next = list;
				p->iface = cur;
				p->addr = addr->address;
				list = p;
				addr = addr->next;
			}
		}
	}
	return list;
}

static struct olsr_hello_entry *hello_list_alloc(struct vder_iface *dst_if)
{

	struct olsr_hello_entry *list = NULL, *p;
	int i;

	for (i = 0; i < settings->n_ifaces; i++) {
		struct vder_iface *cur = settings->ifaces[i];
		if (cur == dst_if) {
			struct vder_ip4address *addr = cur->address_list;
			while (addr) {
				p = malloc(sizeof(struct olsr_hello_entry));
				if (!p)
					return list;
				p->next = list;
				p->iface = cur;
				p->addr = addr->address;
				list = p;
				addr = addr->next;
			}
		}
	}
	return list;
}

static void hello_list_free(struct olsr_hello_entry *l)
{
	struct olsr_hello_entry *p;
	while(l) {
		p = l;
		l = p->next;
		free(p);
	}
}

static void mid_list_free(struct olsr_mid_entry *l)
{
	struct olsr_mid_entry *p;
	while(l) {
		p = l;
		l = p->next;
		free(p);
	}
}


static void olsr_make_dgram(struct vder_iface *vif)
{

	uint32_t orig, dest;
	uint8_t dgram[2000];
	int size = 0;
	struct olsr_hello_entry *elist, *ep;
	struct olsr_mid_entry *mlist, *mp;
	struct olsrhdr *ohdr;
	uint32_t netmask, bcast;

	static uint8_t hello_counter = 0, mid_counter = 0, tc_counter = 0;
	static uint16_t pkt_counter = 0;

	ohdr = (struct olsrhdr *)dgram;
	size += sizeof(struct olsrhdr);

	elist = hello_list_alloc(vif);
	ep = elist;
	if (!ep)
		return;
	netmask = vder_get_netmask(vif, ep->addr);
	bcast = vder_get_broadcast(ep->addr, netmask);
	while (ep) {
		struct olsrmsg *msg_hello;
		struct olsr_hmsg_hello *hello;
		struct olsr_link *hlink;
		uint32_t neighbors[256];
		int n_vec_size, i;

		msg_hello = (struct olsrmsg *) (dgram + size);
		size += sizeof(struct olsrmsg);
		msg_hello->type = OLSRMSG_HELLO;
		msg_hello->vtime = 60; /* one hot minute */
		msg_hello->orig = ep->addr;
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
				neigh->lq = 0xFF;
				neigh->nlq = 0xFF;
			}
		}
		ep = ep->next;
	}
	hello_list_free(elist);
	mlist = mid_list_alloc(vif);
	/* TODO: Add MID msg */
	mid_list_free(mlist);

	/* TODO: Add TC msg */

	ohdr->len = htons(size);
	ohdr->seq = htons(pkt_counter++);

	if ( 0 > vder_udpsocket_sendto_broadcast(udpsock, dgram, size, vif, bcast, OLSR_PORT) ) {
		perror("olsr send");
	}
}

static void olsr_recv(uint8_t *buffer, int len)
{
	struct olsrhdr *oh = (struct olsrhdr *) buffer;
	//printf ("Received olsr msg, size: %d (%d)\n", len, ntohs(oh->len));


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
			for (i = 0; i < settings->n_ifaces; i++)
				olsr_make_dgram(settings->ifaces[i]);
			last_out = now;
		}
	}
}

