/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */

#ifndef _VDER_ROUTER
#define _VDER_ROUTER
#include <libvdeplug.h>
#include <stdint.h>
#include <pthread.h>
#include "rbtree.h"
#include <semaphore.h>

struct vde_router;
struct vder_queue;

/* IP address (generic) */
struct vder_ip4address {
	struct vder_ip4address *next;
	uint32_t address;
	uint32_t netmask;
};


/*
 * Filter interface
 */
enum filter_action {
	filter_accept = 0,
	filter_priority,
	filter_reject,
	filter_drop,
	filter_invalid = 255
};

struct vder_filter {
	struct vder_filter *next;
	struct vder_iface *src_iface;
	uint8_t proto;
	struct vder_ip4address saddr;
	struct vder_ip4address daddr;
	uint16_t sport;
	uint16_t dport;
	int tos;
	enum filter_action action;
	uint8_t priority;
	uint32_t stats_packets;
	uint32_t stats_bytes;
};

/* Interface */
struct vder_arp_entry {
	struct rb_node rb_node;
	uint32_t ipaddr;
	uint8_t macaddr[6];
};



/* route */
struct vder_route {
	struct vder_route *next;
	uint32_t dest_addr;
	uint32_t netmask;
	uint32_t gateway;
	uint16_t metric;
	struct vder_iface *iface;
};

struct vder_timed_dequeue {
	struct vder_timed_dequeue *next;
	uint64_t last_out;
	uint32_t interval;
	struct vder_queue *q;
};

struct vde_router {
	struct vder_iface *iflist;
	struct vder_route *routing_table;
	struct vder_filter *filtering_table;
	struct vder_timed_dequeue *timed_dequeue;
	pthread_mutex_t global_config_lock;
	pthread_t timer;
	uint32_t smallest_interval;
};

/* Buffer structure */

struct __attribute__ ((__packed__)) vde_buff 
{
	struct vde_buff *next;
	int len;
	struct vder_iface *src;
	uint8_t priority;
	unsigned char data[0];
};

#define QTYPE_OUT 0
#define QTYPE_PRIO 1

#define PRIO_ARP 1
#define PRIO_BESTEFFORT 15
#define PRIO_NUM 32

enum queue_policy_e {
	QPOLICY_UNLIMITED = 0,
	QPOLICY_FIFO,
	QPOLICY_RED,
	QPOLICY_TOKEN
};

/* Queue */
struct vder_queue {
	uint32_t n; /*< Number of packets */
	uint32_t size; /*< this is in bytes */
	pthread_mutex_t lock;
	sem_t semaphore;
	struct vde_buff *head;
	struct vde_buff *tail;
	uint8_t type;
	sem_t *prio_semaphore;

	enum queue_policy_e policy;
	int (*may_enqueue)(struct vder_queue *q, struct vde_buff *vb);
	int (*may_dequeue)(struct vder_queue *q);
	union policy_opt_e {
		struct {
			uint32_t limit;
			uint32_t stats_drop;
		} fifo;
		struct {
			uint32_t min;
			uint32_t max;
			double P;
			uint32_t limit;
			uint32_t stats_drop;
			uint32_t stats_probability_drop;
		} red;
		struct {
			uint32_t limit;
			uint32_t stats_drop;
			unsigned long long interval;
		} token;
	}policy_opt;
};


struct vder_iface {
	uint8_t interface_id;
	struct vder_iface *next;
	struct vder_ip4address *address_list;
	uint8_t macaddr[6];
	VDECONN *vdec;
	char vde_sock[1024];
	struct rb_root arp_table;
	struct vder_queue out_q;

	struct vder_queue prio_q[256];
	sem_t prio_semaphore;

	struct vde_router *router;
	pthread_t sender;
	pthread_t receiver;
	pthread_t queue_manager;
	pthread_t dhcpd;
	int dhcpd_started;
	struct {
		uint32_t sent;
		uint32_t recvd;
	} stats;
};

#endif
