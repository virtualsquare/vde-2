/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef _VDER_DATALINK
#define _VDER_DATALINK
#include <stdint.h>
#include "vde_headers.h"
#include "vde_router.h"

/* Global router initialization */
void vderouter_init(void);

/* Route management */

uint32_t vder_get_right_localip(struct vder_iface *vif, uint32_t dst);
int vder_route_add(uint32_t address, uint32_t netmask, uint32_t gateway, uint16_t metric, struct vder_iface *dst);
int vder_route_del(uint32_t address, uint32_t netmask, int metric);
struct vder_route * vder_get_route(uint32_t address);
int vder_default_route(uint32_t gateway, int metric);
uint32_t vder_get_right_localip(struct vder_iface *vif, uint32_t dst);
int vder_ipaddress_is_local(uint32_t addr);

/* Interface management */

struct vder_iface *vder_iface_new(char *sock, uint8_t *macaddr);
int vder_iface_address_add(struct vder_iface *iface, uint32_t addr, uint32_t netmask);
int vder_iface_address_del(struct vder_iface *iface, uint32_t addr);
int vder_sendto(struct vder_iface *iface, struct vde_buff *vb, uint8_t *dst);

struct vder_iface *vder_iface_new(char *sock, uint8_t *macaddr);
int vder_iface_address_add(struct vder_iface *iface, uint32_t addr, uint32_t netmask);
int vder_iface_address_del(struct vder_iface *iface, uint32_t addr);
int vder_send(struct vder_iface *iface, struct vde_buff *vb, int len, uint8_t *dst);
int vder_recv(struct vder_iface *iface, struct vde_buff *vb, int len);

/* Thread-loops */
void *vder_core_send_loop(void *);
void *vder_core_recv_loop(void *);
void *vder_core_queuer_loop(void *);

/* timed dequeues (token bucket) */
void vder_timed_dequeue_add(struct vder_queue *q, uint32_t interval);
void vder_timed_dequeue_del(struct vder_queue *q);


/* Filter */
int vder_filter_del(struct vder_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport);
int vder_filter_add(struct vder_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport,
		enum filter_action action, uint8_t priority);

int vder_filter(struct vde_buff *buf);
#endif
