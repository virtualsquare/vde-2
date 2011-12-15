#include "vde_router.h"
#include "vde_headers.h"
#include "vder_queue.h"
#include "vder_packet.h"
#include "vder_icmp.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libvdeplug.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/time.h>

struct vde_router Router = {};



/* MAC Addresses helpers. */

const uint8_t macaddr_vendor[3] = {0,2,5};

static uint8_t interfaces_list_lenght(void)
{
	uint8_t len = 0;
	struct vder_iface *vif = Router.iflist;
	while(vif) {
		len++;
		vif = vif->next;
	}
	return len;
}

static void new_macaddress(struct vder_iface *vif)
{
	uint16_t pid = getpid();
	memcpy(vif->macaddr, macaddr_vendor, 3);
	vif->macaddr[3] = (pid & 0xFF00) >> 8;
	vif->macaddr[4] = (pid & 0xFF);
	vif->macaddr[5] = vif->interface_id;
}

/* Get TCP/UDP header ports */

#define transport_sport(vdb) *((uint16_t *)((unsigned char*)(payload(vdb)) + 0))
#define transport_dport(vdb) *((uint16_t *)((unsigned char*)(payload(vdb)) + 2))

/* Queue management */

static void queue_init(struct vder_queue *q)
{
	memset(q, 0, sizeof(struct vder_queue));
	pthread_mutex_init(&q->lock, NULL);
	qunlimited_setup(q);
}

static void enqueue(struct vder_queue *q, struct vde_buff *b)
{
	pthread_mutex_lock(&q->lock);

	if (!q->may_enqueue(q, b)) {
		free(b);
		pthread_mutex_unlock(&q->lock);
		return;
	}

	b->next = NULL;
	if (!q->head) {
		q->head = b;
		q->tail = b;
	} else {
		q->tail->next = b;
		q->tail = b;
	}
	q->size += b->len;
	q->n++;
	pthread_mutex_unlock(&q->lock);
	if (q->policy != QPOLICY_TOKEN) {
		if (q->type == QTYPE_OUT)
			sem_post(&q->semaphore);
		else
			sem_post(q->prio_semaphore);
	}
}

static struct vde_buff *prio_dequeue(struct vder_iface *vif)
{
	struct vder_queue *q;
	int i;
	struct vde_buff *ret = NULL;
	sem_wait(&vif->prio_semaphore);
	for (i = 0; i < PRIO_NUM; i++) {
		q = &(vif->prio_q[i]);
		pthread_mutex_lock(&q->lock);
		if (q->size == 0){
			pthread_mutex_unlock(&q->lock);
			continue;
		}
		if (q->n) {
			ret = q->head;
			q->head = ret->next;
			q->n--;
			q->size -= ret->len;
			if (q->n == 0) {
				q->tail = NULL;
				q->head = NULL;
			}
			pthread_mutex_unlock(&q->lock);
			break;
		}
		pthread_mutex_unlock(&q->lock);
	}
	return ret;
}

static struct vde_buff *dequeue(struct vder_queue *q)
{
	struct vde_buff *ret = NULL;
	if (q->type == QTYPE_OUT)
		sem_wait(&q->semaphore);
	else
		return NULL;
	pthread_mutex_lock(&q->lock);
	if (q->n) {
		ret = q->head;
		q->head = ret->next;
		q->n--;
		q->size -= ret->len;
		if (q->n == 0) {
			q->tail = NULL;
			q->head = NULL;
		}
	}
	pthread_mutex_unlock(&q->lock);
	return ret;
}

#define microseconds(tv) (unsigned long long)((tv.tv_sec * 1000000) + (tv.tv_usec));

static void *vder_timer_loop(void *arg)
{
	struct timeval now_tv;
	struct timespec interval = {};
	unsigned long long now;
	struct vder_timed_dequeue *cur;
	while(1) {
		gettimeofday(&now_tv, NULL);
		now = microseconds(now_tv);
		cur = Router.timed_dequeue;
		pthread_mutex_lock(&Router.global_config_lock);
		while(cur) {
			while (now > (cur->last_out + cur->interval)) {
				if (cur->q) {
					if (cur->q->type == QTYPE_OUT)
						sem_post(&cur->q->semaphore);
					else
						sem_post(cur->q->prio_semaphore);
					cur->last_out += cur->interval;
					if (cur->last_out > now)
						cur->last_out = now;
				}
			}
			cur = cur->next;
		}
		pthread_mutex_unlock(&Router.global_config_lock);
		interval.tv_sec = 0;
		interval.tv_nsec = Router.smallest_interval / 1000;
		if (Router.timed_dequeue) 
			nanosleep(&interval, NULL);
		else
			sleep(2);
	}
	return 0;
}


void vder_timed_dequeue_add(struct vder_queue *q, uint32_t interval)
{
	struct vder_timed_dequeue *new = malloc(sizeof(struct vder_timed_dequeue));
	struct timeval now_tv;
	pthread_mutex_lock(&Router.global_config_lock);
	gettimeofday(&now_tv, 0);
	if (!new)
		return;
	new->interval = interval;
	new->q = q;
	new->last_out = microseconds(now_tv);
	new->next = Router.timed_dequeue;
	Router.timed_dequeue = new;
	if (Router.smallest_interval > new->interval) {
		Router.smallest_interval = new->interval;
	}
	pthread_mutex_unlock(&Router.global_config_lock);
}

void vder_timed_dequeue_del(struct vder_queue *q) 
{
	struct vder_timed_dequeue *prev = NULL, *cur = Router.timed_dequeue;
	pthread_mutex_lock(&Router.global_config_lock);
	while(cur) {
		if (cur->q == q) {
			if (!prev)
				Router.timed_dequeue = cur->next;
			else
				prev->next = cur->next;
			free(cur);
			break;
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Router.global_config_lock);
}

/* Global router initialization */
void vderouter_init(void)
{
	memset(&Router, 0, sizeof(Router));
	pthread_create(&Router.timer, 0, vder_timer_loop, NULL); 
	pthread_mutex_init(&Router.global_config_lock, NULL);
	Router.smallest_interval = 100000;

}

/* Route management */

uint32_t vder_get_right_localip(struct vder_iface *vif, uint32_t dst)
{
	struct vder_ip4address *cur = vif->address_list;
	while(cur) {
		if ((cur->address & cur->netmask) == (dst & cur->netmask))
			return cur->address;
		cur = cur->next;
	}
	return 0U;
}

/* insert route, ordered by netmask, metric.
 *  Default gw will be the last ones.
 */
int vder_route_add(uint32_t address, uint32_t netmask, uint32_t gateway, uint16_t metric, struct vder_iface *dst)
{
	struct vder_route *cur, *prev, *ro = malloc(sizeof(struct vder_route));
	uint32_t l_addr, l_nm;
	int ret = -1;
	if (!ro)
		return -1;
	pthread_mutex_lock(&Router.global_config_lock);
	l_addr = ntohl(address);
	l_nm = ntohl(netmask);

	/* Address is "network part" only */
	l_addr &= l_nm;
	ro->dest_addr = htonl(l_addr);
	ro->netmask = netmask;
	ro->gateway = gateway;
	ro->metric = metric;
	ro->iface = dst;

	/* Is this route already there? */
	cur = Router.routing_table;
	while(cur) {
		if ((cur->dest_addr == ro->dest_addr) && (cur->netmask == ro->netmask) && (cur->metric == ro->metric)) {
			errno = EEXIST;
			goto out_unlock;
		}
		cur = cur->next;
	}

	cur = Router.routing_table;
	prev = NULL;
	if (!cur) {
		Router.routing_table = ro;
		ro->next = NULL;
	} else {
		while(cur) {
			if (ntohl(cur->netmask) < ntohl(ro->netmask) ||
			  ((cur->netmask == ro->netmask) && (cur->metric < ro->metric))) {
				if (!prev) {
					Router.routing_table = ro;
					ro->next = cur;
					ret = 0; /* Successfully inserted as first member */
					goto out_unlock;
				} else {
					prev->next = ro;
					ro->next = cur;
					ret = 0; /* Successfully inserted between prev and cur */
					goto out_unlock;
				}
			}
			prev = cur;
			cur = cur->next;
		}
		/* if we got here, the current route must be inserted after the last one */
		prev->next = ro;
		ro->next = NULL;
		ret = 0;
	}

out_unlock:
	pthread_mutex_unlock(&Router.global_config_lock);
	return ret;
}

int vder_route_del(uint32_t address, uint32_t netmask, int metric)
{
	struct vder_route *cur = Router.routing_table, *prev = NULL;
	int retval = -1;
	pthread_mutex_lock(&Router.global_config_lock);
	while(cur) {
		if ((cur->dest_addr == address) &&
		 (cur->netmask == netmask) &&
		 (cur->metric == metric)) {
			if (prev) {
				prev->next = cur->next;
			} else {
				Router.routing_table = cur->next;
			}
			free(cur);
			retval = 0;
			break;
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Router.global_config_lock);
	return retval;
}

struct vder_route * vder_get_route(uint32_t address)
{
	struct vder_route *cur = Router.routing_table;
	uint32_t l_addr, r_addr, r_netmask;
	l_addr = ntohl(address);
	while(cur) {
		r_addr = ntohl(cur->dest_addr);
		r_netmask = ntohl(cur->netmask);
		if ((l_addr & r_netmask) == r_addr)
			break;
		cur = cur->next;
	}
	return cur;
}

int vder_default_route(uint32_t gateway, int metric)
{
	struct vder_route *dst = vder_get_route(gateway);
	if (!dst || (!dst->dest_addr) || dst->gateway)
		return -EINVAL;
	return vder_route_add(0, 0, gateway, metric, dst->iface);
}

/* Interface management */

struct vder_iface *vder_iface_new(char *sock, uint8_t *macaddr)
{
	struct vder_iface *vif = (struct vder_iface *) malloc(sizeof(struct vder_iface)), *cur;
    struct vde_open_args open_args={.mode=0700};
	int i;
	if (!vif)
		return NULL;

	pthread_mutex_lock(&Router.global_config_lock);

	vif->vdec = vde_open(sock, "vde_router", &open_args); 
	if (vif->vdec == NULL) {
		perror("vde_open");
		free(vif);
		vif = NULL;
		goto out;
	}

	sem_init(&vif->out_q.semaphore, 0, 0);
	sem_init(&vif->prio_semaphore, 0, 0);

	queue_init(&vif->out_q);
	vif->out_q.type = QTYPE_OUT;
	for (i=0; i< PRIO_NUM; i++) {
		queue_init(&(vif->prio_q[i]));
		vif->prio_q[i].type = QTYPE_PRIO;
		vif->prio_q[i].prio_semaphore = &vif->prio_semaphore;
	}

	vif->interface_id = interfaces_list_lenght();
	if (!macaddr)
		new_macaddress(vif);
	else
		memcpy(vif->macaddr, macaddr, 6);
	vif->arp_table = RB_ROOT;
	vif->address_list = NULL;
	vif->router = &Router;
	vif->next = NULL;
	cur = Router.iflist;
	strncpy(vif->vde_sock, sock, 1023);
	if(!cur) {
		Router.iflist = vif;
	} else {
		while(cur->next)
			cur = cur->next;
		cur->next = vif;
	}

out:
	pthread_mutex_unlock(&Router.global_config_lock);
	return vif;
}

int vder_iface_address_add(struct vder_iface *iface, uint32_t addr, uint32_t netmask)
{
	struct vder_ip4address *address = malloc(sizeof(struct vder_ip4address));
	struct vder_ip4address *cur = iface->address_list;
	if (!address) {
		errno = EINVAL;
		return -1;
	}
	while(cur) {
		if (cur->address == addr) {
			free(address);
			errno = EADDRINUSE;
			return -1;
		}
		cur = cur->next;
	}

	pthread_mutex_lock(&Router.global_config_lock);
	address->address = addr;
	address->netmask = netmask;
	address->next = iface->address_list;
	iface->address_list = address;
	pthread_mutex_unlock(&Router.global_config_lock);

	/* Add static route towards neightbors */
	vder_route_add(address->address, address->netmask, 0U, 1, iface);

	return 0;
}

int vder_iface_address_del(struct vder_iface *iface, uint32_t addr)
{
	struct vder_ip4address *cur = iface->address_list, *prev = NULL;
	uint32_t netmask = 0U;
	pthread_mutex_lock(&Router.global_config_lock);
	while(cur) {
		if (cur->address == addr) {
			if (prev) {
				prev->next = cur->next;
			} else {
				iface->address_list = cur->next;
			}
			netmask = cur->netmask;
			free(cur);
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Router.global_config_lock);

	/* Get rid of the previously added route */
	if(netmask) {
		vder_route_del((addr & netmask), netmask, 1);
		return 0;
	} else {
		errno = ENOENT;
		return -1;
	}
}

int vder_sendto(struct vder_iface *iface, struct vde_buff *vb, uint8_t *dst)
{
	struct vde_ethernet_header *eth;
	if (!vb || !dst) {
		errno = EINVAL;
		return -1;
	}
	eth = ethhead(vb);
	memcpy(eth->dst, dst, 6);
	memcpy(eth->src, iface->macaddr, 6);
	enqueue(&(iface->prio_q[vb->priority]), vb);
	return 0;
}


int vder_recv(struct vder_iface *iface, struct vde_buff *vb, int len)
{
	vb->len = vde_recv(iface->vdec, vb->data, len, 0);
	vb->src = iface;
	return vb->len;
}

void *vder_core_send_loop(void *vde_if_arg)
{
	struct vder_iface *vde_if = vde_if_arg;
	struct vde_buff *buf;
	while(1) {
		buf = dequeue(&vde_if->out_q);
		if (!buf)
			continue;
		vde_send(vde_if->vdec, buf->data, buf->len, 0);
		vde_if->stats.sent++;
		free(buf);
	}
}

void *vder_core_recv_loop(void *vde_if_arg)
{
	struct vder_iface *vde_if = vde_if_arg;
	while(1) {
		(void) vder_packet_recv(vde_if, -1);
		vde_if->stats.recvd++;
	}
}

void *vder_core_queuer_loop(void *vde_if_arg)
{
	struct vder_iface *vde_if = vde_if_arg;
	struct vde_buff *buf;
	while(1) {
		buf = prio_dequeue(vde_if);
		if (!buf)
			continue;
		enqueue(&vde_if->out_q, buf);
	}
}

int vder_ipaddress_is_local(uint32_t addr) {
	struct vder_iface *iface = Router.iflist;
	while (iface) {
		struct vder_ip4address *cur = iface->address_list;
		while(cur) {
			if (cur->address == addr) {
				return 1;
			}
			cur = cur->next;
		}
		iface = iface->next;
	}
	return 0;
}



/* IP filter management */
int vder_filter_del(struct vder_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport)
{
	struct vder_filter *prev = NULL, *search = Router.filtering_table;
	while(search) {
		if ( (search->src_iface == src) &&
			(search->saddr.address == saddr_address) &&
			(search->saddr.netmask  == saddr_netmask) &&
			(search->daddr.address  == daddr_address) &&
			(search->daddr.netmask  == daddr_netmask) &&
			(search->sport == sport) &&
			(search->dport == dport) &&
			(search->tos == tos)
		) {
			if (!prev) {
				Router.filtering_table = search->next;
			} else {
				prev->next = search->next;
			}
			free(search);
			return 0;
		}
		prev = search;
		search = search->next;
	}
	errno = ENOENT;
	return -1;
}

int vder_filter_add(struct vder_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport,
		enum filter_action action, uint8_t priority)
{
	struct vder_filter *new = malloc(sizeof(struct vder_filter));
	if (!new)
		return -1;
	new->src_iface = src;
	new->saddr.address = saddr_address;
	new->saddr.netmask = saddr_netmask;
	new->daddr.address = daddr_address;
	new->daddr.netmask = daddr_netmask;
	new->sport = sport;
	new->dport = dport;
	new->tos = tos;
	new->proto = proto;
	new->stats_packets = 0U;
	new->stats_bytes = 0U;
	new->action = action;
	new->next = Router.filtering_table;
	Router.filtering_table = new;
	return 0;
}

int vder_filter(struct vde_buff *buf)
{
	struct iphdr *ip = iphead(buf);
	struct vder_filter *selected = NULL, *cur = Router.filtering_table;
	uint8_t foot[sizeof(struct iphdr) + 8];
	while(cur) {
		if ( (!cur->src_iface || (cur->src_iface == buf->src)) &&
			 (!cur->proto     || (cur->proto == ip->protocol)) &&
			 ( (cur->tos < 0) || ((uint8_t)cur->tos == ip->tos)) &&
			 (!cur->saddr.address || (cur->saddr.address == (cur->saddr.netmask & ip->saddr))) &&
			 (!cur->daddr.address || (cur->daddr.address == (cur->daddr.netmask & ip->daddr))) &&
			 (!cur->sport || (cur->sport == transport_sport(buf))) &&
			 (!cur->dport || (cur->dport == transport_dport(buf)))
			) {
				selected = cur;
				break;
		}
		cur = cur->next;
	}
	if (selected) {
		selected->stats_packets++;
		selected->stats_bytes += buf->len;
		switch(selected->action) {
			case filter_priority:
				buf->priority = selected->priority;
				/* fall through */
			case filter_accept:
				return 0;

			case filter_reject:
				memcpy(foot, footprint(buf), sizeof(struct iphdr) + 8);
				vder_icmp_filter(ip->saddr, foot);
				/* fall through */
			case filter_drop:
				return 1;
			default: 
				return 0;
		}
	}
	return 0; /* Default (no rule set): accept. */
}
