/*
 * VDE - vde_vxlan Network emulator for vde
 * Copyright (C) 2014 Renzo Davoli, Alessandro Ghedini VirtualSquare
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "log.h"
#include "switch.h"
#include "vxlan_hash.h"
#include "consmgmt.h"
#include "bitarray.h"

#define MIN_PERSISTENCE_DFL 3
static int min_persistence=MIN_PERSISTENCE_DFL;
#define HASH_INIT_BITS 7
static int hash_bits;
static int hash_mask;
#define HASH_SIZE (1 << hash_bits)

struct hash_entry {
	struct hash_entry *next;
	struct hash_entry **prev;
	time_t last_seen;
	in_addr_t port;
	u_int64_t dst;
};

static struct hash_entry **h;

static int calc_hash(u_int64_t src)
{
	src ^= src >> 33;
	src *= 0xff51afd7ed558ccd;
	src ^= src >> 33;
	src *= 0xc4ceb9fe1a85ec53;
	return src & hash_mask;
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define EMAC2MAC6(X) \
	(u_int)((X)&0xff), (u_int)(((X)>>8)&0xff), (u_int)(((X)>>16)&0xff), \
  (u_int)(((X)>>24)&0xff), (u_int)(((X)>>32)&0xff), (u_int)(((X)>>40)&0xff)
#elif BYTE_ORDER == BIG_ENDIAN
#define EMAC2MAC6(X) \
	(u_int)(((X)>>24)&0xff), (u_int)(((X)>>16)&0xff), (u_int)(((X)>>8)&0xff), \
  (u_int)((X)&0xff), (u_int)(((X)>>40)&0xff), (u_int)(((X)>>32)&0xff)
#else
#error Unknown Endianess
#endif

#define EMAC2VLAN(X) ((u_int16_t) ((X)>>48))
#define EMAC2VLAN2(X) ((u_int) (((X)>>48) &0xff)), ((u_int) (((X)>>56) &0xff))

#define find_entry(MAC) \
	({struct hash_entry *e; \
	 int k = calc_hash(MAC);\
	 for(e = h[k]; e && e->dst != (MAC); e = e->next)\
	 ;\
	 e; })


#define extmac(MAC,VLAN) \
	    ((*(u_int32_t *) &((MAC)[0])) + ((u_int64_t) ((*(u_int16_t *) &((MAC)[4]))+ ((u_int64_t) (VLAN) << 16)) << 32))

/* looks in global hash table 'h' for given address, and return associated
 * port */
int find_in_hash(unsigned char *dst, int vlan, in_addr_t *out)
{
	struct hash_entry *e = find_entry(extmac(dst,vlan));
	*out = 0;
	if(e == NULL) return 0;
	*out = e->port;
	return 1;
}

int find_in_hash_update(unsigned char *src, int vlan, in_addr_t port, in_addr_t *out)
{
	struct hash_entry *e;
	u_int64_t esrc=extmac(src,vlan);
	int k = calc_hash(esrc);
	in_addr_t oldport;
	time_t now;
	for(e = h[k]; e && e->dst != esrc; e = e->next)
		;
	if(e == NULL) {
		e = (struct hash_entry *) malloc(sizeof(*e));
		if(e == NULL){
			printlog(LOG_WARNING,"Failed to malloc hash entry %s",strerror(errno));
			return 0;
		}

		DBGOUT(DBGHASHNEW,"%02x:%02x:%02x:%02x:%02x:%02x VLAN %02x:%02x Port %d",
				EMAC2MAC6(esrc), EMAC2VLAN2(esrc), port);
		EVENTOUT(DBGHASHNEW,esrc);
		e->dst = esrc;
		if(h[k] != NULL) h[k]->prev = &(e->next);
		e->next = h[k];
		e->prev = &(h[k]);
		e->port = port;
		h[k] = e;
	}
	oldport=e->port;
	now=time(NULL);
	if (oldport!=port) {
		if ((now - e->last_seen) > min_persistence) {
			e->port=port;
			e->last_seen = now;
		}
	} else {
		e->last_seen = now;
	}
	if (out != NULL) *out = oldport;
	return 1;
}

#define delete_hash_entry(OLD) \
	({ \
	 DBGOUT(DBGHASHDEL,"%02x:%02x:%02x:%02x:%02x:%02x VLAN %02x:%02x Port %d", EMAC2MAC6(OLD->dst), EMAC2VLAN2(OLD->dst), OLD->port); \
	 EVENTOUT(DBGHASHDEL,OLD->dst);\
	 *((OLD)->prev)=(OLD)->next; \
	 if((OLD)->next != NULL) (OLD)->next->prev = (OLD)->prev; \
	 free((OLD)); \
	 })


/* for each entry of the global hash table 'h', calls function f, passing to it
 * the hash entry and the additional arg 'arg' */
static void for_all_hash(void (*f)(struct hash_entry *, void *), void *arg)
{
	int i;
	struct hash_entry *e, *next;

	for(i = 0; i < HASH_SIZE; i++){
		for(e = h[i]; e; e = next){
			next = e->next;
			(*f)(e, arg);
		}
	}
}

#define GC_INTERVAL 2
#define GC_EXPIRE 100
static int gc_interval;
static int gc_expire;

/* clean from the hash table entries older than GC_EXPIRE seconds, given that
 * 'now' points to a time_t structure describing the current time */
static void gc(struct hash_entry *e, void *now)
{
	time_t t = *(time_t *) now;
	if(e->last_seen + gc_expire < t)
		delete_hash_entry(e);
}

/* clean old entries in the hash table 'h', and prepare the timer to be called
 * again between GC_INTERVAL seconds */
void hash_gc(void)
{
	time_t t = time(NULL);
	static time_t last_t;
	if (t - last_t > GC_INTERVAL) {
		for_all_hash(&gc, &t);
		last_t=t;
	}
}

#define HASH_INIT(BIT) \
	({ hash_bits=(BIT);\
	 hash_mask=HASH_SIZE-1;\
	 if ((h=(struct hash_entry **) calloc (HASH_SIZE,sizeof (struct hash_entry *))) == NULL) {\
	 printlog(LOG_WARNING,"Failed to malloc hash table %s",strerror(errno));\
	 exit(1); \
	 }\
	 })

static inline int po2round(int vx)
{
	if (vx == 0)
		return 0;
	else {
		register int i=0;
		register int x=vx-1;
		while (x) { x>>=1; i++; }
		if (vx != 1<<i)
			printlog(LOG_WARNING,"Hash size must be a power of 2. %d rounded to %d",vx,1<<i);
		return i;
	}
}

int hash_set_gc_interval(int p)
{
	gc_interval=p;
	return 0;
}

int hash_set_gc_expire(int e)
{
	gc_expire=e;
	return 0;
}

int hash_set_minper(int e)
{
	min_persistence=e;
	return 0;
}

/* sets sig_alarm as handler for SIGALRM, and run it a first time */
void hash_init(int hash_size)
{
	HASH_INIT(po2round(hash_size));

	gc_interval=GC_INTERVAL;
	gc_expire=GC_EXPIRE;
}
