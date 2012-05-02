/* Copyright 2005 Renzo Davoli VDE-2
 * Copyright 2002 Yon Uriarte and Jeff Dike (uml_switch)
 * Licensed under the GPLv2
 * Modified 2003 Renzo Davoli
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
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

#include "switch.h"
#include "hash.h"
#include "qtimer.h"
#include "consmgmt.h"
#include "bitarray.h"

#define MIN_PERSISTENCE_DFL 3
static int min_persistence=MIN_PERSISTENCE_DFL;
#define HASH_INIT_BITS 7
static int hash_bits;
static int hash_mask;
#define HASH_SIZE (1 << hash_bits)

#ifdef DEBUGOPT
#define DBGHASHNEW (dl) 
#define DBGHASHDEL (dl+1) 
static struct dbgcl dl[]= {
	{"hash/+","hash: new element",D_HASH|D_PLUS},
	{"hash/-","hash: discarded element",D_HASH|D_MINUS},
};
#endif
struct hash_entry {
	struct hash_entry *next;
	struct hash_entry **prev;
	time_t last_seen;
	int port;
	uint64_t dst;
};

static struct hash_entry **h;

static int calc_hash(uint64_t src)
{
	register int x = src * 0x030507090b0d1113LL;
	x = (x ^ x >> 12 ^ x >> 8 ^ x >> 4) & hash_mask;
	/*printf("HASH %02x:%02x:%02x:%02x:%02x:%02x V%d -> %d\n", src[0], src[1], src[2], src[3], src[4], src[5],(src[6]>>8)+src[7],x);*/
	return x; 
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define EMAC2MAC6(X) \
	(uint32_t)((X)&0xff), (uint32_t)(((X)>>8)&0xff), (uint32_t)(((X)>>16)&0xff), \
  (uint32_t)(((X)>>24)&0xff), (uint32_t)(((X)>>32)&0xff), (uint32_t)(((X)>>40)&0xff)
#elif BYTE_ORDER == BIG_ENDIAN
#define EMAC2MAC6(X) \
	(uint32_t)(((X)>>24)&0xff), (uint32_t)(((X)>>16)&0xff), (uint32_t)(((X)>>8)&0xff), \
  (uint32_t)((X)&0xff), (uint32_t)(((X)>>40)&0xff), (uint32_t)(((X)>>32)&0xff)
#else
#error Unknown Endianess
#endif

#define EMAC2VLAN(X) ((uint16_t) ((X)>>48))
#define EMAC2VLAN2(X) ((uint32_t) (((X)>>48) &0xff)), ((uint32_t) (((X)>>56) &0xff))

#define find_entry(MAC) \
	({struct hash_entry *e; \
	 int k = calc_hash(MAC);\
	 for(e = h[k]; e && e->dst != (MAC); e = e->next)\
	 ;\
	 e; })


#define extmac(MAC,VLAN) \
	    ((*(uint32_t *) &((MAC)[0])) + ((uint64_t) ((*(uint16_t *) &((MAC)[4]))+ ((uint64_t) (VLAN) << 16)) << 32))

/* looks in global hash table 'h' for given address, and return associated
 * port */
int find_in_hash(unsigned char *dst,int vlan)
{
	struct hash_entry *e = find_entry(extmac(dst,vlan));
	if(e == NULL) return -1;
	return(e->port);
}


int find_in_hash_update(unsigned char *src,int vlan,int port)
{
	struct hash_entry *e;
	uint64_t esrc=extmac(src,vlan);
	int k = calc_hash(esrc);
	int oldport;
	time_t now;
	for(e = h[k]; e && e->dst != esrc; e = e->next)
		;
	if(e == NULL) {
		e = (struct hash_entry *) malloc(sizeof(*e));
		if(e == NULL){
			printlog(LOG_WARNING,"Failed to malloc hash entry %s",strerror(errno));
			return -1;
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
	now=qtime();
	if (oldport!=port) {
		if ((now - e->last_seen) > min_persistence) {
			e->port=port;
			e->last_seen = now;
		}
	} else {
		e->last_seen = now;
	}
	return oldport;
}

#define delete_hash_entry(OLD) \
	({ \
	 DBGOUT(DBGHASHDEL,"%02x:%02x:%02x:%02x:%02x:%02x VLAN %02x:%02x Port %d", EMAC2MAC6(OLD->dst), EMAC2VLAN2(OLD->dst), OLD->port); \
	 EVENTOUT(DBGHASHDEL,OLD->dst);\
	 *((OLD)->prev)=(OLD)->next; \
	 if((OLD)->next != NULL) (OLD)->next->prev = (OLD)->prev; \
	 free((OLD)); \
	 })


void delete_hash(unsigned char *dst,int vlan)
{
	struct hash_entry *old = find_entry(extmac(dst,vlan));

	if(old == NULL) return;
	qtime_csenter();
	delete_hash_entry(old);
	qtime_csexit();
}

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

static void delete_port_iterator (struct hash_entry *e, void *arg)
{
	int *pport=(int *)arg;
	if (e->port == *pport)
		delete_hash_entry(e);
}

void hash_delete_port (int port)
{
	qtime_csenter();
	for_all_hash(delete_port_iterator,&port);
	qtime_csexit();
}

static void delete_vlan_iterator (struct hash_entry *e, void *arg)
{
	int *vlan=(int *)arg;
	if (EMAC2VLAN(e->dst) == (uint16_t)(*vlan))
		delete_hash_entry(e);
}

void hash_delete_vlan (int vlan)
{
	qtime_csenter();
	for_all_hash(delete_vlan_iterator,&vlan);
	qtime_csexit();
}

struct vlanport {int vlan; int port;};

static void delete_vlanport_iterator (struct hash_entry *e, void *arg)
{
	struct vlanport *vp=(struct vlanport *)arg;
	if ((EMAC2VLAN(e->dst)) == (uint16_t)(vp->vlan) &&
			e->port == vp->port)
		delete_hash_entry(e);
}

void hash_delete_vlanport (int vlan,int port)
{
	struct vlanport vp={vlan,port};
	qtime_csenter();
	for_all_hash(delete_vlanport_iterator,&vp);
	qtime_csexit();
}

struct vlansetofports {int vlan; bitarray setofports;};

static void delete_vlansetofports_iterator (struct hash_entry *e, void *arg)
{
	struct vlansetofports *vp=(struct vlansetofports *)arg;
	if ((EMAC2VLAN(e->dst)) == (uint16_t)(vp->vlan) &&
			ba_check(vp->setofports,e->port))
		delete_hash_entry(e);
}

void hash_delete_vlanports (int vlan,bitarray setofports)
{
	struct vlansetofports vp={vlan,setofports};
	qtime_csenter();
	for_all_hash(delete_vlansetofports_iterator,&vp);
	qtime_csexit();
}

static void flush_iterator (struct hash_entry *e, void *arg)
{
	delete_hash_entry(e);
}

void hash_flush ()
{
	qtime_csenter();
	for_all_hash(flush_iterator,NULL);
	qtime_csexit();
}


#define GC_INTERVAL 2
#define GC_EXPIRE 100
static int gc_interval;
static int gc_expire;
static unsigned int gc_timerno;

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
static void hash_gc(void *arg)
{
	time_t t = qtime();
	for_all_hash(&gc, &t);
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

int hash_resize(int hash_size)
{
	if (hash_size > 0) {
		hash_flush();
		qtime_csenter();
		free(h);
		HASH_INIT(po2round(hash_size));
		qtime_csexit();
		return 0;
	} else
		return EINVAL;
}

int hash_set_gc_interval(int p)
{
	qtimer_del(gc_timerno);
	gc_interval=p;
	gc_timerno=qtimer_add(gc_interval,0,hash_gc,NULL);
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

int hash_get_gc_interval()
{
	return gc_interval;
}

int hash_get_gc_expire()
{
	return gc_expire;
}

static int find_hash(FILE *fd,char *strmac)
{
	int maci[ETH_ALEN];
	unsigned char macv[ETH_ALEN];
	unsigned char *mac=macv;
	int rv=-1;
	int vlan=0;
	struct hash_entry *e;
	if (index(strmac,':') != NULL)
		rv=sscanf(strmac,"%x:%x:%x:%x:%x:%x %d", maci+0, maci+1, maci+2, maci+3, maci+4, maci+5, &vlan);
	else
		rv=sscanf(strmac,"%x.%x.%x.%x.%x.%x %d", maci+0, maci+1, maci+2, maci+3, maci+4, maci+5, &vlan);
	if (rv < 6)
		return EINVAL;
	else	{
		register int i;
		for (i=0;i<ETH_ALEN;i++)
			mac[i]=maci[i];
		e=find_entry(extmac(mac,vlan));
		if (e==NULL)
			return ENODEV;
		else {
			printoutc(fd,"Hash: %04d Addr: %02x:%02x:%02x:%02x:%02x:%02x VLAN %04d to port: %03d  "
					"age %ld secs", calc_hash(e->dst),
				EMAC2MAC6(e->dst),EMAC2VLAN(e->dst), e->port+1, qtime() - e->last_seen);
			return 0;
		}
	}
}

static void print_hash_entry(struct hash_entry *e, void *arg)
{

	FILE *pfd=arg;
	printoutc(pfd,"Hash: %04d Addr: %02x:%02x:%02x:%02x:%02x:%02x VLAN %04d to port: %03d  " 
			"age %ld secs", calc_hash(e->dst),
			EMAC2MAC6(e->dst),EMAC2VLAN(e->dst), e->port, qtime() - e->last_seen);
}

static int print_hash(FILE *fd)
{
	qtime_csenter();
	for_all_hash(print_hash_entry, fd);
	qtime_csexit();
	return 0;
}

static int showinfo(FILE *fd)
{
	printoutc(fd,"Hash size %d",HASH_SIZE);
	printoutc(fd,"GC interval %d secs",gc_interval);
	printoutc(fd,"GC expire %d secs",gc_expire);
	printoutc(fd,"Min persistence %d secs",min_persistence);
	return 0;
}

static struct comlist cl[]={
	{"hash","============","HASH TABLE MENU",NULL,NOARG},
	{"hash/showinfo","","show hash info",showinfo,NOARG|WITHFILE},
	{"hash/setsize","N","change hash size",hash_resize,INTARG},
	{"hash/setgcint","N","change garbage collector interval",hash_set_gc_interval,INTARG},
	{"hash/setexpire","N","change hash entries expire time",hash_set_gc_expire,INTARG},
	{"hash/setminper","N","minimum persistence time",hash_set_minper,INTARG},
	{"hash/print","","print the hash table",print_hash,NOARG|WITHFILE},
	{"hash/find","MAC [VLAN]","MAC lookup",find_hash,STRARG|WITHFILE},
};

/* sets sig_alarm as handler for SIGALRM, and run it a first time */
void hash_init(int hash_size)
{
	HASH_INIT(po2round(hash_size));

	gc_interval=GC_INTERVAL;
	gc_expire=GC_EXPIRE;
	gc_timerno=qtimer_add(gc_interval,0,hash_gc,NULL);
	ADDCL(cl);
#ifdef DEBUGOPT
	ADDDBGCL(dl);
#endif
}
