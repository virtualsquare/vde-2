/*
 * Inter process networking (virtual distributed ethernet) module
 * Hash table for Ethernet management
 *  (part of the View-OS project: wiki.virtualsquare.org) 
 *
 * Copyright (C) 2007   Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 * WARNING: THIS CODE IS ALREADY EXTREEEEMELY EXPERIMENTAL
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include "../af_ipn.h"
#include "ipn_hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIEW-OS TEAM");
MODULE_DESCRIPTION("Ethernet hash table Kernel Module");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define IPN_PRE390
#endif

#undef IPN_DEBUG

static struct kmem_cache *ipn_hash_elem_cache;
static void ipn_hash_timer_expired(unsigned long arg);

struct ipn_hash_elem {
	struct hlist_node hashnode;
	struct list_head lrunode;
	u16 key[4];
	int port;
	u64 expiretime;
};

static inline int po2round(int vx)
{
	register int rv=1;
	register int x=vx-1;
	for (x=vx-1; x;  x>>=1)
		rv<<=1;
	return (rv);
}

static inline int hashfun(u16 *key,u16 vlan,int mask)
{
	register int x=key[0] * 0x03050000 + key[1] * 0x0709 +
		key[2] * 0x0b0d0000 + vlan *0x1113;
	x = (x ^ x >> 12 ^ x >> 8 ^ x >> 4) & mask;
	return x;
}

int ipn_hash_new(struct ipn_hash *vdeh,int size,unsigned long timeout)
{
	if (size<=0 || timeout <=0)
		return -EINVAL;
	vdeh->hashtable=kzalloc(sizeof(struct hlist_head)*size,GFP_KERNEL);
	if (!vdeh->hashtable)
		return -ENOMEM;
	INIT_LIST_HEAD(&vdeh->lrulist);
	vdeh->mask=po2round(size)-1;
	vdeh->timeout=timeout * HZ;
	spin_lock_init(&vdeh->hashlock);
	setup_timer(&vdeh->hashtimer,ipn_hash_timer_expired,
			(unsigned long) vdeh);
	return 0;
}

static void _ipn_hash_flush(struct ipn_hash *vdeh)
{
	struct list_head *node;
	struct list_head *temp;
	list_for_each_safe(node,temp,&vdeh->lrulist) {
		struct ipn_hash_elem *elem=list_entry(node,struct ipn_hash_elem,lrunode);
#ifdef IPN_DEBUG
		printk("HASH DELETED FLUSH %x %x %x %x\n", elem->key[0], elem->key[1], elem->key[2], elem->key[3]);
#endif
		list_del(&elem->lrunode);
		hlist_del(&elem->hashnode);
		kmem_cache_free(ipn_hash_elem_cache,elem);
	}
}

void ipn_hash_flush(struct ipn_hash *vdeh)
{
	spin_lock(&vdeh->hashlock);
	_ipn_hash_flush(vdeh);
	spin_unlock(&vdeh->hashlock);
}

void ipn_hash_flush_key(struct ipn_hash *vdeh,u16 *key,u16 *vlan)
{
	struct list_head *node;
	struct list_head *temp;
	spin_lock(&vdeh->hashlock);
	list_for_each_safe(node,temp,&vdeh->lrulist) {
		struct ipn_hash_elem *elem=list_entry(node,struct ipn_hash_elem,lrunode);
		if ((!key || (elem->key[0]==key[0] &&
						elem->key[1]==key[1] &&
						elem->key[2]==key[2])) ||
				(!vlan || elem->key[3]==*vlan)) {
#ifdef IPN_DEBUG
			printk("HASH DELETED FLUSH KEY %x %x %x %x\n", elem->key[0], elem->key[1], elem->key[2], elem->key[3]);
#endif
			list_del(&elem->lrunode);
			hlist_del(&elem->hashnode);
			kmem_cache_free(ipn_hash_elem_cache,elem);
		}
	}
	spin_unlock(&vdeh->hashlock);
}

void ipn_hash_flush_port(struct ipn_hash *vdeh,int port)
{
	struct list_head *node;
	struct list_head *temp;
	spin_lock(&vdeh->hashlock);
	list_for_each_safe(node,temp,&vdeh->lrulist) {
		struct ipn_hash_elem *elem=list_entry(node,struct ipn_hash_elem,lrunode);
		if (elem->port==port) {
#ifdef IPN_DEBUG
			printk("HASH DELETED FLUSH PORT %x %x %x %x\n", elem->key[0], elem->key[1], elem->key[2], elem->key[3]);
#endif
			list_del(&elem->lrunode);
			hlist_del(&elem->hashnode);
			kmem_cache_free(ipn_hash_elem_cache,elem);
		}
	}
	spin_unlock(&vdeh->hashlock);
}

void ipn_hash_free(struct ipn_hash *vdeh)
{
	spin_lock(&vdeh->hashlock);
	_ipn_hash_flush(vdeh);
	del_timer_sync(&vdeh->hashtimer);
	kfree(vdeh->hashtable);
	spin_unlock(&vdeh->hashlock);
}

static void ipn_hash_timer_expired(unsigned long arg)
{
	struct ipn_hash *vdeh=(struct ipn_hash *) arg;
	struct list_head *node;
	struct list_head *temp;
	u64 jiffies64;
	spin_lock(&vdeh->hashlock);
	jiffies64=get_jiffies_64();
#ifdef IPN_DEBUG
	printk("HASH TIMER %lld\n",jiffies64);
#endif
	list_for_each_safe(node,temp,&vdeh->lrulist) {
		struct ipn_hash_elem *elem=list_entry(node,struct ipn_hash_elem,lrunode);
		long next=elem->expiretime-jiffies64;
		if (next < 0) {
#ifdef IPN_DEBUG
			printk("HASH DELETED TIMER %x %x %x %x\n", elem->key[0], elem->key[1], elem->key[2], elem->key[3]);
#endif
			list_del(&elem->lrunode);
			hlist_del(&elem->hashnode);
			kmem_cache_free(ipn_hash_elem_cache,elem);
		} else {
			mod_timer(&vdeh->hashtimer,jiffies+(unsigned long)next);
			break;
		}
	}
	spin_unlock(&vdeh->hashlock);
}

void ipn_hash_add(struct ipn_hash *vdeh,u16 *key,u16 vlan,int port)
{
	struct ipn_hash_elem *elem=NULL;
	int hashvalue=hashfun(key,vlan,vdeh->mask);
	int found=0;
	spin_lock(&vdeh->hashlock);
#ifdef PRE390
	struct hlist_node *node;
	hlist_for_each_entry(elem, node,
			&vdeh->hashtable[hashvalue], hashnode) 
#else
	hlist_for_each_entry(elem,
			&vdeh->hashtable[hashvalue], hashnode) 
#endif
	{
		if (elem->key[0]==key[0] && elem->key[1]==key[1] &&
				elem->key[2]==key[2] && elem->key[3]==vlan) {
			found=1;
			break;
		}
	} 
	if (found) {
#ifdef IPN_DEBUG
		printk("FOUND SENDER %x %x %x %x (%d) <- %d (was %d)\n", key[0], key[1], key[2], vlan,hashvalue,port,elem->port);
#endif
		list_del(&elem->lrunode);
		hlist_del(&elem->hashnode);
	} else if (vdeh->timeout>0){ /* vdeh->timeout == 0 means HUB */
#ifdef IPN_DEBUG
		printk("NEW HASH %x %x %x %x (%d) <- %d\n", key[0], key[1], key[2], vlan, hashvalue,port);
#endif
		elem=kmem_cache_alloc(ipn_hash_elem_cache,GFP_KERNEL);
		if (elem) {
			elem->key[0]=key[0]; elem->key[1]=key[1];
			elem->key[2]=key[2]; elem->key[3]=vlan;
		}
	} 
	if (elem) {
		elem->port=port;
		list_add_tail(&elem->lrunode,&vdeh->lrulist);
		hlist_add_head(&elem->hashnode,&vdeh->hashtable[hashvalue]);
		if (!timer_pending(&vdeh->hashtimer))
			mod_timer(&vdeh->hashtimer,jiffies + vdeh->timeout);
		elem->expiretime=get_jiffies_64() + vdeh->timeout;
	}
	spin_unlock(&vdeh->hashlock);
}

int ipn_hash_find(struct ipn_hash *vdeh,u16 *key,u16 vlan)
{
	struct ipn_hash_elem *elem;
	int rv=-1;
	int hashvalue=hashfun(key,vlan,vdeh->mask);

	spin_lock(&vdeh->hashlock);
#ifdef IPN_DEBUG
	printk("SEARCH HASH %x %x %x %x \n", key[0], key[1], key[2], vlan);
#endif
#ifdef PRE390
	struct hlist_node *node;
	hlist_for_each_entry(elem, node,
			&vdeh->hashtable[hashvalue], hashnode) 
#else
	hlist_for_each_entry(elem,
			&vdeh->hashtable[hashvalue], hashnode) 
#endif
	{
		if (elem->key[0]==key[0] && elem->key[1]==key[1] &&
				elem->key[2]==key[2] && elem->key[3]==vlan) {
			rv=elem->port;
#ifdef IPN_DEBUG
			printk("FOUND HASH %x %x %x %x -> %d\n", key[0], key[1], key[2], vlan, rv);
#endif
			break;
		}
	}
	spin_unlock(&vdeh->hashlock);
	return rv;
}

int ipn_hash_init(void)
{
	ipn_hash_elem_cache=kmem_cache_create("ipn_hash",sizeof(struct ipn_hash_elem),0,0,NULL);
	if (ipn_hash_elem_cache)
		return 0;
	else
		return -ENOMEM;
}

void ipn_hash_fini(void)
{
	if (ipn_hash_elem_cache)
		kmem_cache_destroy(ipn_hash_elem_cache);
}

EXPORT_SYMBOL_GPL(ipn_hash_new);
EXPORT_SYMBOL_GPL(ipn_hash_flush);
EXPORT_SYMBOL_GPL(ipn_hash_flush_key);
EXPORT_SYMBOL_GPL(ipn_hash_flush_port);
EXPORT_SYMBOL_GPL(ipn_hash_free);
EXPORT_SYMBOL_GPL(ipn_hash_add);
EXPORT_SYMBOL_GPL(ipn_hash_find);

module_init(ipn_hash_init);
module_exit(ipn_hash_fini);

