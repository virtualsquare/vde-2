/*
 * Inter process networking (virtual distributed ethernet) module
 * management of ipn_msgbuf (one slab for each MTU)
 *  (part of the View-OS project: wiki.virtualsquare.org) 
 *
 * N.B. all these functions need global locking! (ipn_glob_lock)
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
 * WARNING: THIS CODE IS ALREADY EXPERIMENTAL
 *
 */

#include <linux/init.h>
#include <linux/module.h>

#include "af_ipn.h"
#include "ipn_netdev.h"

struct ipn_msgbuf {
	struct list_head list;
	int mtu;
	int refcnt;
	char cachename[12];
	struct kmem_cache *cache;
};

static LIST_HEAD(ipn_msgbufh);
static struct kmem_cache *ipn_msgbuf_cache;

/* get a kmem_cache pointer for a given mtu.
 * it is a cache for struct msgpool_item elements (the latter field of
 * the struct, i.e. the payload, has variable length depending on the mtu)
 * if it exists already a cache with the given mtu, ipn_msgbuf_get creates
 * one more reference for that cache, otherwise a new one is created.
 */
struct kmem_cache *ipn_msgbuf_get(int mtu)
{
	struct ipn_msgbuf *ipn_msgbuf;
	list_for_each_entry(ipn_msgbuf, &ipn_msgbufh, list) {
		if (mtu == ipn_msgbuf->mtu) {
			ipn_msgbuf->refcnt++;
			return ipn_msgbuf->cache;
		}
	}
	ipn_msgbuf=kmem_cache_alloc(ipn_msgbuf_cache,GFP_KERNEL);
	if (ipn_msgbuf == NULL)
		return NULL;
	else {
		ipn_msgbuf->mtu=mtu;
		ipn_msgbuf->refcnt=1;
		snprintf(ipn_msgbuf->cachename,12,"ipn%d",mtu);
		ipn_msgbuf->cache=kmem_cache_create(ipn_msgbuf->cachename,sizeof(struct msgpool_item)+mtu,0,0,NULL);
		list_add_tail(&ipn_msgbuf->list,&ipn_msgbufh);
		return ipn_msgbuf->cache;
	}
}

/* release a reference of a msgbuf cache (a network with a given mtu
 * is terminating).
 * the last reference for a given mtu releases the slub*/
void ipn_msgbuf_put(struct kmem_cache *cache)
{
	struct ipn_msgbuf *ipn_msgbuf;
	list_for_each_entry(ipn_msgbuf, &ipn_msgbufh, list) {
		if (ipn_msgbuf->cache == cache) {
			ipn_msgbuf->refcnt--;
			if (ipn_msgbuf->refcnt == 0) {
				kmem_cache_destroy(ipn_msgbuf->cache);
				list_del(&ipn_msgbuf->list);
				kmem_cache_free(ipn_msgbuf_cache,ipn_msgbuf);
				return;
			}
		}
	}
}

int ipn_msgbuf_init(void)
{
	ipn_msgbuf_cache=kmem_cache_create("ipn_msgbuf",sizeof(struct ipn_msgbuf),0,0,NULL);
	if (!ipn_msgbuf_cache)
		return -ENOMEM;
	else
		return 0;
}

void ipn_msgbuf_fini(void)
{
	if (ipn_msgbuf_cache) {
		while (!list_empty(&ipn_msgbufh)) {
			struct ipn_msgbuf *ipn_msgbuf=list_first_entry(&ipn_msgbufh, struct ipn_msgbuf, list);
			list_del(&ipn_msgbuf->list);
			kmem_cache_destroy(ipn_msgbuf->cache);
			kmem_cache_free(ipn_msgbuf_cache,ipn_msgbuf);
		}
		kmem_cache_destroy(ipn_msgbuf_cache);
	}
}
