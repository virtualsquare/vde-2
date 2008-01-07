#ifndef _IPN_HASH_H
#define _IPN_HASH_H
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
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/jiffies.h>

struct ipn_hash {
	struct hlist_head *hashtable;
	struct list_head lrulist;
	int mask;  /* size-1 where size must be a power of 2 */
	unsigned long timeout;
	spinlock_t hashlock;
	struct timer_list hashtimer;
};

int ipn_hash_new(struct ipn_hash *vdeh,int size,unsigned long timeout);
void ipn_hash_flush(struct ipn_hash *vdeh);
void ipn_hash_flush_key(struct ipn_hash *vdeh,u16 *key,u16 *vlan);
void ipn_hash_flush_port(struct ipn_hash *vdeh,int port);
void ipn_hash_free(struct ipn_hash *vdeh);
void ipn_hash_add(struct ipn_hash *vdeh,u16 *key,u16 vlan,int port);
int ipn_hash_find(struct ipn_hash *vdeh,u16 *key,u16 vlan);
int ipn_hash_init(void);
void ipn_hash_fini(void);
#endif
