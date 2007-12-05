#ifndef _IPN_NETDEV_H
#define _IPN_NETDEV_H
/*
 * Inter process networking (virtual distributed ethernet) module
 * Net devices: tap and grab
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
#include <linux/socket.h>
#include <linux/poll.h>
#include <linux/un.h>
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/etherdevice.h>
/* We are stealing bridge structures, just for now */
#include <linux/if_bridge.h>
#include <net/sock.h>
#include "af_ipn.h"

struct net_device *ipn_netdev_alloc(int type, char *name, int *err);
int ipn_netdev_activate(struct ipn_node *ipn_node);
void ipn_netdev_close(struct ipn_node *ipn_node);
void ipn_netdev_sendmsg(struct ipn_node *to,struct msgpool_item *msg);
int ipn_netdev_init(void);
void ipn_netdev_fini(void);

inline struct ipn_node *ipn_netdev2node(struct net_device *dev)
{
	return (struct ipn_node *) rcu_dereference(dev->br_port);
}
#endif
