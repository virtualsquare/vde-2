/*
 * Inter process networking (virtual distributed ethernet) module
 * Net devices: tap and grab
 *  (part of the View-OS project: wiki.virtualsquare.org)
 *
 * Copyright (C) 2007,2009   Renzo Davoli (renzo@cs.unibo.it)
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
#include <linux/socket.h>
#include <linux/poll.h>
#include <linux/un.h>
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/version.h>
#include <net/sock.h>
#include "af_ipn.h"
#include "ipn_netdev.h"

#define DRV_NAME  "ipn"
#define DRV_VERSION "0.3.1"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define IPN_PRE2624
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define IPN_PRE2629
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define IPN_PRE2637
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define IPN_PRE2639
#endif

static const struct ethtool_ops ipn_ethtool_ops;

struct ipntap {
	struct ipn_node *ipn_node;
	struct net_device_stats stats;
};

/* TAP Net device open. */
static int ipntap_net_open(struct net_device *dev)
{
	  netif_start_queue(dev);
		  return 0;
}

/* TAP Net device close. */
static int ipntap_net_close(struct net_device *dev)
{
	  netif_stop_queue(dev);
		  return 0;
}

static struct net_device_stats *ipntap_net_stats(struct net_device *dev)
{
	struct ipntap *ipntap = netdev_priv(dev);
	return &ipntap->stats;
}

/* receive from a TAP */
static int ipn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipntap *ipntap = netdev_priv(dev);
	struct ipn_node *ipn_node=ipntap->ipn_node;
	struct msgpool_item *newmsg;
	if (!ipn_node || !ipn_node->ipn || skb->len > ipn_node->ipn->mtu)
		goto drop;
	newmsg=ipn_msgpool_alloc(ipn_node->ipn,1,skb->len);
	if (!newmsg)
		goto drop;
	newmsg->len=skb->len;
	memcpy(newmsg->data,skb->data,skb->len);
	ipn_proto_injectmsg(ipntap->ipn_node,newmsg);
	ipn_msgpool_put(newmsg,ipn_node->ipn);
	ipntap->stats.tx_packets++;
	ipntap->stats.tx_bytes += skb->len;
	kfree_skb(skb);
	return 0;

drop:
	ipntap->stats.tx_dropped++;
	kfree_skb(skb);
	return 0;
}

#ifdef IPN_PRE2637
/* receive from a GRAB via interface hook */
struct sk_buff *ipn_handle_hook(struct ipn_node *ipn_node, struct sk_buff *skb)
#else
#ifdef IPN_PRE2639
static struct sk_buff *ipn_handle_frame(struct sk_buff *skb)
#else
static rx_handler_result_t ipn_handle_frame(struct sk_buff **pskb)
#endif
#endif
{
#ifndef IPN_PRE2639
	struct sk_buff *skb = *pskb;
#endif
	char *data=(skb->data)-(skb->mac_len);
	int len=skb->len+skb->mac_len;
#ifndef IPN_PRE2637
	struct ipn_node *ipn_node=ipn_netdev2node(skb->dev);
#endif

	if (ipn_node &&
			((ipn_node->flags & IPN_NODEFLAG_DEVMASK) == IPN_NODEFLAG_GRAB) &&
			ipn_node->ipn && len<=ipn_node->ipn->mtu) {
		struct msgpool_item *newmsg;
		newmsg=ipn_msgpool_alloc(ipn_node->ipn,1,len);
		if (newmsg) {
			newmsg->len=len;
			memcpy(newmsg->data,data,len);
			ipn_proto_injectmsg(ipn_node,newmsg);
			ipn_msgpool_put(newmsg,ipn_node->ipn);
		}
	}

#ifdef IPN_PRE2639
	return (skb);
#else
	return RX_HANDLER_PASS;
#endif
}

#ifndef IPN_PRE2629
static struct net_device_ops ipntap_netdev_ops = {
	.ndo_open = ipntap_net_open,
	.ndo_start_xmit = ipn_net_xmit,
	.ndo_stop = ipntap_net_close,
	.ndo_get_stats = ipntap_net_stats
};
#endif

static void ipntap_setup(struct net_device *dev)
{
#ifdef IPN_PRE2629
	dev->open = ipntap_net_open;
	dev->hard_start_xmit = ipn_net_xmit;
	dev->stop = ipntap_net_close;
	dev->get_stats = ipntap_net_stats;
#endif
	dev->ethtool_ops = &ipn_ethtool_ops;
}

struct net_device *ipn_netdev_alloc(struct net *net,int type, char *name, int *err)
{
	struct net_device *dev=NULL;
	*err=0;
	if (!name || *name==0)
		name="ipn%d";
	switch (type) {
		case IPN_NODEFLAG_TAP:
			dev=alloc_netdev(sizeof(struct ipntap), name, ipntap_setup);
			if (!dev)
				*err= -ENOMEM;
#ifndef IPN_PRE2629
			dev_net_set(dev, net);
			dev->netdev_ops = &ipntap_netdev_ops;
#endif
			ether_setup(dev);
			if (strchr(dev->name, '%')) {
				*err = dev_alloc_name(dev, dev->name);
				if (*err < 0) {
					free_netdev(dev);
					return NULL;
				}
			}
			random_ether_addr(dev->dev_addr);
			break;
		case IPN_NODEFLAG_GRAB:
#ifdef IPN_PRE2637
#ifdef IPN_STEALING
			/* only if bridge is not working */
			if (ipn_handle_frame_hook != (void *) ipn_handle_hook) {
				printk (KERN_WARNING "IPN interface GRAB disabled (stealing mode) if bridge is loaded\n");
				return NULL;
			}
#endif
#endif
#ifdef IPN_PRE2624
			dev=dev_get_by_name(name);
#else
			dev=dev_get_by_name(net,name);
#endif
			if (dev) {
				if (dev->flags & IFF_LOOPBACK)
					*err= -EINVAL;
#ifdef IPN_PRE2637
				else if (rcu_dereference(dev->ipn_port) != NULL)
					*err= -EBUSY;
#else
				else if (rcu_dereference(dev->rx_handler) != NULL)
					*err= -EBUSY;
#endif
				if (*err)
					dev=NULL;
			}
			break;
	}
	return dev;
}

int ipn_netdev_activate(struct ipn_node *ipn_node)
{
	int rv=-EINVAL;
	switch (ipn_node->flags & IPN_NODEFLAG_DEVMASK) {
		case IPN_NODEFLAG_TAP:
			{
				struct ipntap *ipntap=netdev_priv(ipn_node->netdev);
				ipntap->ipn_node=ipn_node;
				rtnl_lock();
				if ((rv=register_netdevice(ipn_node->netdev)) == 0) {
#ifdef IPN_PRE2637
					rcu_assign_pointer(ipn_node->netdev->ipn_port,
#ifdef IPN_STEALING
							(void *)
#endif
							ipn_node);
#else
					netdev_rx_handler_register(ipn_node->netdev,
							ipn_handle_frame,
							ipn_node);
#endif
				}
				rtnl_unlock();
				if (rv) {/* error! */
					ipn_node->flags &= ~IPN_NODEFLAG_DEVMASK;
					free_netdev(ipn_node->netdev);
				}
			}
			break;
		case IPN_NODEFLAG_GRAB:
			rtnl_lock();
#ifdef IPN_PRE2637
			rcu_assign_pointer(ipn_node->netdev->ipn_port,
#ifdef IPN_STEALING
					(void *)
#endif
					ipn_node);
#else
			netdev_rx_handler_register(ipn_node->netdev,
					ipn_handle_frame,
					ipn_node);
#endif
			dev_set_promiscuity(ipn_node->netdev,1);
			rtnl_unlock();
			rv=0;
			break;
	}
	return rv;
}

void ipn_netdev_close(struct ipn_node *ipn_node)
{
	switch (ipn_node->flags & IPN_NODEFLAG_DEVMASK) {
		case IPN_NODEFLAG_TAP:
			ipn_node->flags &= ~IPN_NODEFLAG_DEVMASK;
			rtnl_lock();
#ifdef IPN_PRE2637
			rcu_assign_pointer(ipn_node->netdev->ipn_port, NULL);
#else
			netdev_rx_handler_unregister(ipn_node->netdev);
#endif
			unregister_netdevice(ipn_node->netdev);
			rtnl_unlock();
			free_netdev(ipn_node->netdev);
			break;
		case IPN_NODEFLAG_GRAB:
			ipn_node->flags &= ~IPN_NODEFLAG_DEVMASK;
			rtnl_lock();
#ifdef IPN_PRE2637
			rcu_assign_pointer(ipn_node->netdev->ipn_port, NULL);
#else
			netdev_rx_handler_unregister(ipn_node->netdev);
#endif
			dev_set_promiscuity(ipn_node->netdev,-1);
			rtnl_unlock();
			break;
	}
}

void ipn_netdev_sendmsg(struct ipn_node *to,struct msgpool_item *msg)
{
	struct sk_buff *skb;
	struct net_device *dev=to->netdev;
	struct ipntap *ipntap=netdev_priv(dev);
	
	if (msg->len > dev->mtu + dev->hard_header_len) {
		printk("ipn_netdev_sendmsg: dropping packet, msg->len > MTU+HDR\n");
		ipntap->stats.rx_dropped++;
		return;
	}
	skb=alloc_skb(msg->len+NET_IP_ALIGN,GFP_KERNEL);
	if (!skb) {
		printk("ipn_netdev_sendmsg: dropping packet, cannot alloc skb\n");
		ipntap->stats.rx_dropped++;
		return;
	}
	memcpy(skb_put(skb,msg->len),msg->data,msg->len);
	switch (to->flags & IPN_NODEFLAG_DEVMASK) {
		case IPN_NODEFLAG_TAP:
			skb->protocol = eth_type_trans(skb, dev);
			netif_rx_ni(skb);
			ipntap->stats.rx_packets++;
			ipntap->stats.rx_bytes += msg->len;
			break;
		case IPN_NODEFLAG_GRAB:
			skb->dev = dev;
			dev_queue_xmit(skb);
			break;
	}
}

/* ethtool interface */

static int ipn_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported    = 0;
	cmd->advertising  = 0;
	cmd->speed    = SPEED_10;
	cmd->duplex   = DUPLEX_FULL;
	cmd->port   = PORT_TP;
	cmd->phy_address  = 0;
	cmd->transceiver  = XCVR_INTERNAL;
	cmd->autoneg    = AUTONEG_DISABLE;
	cmd->maxtxpkt   = 0;
	cmd->maxrxpkt   = 0;
	return 0;
}

static void ipn_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");
}

static const struct ethtool_ops ipn_ethtool_ops = {
	.get_settings = ipn_get_settings,
	.get_drvinfo  = ipn_get_drvinfo,
	/* not implemented (yet?)
	.get_msglevel = ipn_get_msglevel,
	.set_msglevel = ipn_set_msglevel,
	.get_link = ipn_get_link,
	.get_rx_csum  = ipn_get_rx_csum,
	.set_rx_csum  = ipn_set_rx_csum */
};

int ipn_netdev_init(void)
{
#ifdef IPN_PRE2637
#ifdef IPN_STEALING
	if (ipn_handle_frame_hook != NULL) 
		printk (KERN_WARNING "IPN interface GRAB disabled (stealing mode) if bridge is loaded\n");
	else
#endif
		ipn_handle_frame_hook=
#ifdef IPN_STEALING
			(void *)
#endif
			ipn_handle_hook;
#endif

	return 0;
}

void ipn_netdev_fini(void)
{
#ifdef IPN_PRE2637
#ifdef IPN_STEALING
	/* only if bridge is not working */
	if (ipn_handle_frame_hook == (void *) ipn_handle_hook)
#endif
		ipn_handle_frame_hook=NULL;
#endif
}
