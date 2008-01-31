/*
 * Main inter process networking (virtual distributed ethernet) module
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
#include <linux/version.h>
#include <net/sock.h>
/*
#include <net/af_ipn.h>
*/
#include "af_ipn.h"
#include "ipn_netdev.h"
#include "ipn_msgbuf.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIEW-OS TEAM");
MODULE_DESCRIPTION("IPN Kernel Module");

#define IPN_MAX_PROTO 4

/*extension of RCV_SHUTDOWN defined in include/net/sock.h
 * when the bit is set recv fails */
/* NO_OOB: do not send OOB */
#define RCV_SHUTDOWN_NO_OOB	4
/* EXTENDED MASK including OOB */
#define SHUTDOWN_XMASK	(SHUTDOWN_MASK | RCV_SHUTDOWN_NO_OOB)
/* if XRCV_SHUTDOWN is all set recv fails */
#define XRCV_SHUTDOWN	(RCV_SHUTDOWN | RCV_SHUTDOWN_NO_OOB)

/* Network table and hash */
struct hlist_head ipn_network_table[IPN_HASH_SIZE + 1];
/* not needed. Now protected by ipn_glob_mutex 
 * comment *IPNTL*
 * DEFINE_SPINLOCK(ipn_table_lock);
 */
static struct kmem_cache *ipn_network_cache;
static struct kmem_cache *ipn_node_cache;
static struct kmem_cache *ipn_msgitem_cache;
static DECLARE_MUTEX(ipn_glob_mutex);

/* Protocol 1: HUB/Broadcast default protocol. Function Prototypes */
static int ipn_bcast_newport(struct ipn_node *newport);
static int ipn_bcast_handlemsg(struct ipn_node *from, 
		struct msgpool_item *msgitem);

/* default protocol IPN_BROADCAST (0) */
static struct ipn_protocol ipn_bcast = {
	.refcnt=0,
	.ipn_p_newport=ipn_bcast_newport, 
	.ipn_p_handlemsg=ipn_bcast_handlemsg};
/* Protocol table */
static struct ipn_protocol *ipn_protocol_table[IPN_MAX_PROTO]={&ipn_bcast};

/* Socket call function prototypes */
static int ipn_release(struct socket *);
static int ipn_bind(struct socket *, struct sockaddr *, int);
static int ipn_connect(struct socket *, struct sockaddr *,
		int addr_len, int flags);
static int ipn_getname(struct socket *, struct sockaddr *, int *, int);
static unsigned int ipn_poll(struct file *, struct socket *, poll_table *);
static int ipn_ioctl(struct socket *, unsigned int, unsigned long);
static int ipn_shutdown(struct socket *, int);
static int ipn_sendmsg(struct kiocb *, struct socket *,
		struct msghdr *, size_t);
static int ipn_recvmsg(struct kiocb *, struct socket *,
		struct msghdr *, size_t, int);
static int ipn_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int optlen);
static int ipn_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen);

/* Network table Management 
 * inode->ipn_network hash table 
 * LOCKING: MUTEX ipn_glob_mutex must be LOCKED*/
static inline void ipn_insert_network(struct hlist_head *list, struct ipn_network *ipnn)
{
	/* *IPNTL* spin_lock(&ipn_table_lock); */
	hlist_add_head(&ipnn->hnode, list);
	/* *IPNTL* spin_unlock(&ipn_table_lock); */
}

static inline void ipn_remove_network(struct ipn_network *ipnn)
{
	/* *IPNTL* spin_lock(&ipn_table_lock); */
	hlist_del(&ipnn->hnode);
	/* *IPNTL* spin_unlock(&ipn_table_lock); */
}

static struct ipn_network *ipn_find_network_byinode(struct inode *i)
{
	struct ipn_network *ipnn;
	struct hlist_node *node;

	/* *IPNTL* spin_lock(&ipn_table_lock);*/
	hlist_for_each_entry(ipnn, node,
			&ipn_network_table[i->i_ino & (IPN_HASH_SIZE - 1)], hnode) {
		struct dentry *dentry = ipnn->dentry;

		if(ipnn->refcnt > 0 && dentry && dentry->d_inode == i)
			goto found;
	}
	ipnn = NULL;
found:
	/* *IPNTL* spin_unlock(&ipn_table_lock); */
	return ipnn;
}

/* msgpool management 
 * msgpool_item are ipn_network dependent (each net has its own MTU)
 * for each message sent there is one msgpool_item and many struct msgitem
 * one for each receipient. 
 * msgitem are connected to the node's msgqueue or oobmsgqueue.
 * when a message is delivered to a process the msgitem is deleted and
 * the count of the msgpool_item is decreased.
 * msgpool_item elements gets deleted automatically when count is 0*/

struct msgitem {
	struct list_head list;
	struct msgpool_item *msg;
};

/* alloc a fresh msgpool item. count is set to 1.
 * the typical use is
 *  ipn_msgpool_alloc
 *  for each receipient
 *    enqueue messages to the process (using msgitem), ipn_msgpool_hold 
 *  ipn_msgpool_put
 * The message can be delivered concurrently. init count to 1 guarantees
 * that it survives at least until is has been enqueued to all
 * receivers */
static struct msgpool_item *_ipn_msgpool_alloc(struct ipn_network *ipnn)
{
	struct msgpool_item *new;
	if ((new=kmem_cache_alloc(ipnn->msgpool_cache,GFP_KERNEL)) != NULL) {
		atomic_set(&new->count,1);
		atomic_inc(&ipnn->msgpool_nelem);
	}
	return new;
}

struct msgpool_item *ipn_msgpool_alloc(struct ipn_network *ipnn,int leaky)
{
	  if (leaky && (ipnn->flags & IPN_FLAG_LOSSLESS) &&
				atomic_read(&ipnn->msgpool_nelem) < ipnn->msgpool_size)
			return NULL;
		else 
			return _ipn_msgpool_alloc(ipnn);
}

/* If the service il LOSSLESS, this msgpool call waits for an
 * available msgpool item */
static struct msgpool_item *ipn_msgpool_alloc_locking(struct ipn_network *ipnn)
{
	if (ipnn->flags & IPN_FLAG_LOSSLESS) {
		while (atomic_read(&ipnn->msgpool_nelem) >= ipnn->msgpool_size) {
			if (wait_event_interruptible_exclusive(ipnn->send_wait,
						atomic_read(&ipnn->msgpool_nelem) < ipnn->msgpool_size))
				return NULL;
		}
	}
	return _ipn_msgpool_alloc(ipnn);
}

static inline void ipn_msgpool_hold(struct msgpool_item *msg)
{
	atomic_inc(&msg->count);
}

/* decrease count and delete msgpool_item if count == 0 */
void ipn_msgpool_put(struct msgpool_item *old,
		struct ipn_network *ipnn)
{
	if (atomic_dec_and_test(&old->count)) {
		kmem_cache_free(ipnn->msgpool_cache,old);
		atomic_dec(&ipnn->msgpool_nelem);
		if (ipnn->flags & IPN_FLAG_LOSSLESS) /* this could be done anyway */
			wake_up_interruptible(&ipnn->send_wait);
	}
}

/* socket calls */
static const struct proto_ops ipn_ops = {
	.family = PF_IPN,
	.owner =  THIS_MODULE,
	.release =  ipn_release,
	.bind =   ipn_bind,
	.connect =  ipn_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname =  ipn_getname,
	.poll =   ipn_poll,
	.ioctl =  ipn_ioctl,
	.listen = sock_no_listen,
	.shutdown = ipn_shutdown,
	.setsockopt = ipn_setsockopt,
	.getsockopt = ipn_getsockopt,
	.sendmsg =  ipn_sendmsg,
	.recvmsg =  ipn_recvmsg,
	.mmap =   sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto ipn_proto = {
	.name   = "IPN",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct ipn_sock),
};

/* create a socket
 * ipn_node is a separate structure, pointed by ipn_sock -> node
 * when a node is "persistent", ipn_node survives while ipn_sock gets released*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static int ipn_create(struct socket *sock, int protocol)
#else
static int ipn_create(struct net *net,struct socket *sock, int protocol)
#endif
{
	struct ipn_sock *ipn_sk;
	struct ipn_node *ipn_node;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	void *net=NULL;
#else
	if (net != &init_net)
		return -EAFNOSUPPORT;
#endif

	if (sock->type != SOCK_RAW)
		return -EPROTOTYPE;
	if (protocol > 0)
		protocol=protocol-1;
	else
		protocol=IPN_BROADCAST-1;
	if (protocol < 0 || protocol >= IPN_MAX_PROTO ||
			ipn_protocol_table[protocol] == NULL)
		return -EPROTONOSUPPORT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	ipn_sk = (struct ipn_sock *) sk_alloc(PF_IPN, GFP_KERNEL, &ipn_proto, 1);
#else
	ipn_sk = (struct ipn_sock *) sk_alloc(net, PF_IPN, GFP_KERNEL, &ipn_proto);
#endif

	if (!ipn_sk) 
		return -ENOMEM;
	ipn_sk->node=ipn_node=kmem_cache_alloc(ipn_node_cache,GFP_KERNEL);
	if (!ipn_node) {
		sock_put((struct sock *) ipn_sk);
		return -ENOMEM;
	}
	sock_init_data(sock,(struct sock *) ipn_sk);
	sock->state = SS_UNCONNECTED;
	sock->ops = &ipn_ops;
	sock->sk=(struct sock *)ipn_sk;
	INIT_LIST_HEAD(&ipn_node->nodelist);
	ipn_node->protocol=protocol;
	ipn_node->flags=IPN_NODEFLAG_INUSE;
	ipn_node->shutdown=RCV_SHUTDOWN_NO_OOB;
	ipn_node->descr[0]=0;
	ipn_node->portno=IPN_PORTNO_ANY;
	ipn_node->net=net;
	ipn_node->dev=NULL;
	ipn_node->proto_private=NULL;
	ipn_node->totmsgcount=0;
	ipn_node->oobmsgcount=0;
	spin_lock_init(&ipn_node->msglock);
	INIT_LIST_HEAD(&ipn_node->msgqueue);
	INIT_LIST_HEAD(&ipn_node->oobmsgqueue);
	ipn_node->ipn=NULL;
	init_waitqueue_head(&ipn_node->read_wait);
	ipn_node->pbp=NULL;
	return 0;
}

/* update # of readers and # of writers counters for an ipn network.
 * This function sends oob messages to nodes requesting the service */
/* LOCKING ipnn_mutex is locked */
static void ipn_net_update_counters(struct ipn_network *ipnn,
		int chg_readers, int chg_writers) {
	ipnn->numreaders += chg_readers;
	ipnn->numwriters += chg_writers;
	if (ipnn->mtu >= sizeof(struct numnode_oob))
	{
		struct msgpool_item *ipn_msg=_ipn_msgpool_alloc(ipnn);
		if (ipn_msg) {
			struct numnode_oob *oob_msg=(struct numnode_oob *)(ipn_msg->data);
			struct ipn_node *ipn_node;
			ipn_msg->len=sizeof(struct numnode_oob);
			oob_msg->level=IPN_ANY;
			oob_msg->tag=IPN_OOB_NUMNODE_TAG;
			oob_msg->numreaders=ipnn->numreaders;
			oob_msg->numwriters=ipnn->numwriters;
			list_for_each_entry(ipn_node, &ipnn->connectqueue, nodelist) {
				if (ipn_node->flags & IPN_NODEFLAG_OOB_NUMNODES)
					ipn_proto_oobsendmsg(ipn_node,ipn_msg);
			}
			ipn_msgpool_put(ipn_msg,ipnn);
		}
	}
}

/* flush pending messages (for close and shutdown RCV) */
/* LOCKING: ipnn_mutex is locked */
static void ipn_flush_recvqueue(struct ipn_node *ipn_node)
{
	struct ipn_network *ipnn=ipn_node->ipn;
	spin_lock(&ipn_node->msglock);
	while (!list_empty(&ipn_node->msgqueue)) {
		struct msgitem *msgitem=
			list_first_entry(&ipn_node->msgqueue, struct msgitem, list);
		list_del(&msgitem->list);
		ipn_node->totmsgcount--;
		ipn_msgpool_put(msgitem->msg,ipnn);
		kmem_cache_free(ipn_msgitem_cache,msgitem);
	}
	spin_unlock(&ipn_node->msglock);
}

/* flush pending oob messages (for socket close) */
/* LOCKING: ipnn_mutex is locked */
static void ipn_flush_oobrecvqueue(struct ipn_node *ipn_node)
{
	struct ipn_network *ipnn=ipn_node->ipn;
	spin_lock(&ipn_node->msglock);
	while (!list_empty(&ipn_node->oobmsgqueue)) {
		struct msgitem *msgitem=
			list_first_entry(&ipn_node->oobmsgqueue, struct msgitem, list);
		list_del(&msgitem->list);
		ipn_node->totmsgcount--;
		ipn_node->oobmsgcount--;
		ipn_msgpool_put(msgitem->msg,ipnn);
		kmem_cache_free(ipn_msgitem_cache,msgitem);
	}
	spin_unlock(&ipn_node->msglock);
}

/* Terminate node. The node is "logically" terminated. */
/* LOCKING: ipn_glob_lock must be locked here */
static int ipn_terminate_node(struct ipn_node *ipn_node)
{
	struct ipn_network *ipnn=ipn_node->ipn;
	if (ipnn) {
		if (down_interruptible(&ipnn->ipnn_mutex)) 
			return -ERESTARTSYS;
		if (ipn_node->portno >= 0) {
			ipn_protocol_table[ipnn->protocol]->ipn_p_predelport(ipn_node);
			ipnn->connport[ipn_node->portno]=NULL;
		}
		list_del(&ipn_node->nodelist);
		ipn_flush_recvqueue(ipn_node);
		ipn_flush_oobrecvqueue(ipn_node);
		if (ipn_node->portno >= 0) 
			ipn_protocol_table[ipnn->protocol]->ipn_p_delport(ipn_node);
		ipn_node->ipn=NULL;
		ipn_net_update_counters(ipnn,
				(ipn_node->shutdown & RCV_SHUTDOWN)?0:-1,
				(ipn_node->shutdown & SEND_SHUTDOWN)?0:-1);
		ipn_node->shutdown = SHUTDOWN_XMASK;
		up(&ipnn->ipnn_mutex);
		if (ipn_node->dev)
			ipn_netdev_close(ipn_node);
		/* No more network elements */
		ipnn->refcnt--;
		if (ipnn->refcnt == 0)
		{
			ipn_protocol_table[ipnn->protocol]->ipn_p_delnet(ipnn);
			ipn_remove_network(ipnn);
			ipn_protocol_table[ipnn->protocol]->refcnt--;
			if (ipnn->dentry) {
				dput(ipnn->dentry);
				mntput(ipnn->mnt);
			}
			if (ipnn->msgpool_cache)
				ipn_msgbuf_put(ipnn->msgpool_cache);
			if (ipnn->connport)
				kfree(ipnn->connport);
			kmem_cache_free(ipn_network_cache, ipnn);
			module_put(THIS_MODULE);
		}
	}
	if (ipn_node->pbp) {
		kfree(ipn_node->pbp);
		ipn_node->pbp=NULL;
	} 
	return 0;
}

/* release of a socket */
static int ipn_release (struct socket *sock)
{
	struct ipn_sock *ipn_sk=(struct ipn_sock *)sock->sk;
	struct ipn_node *ipn_node=ipn_sk->node;
	int rv;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (ipn_node->flags & IPN_NODEFLAG_PERSIST) {
		ipn_node->flags &= ~IPN_NODEFLAG_INUSE;
		rv=0;
		up(&ipn_glob_mutex);
	} else {
		rv=ipn_terminate_node(ipn_node);
		up(&ipn_glob_mutex);
		if (rv==0) {
			ipn_netdevsync();
			kmem_cache_free(ipn_node_cache,ipn_node);
		}
	}
	if (rv==0) 
		sock_put((struct sock *) ipn_sk);
	return rv;
}

/* _set persist, change the persistence of a node,
 * when persistence gets cleared and the node is no longer used
 * the node is terminated and freed.
 * ipn_glob_mutex must be locked */
static int _ipn_setpersist(struct ipn_node *ipn_node, int persist)
{
	int rv=0;
	if (persist)
		ipn_node->flags |= IPN_NODEFLAG_PERSIST;
	else {
		ipn_node->flags &= ~IPN_NODEFLAG_PERSIST;
		if (!(ipn_node->flags & IPN_NODEFLAG_INUSE)) {
			rv=ipn_terminate_node(ipn_node);
			if (rv==0)
				kmem_cache_free(ipn_node_cache,ipn_node);
		}
	}
	return rv;
}

/* ipn_setpersist 
 * lock ipn_glob_mutex and call __ipn_setpersist above */
static int ipn_setpersist(struct ipn_node *ipn_node, int persist)
{
	int rv=0;
	if (ipn_node->dev == NULL)
		return -ENODEV;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	rv=_ipn_setpersist(ipn_node,persist);
	up(&ipn_glob_mutex);
	return rv;
}

/* several network parameters can be set by setsockopt prior to bind */
/* struct pre_bind_parms is a temporary stucture connected to ipn_node->pbp
 * to keep the parameter values. */
struct pre_bind_parms {
	unsigned short maxports;
	unsigned short flags;
	unsigned short msgpoolsize;
	unsigned short mtu;
	unsigned short mode;
};

/* STD_PARMS:  BITS_PER_LONG nodes, no flags, BITS_PER_BYTE pending msgs, 
 * Ethernet + VLAN MTU*/
#define STD_BIND_PARMS {BITS_PER_LONG, 0, BITS_PER_BYTE, 1514, 0x777};

static int ipn_mkname(struct sockaddr_un * sunaddr, int len)
{
	if (len <= sizeof(short) || len > sizeof(*sunaddr))
		return -EINVAL;
	if (!sunaddr || sunaddr->sun_family != AF_IPN)
		return -EINVAL;
	/*
	 * This may look like an off by one error but it is a bit more
	 * subtle. 108 is the longest valid AF_IPN path for a binding.
	 * sun_path[108] doesnt as such exist.  However in kernel space
	 * we are guaranteed that it is a valid memory location in our
	 * kernel address buffer.
	 */
	((char *)sunaddr)[len]=0;
	len = strlen(sunaddr->sun_path)+1+sizeof(short);
	return len;
}

/* IPN BIND */
static int ipn_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_un *sunaddr=(struct sockaddr_un *)uaddr;
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct nameidata nd;
	struct ipn_network *ipnn;
	struct dentry * dentry = NULL;
	int err;
	struct pre_bind_parms parms=STD_BIND_PARMS;

	//printk("IPN bind\n");

	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (sock->state != SS_UNCONNECTED || 
			ipn_node->ipn != NULL) {
		err= -EISCONN;
		goto out;
	}

	if (ipn_node->protocol >= 0 && 
			(ipn_node->protocol >= IPN_MAX_PROTO ||
			 ipn_protocol_table[ipn_node->protocol] == NULL)) {
		err= -EPROTONOSUPPORT;
		goto out;
	}

	addr_len = ipn_mkname(sunaddr, addr_len);
	if (addr_len < 0) {
		err=addr_len;
		goto out;
	}

	/* check if there is already an ipn-network socket with that name */
	err = path_lookup(sunaddr->sun_path, LOOKUP_FOLLOW, &nd);
	if (err) { /* it does not exist, NEW IPN socket! */
		unsigned int mode;
		/* Is it everything okay with the parent? */
		err = path_lookup(sunaddr->sun_path, LOOKUP_PARENT, &nd);
		if (err)
			goto out_mknod_parent;
		/* Do I have the permission to create a file? */
		dentry = lookup_create(&nd, 0);
		err = PTR_ERR(dentry);
		if (IS_ERR(dentry))
			goto out_mknod_unlock;
		/*
		 * All right, let's create it.
		 */
		if (ipn_node->pbp) 
			mode = ipn_node->pbp->mode;
		else
			mode = SOCK_INODE(sock)->i_mode;
		mode = S_IFSOCK | (mode & ~current->fs->umask);
#ifdef APPARMOR
		err = vfs_mknod(nd.dentry->d_inode, dentry, nd.mnt, mode, 0);
#else
		err = vfs_mknod(nd.dentry->d_inode, dentry, mode, 0);
#endif
		if (err)
			goto out_mknod_dput;
		mutex_unlock(&nd.dentry->d_inode->i_mutex);
		dput(nd.dentry);
		nd.dentry = dentry;
		/* create a new ipn_network item */
		if (ipn_node->pbp) 
			parms=*ipn_node->pbp;
		ipnn=kmem_cache_zalloc(ipn_network_cache,GFP_KERNEL); 
		if (!ipnn) {
			err=-ENOMEM;
			goto out_mknod_dput_ipnn;
		}
		ipnn->connport=kzalloc(parms.maxports * sizeof(struct ipn_node *),GFP_KERNEL);
		if (!ipnn->connport) {
			err=-ENOMEM;
			goto out_mknod_dput_ipnn2;
		}

		/* module refcnt is incremented for each network, thus
		 * rmmod is forbidden if there are persistent node */
		if (!try_module_get(THIS_MODULE)) {
			err = -EINVAL;
			goto out_mknod_dput_ipnn2;
		}
		memcpy(&ipnn->sunaddr,sunaddr,addr_len);
		ipnn->mtu=parms.mtu;
		ipnn->msgpool_cache=ipn_msgbuf_get(ipnn->mtu);
		if (!ipnn->msgpool_cache) {
			err=-ENOMEM;
			goto out_mknod_dput_putmodule;
		}
		INIT_LIST_HEAD(&ipnn->unconnectqueue);
		INIT_LIST_HEAD(&ipnn->connectqueue);
		ipnn->refcnt=1;
		ipnn->dentry=nd.dentry;
		ipnn->mnt=nd.mnt;
		init_MUTEX(&ipnn->ipnn_mutex);
		ipnn->sunaddr_len=addr_len;
		ipnn->protocol=ipn_node->protocol;
		if (ipnn->protocol < 0) ipnn->protocol = 0;
		ipn_protocol_table[ipnn->protocol]->refcnt++;
		ipnn->flags=parms.flags;
		ipnn->numreaders=0;
		ipnn->numwriters=0;
		ipnn->maxports=parms.maxports;
		atomic_set(&ipnn->msgpool_nelem,0);
		ipnn->msgpool_size=parms.msgpoolsize;
		ipnn->proto_private=NULL;
		init_waitqueue_head(&ipnn->send_wait);
		err=ipn_protocol_table[ipnn->protocol]->ipn_p_newnet(ipnn);
		if (err)
			goto out_mknod_dput_putmodule;
		ipn_insert_network(&ipn_network_table[nd.dentry->d_inode->i_ino & (IPN_HASH_SIZE-1)],ipnn);
	} else {
		/* join an existing network */
		if (parms.flags & IPN_FLAG_EXCL) {
			err=-EEXIST;
			goto put_fail;
		}
		err = vfs_permission(&nd, MAY_EXEC);
		if (err)
			goto put_fail;
		err = -ECONNREFUSED;
		if (!S_ISSOCK(nd.dentry->d_inode->i_mode))
			goto put_fail;
		ipnn=ipn_find_network_byinode(nd.dentry->d_inode);
		if (!ipnn || (ipnn->flags & IPN_FLAG_TERMINATED) ||
				(ipnn->flags & IPN_FLAG_EXCL))
			goto put_fail;
		list_add_tail(&ipn_node->nodelist,&ipnn->unconnectqueue);
		ipnn->refcnt++;
	}
	if (ipn_node->pbp) {
		kfree(ipn_node->pbp);
		ipn_node->pbp=NULL;
	} 
	ipn_node->ipn=ipnn;
	ipn_node->flags |= IPN_NODEFLAG_BOUND;
	up(&ipn_glob_mutex);
	return 0;

put_fail:
	path_release(&nd);
out:
	up(&ipn_glob_mutex);
	return err;

out_mknod_dput_putmodule:
	module_put(THIS_MODULE);
out_mknod_dput_ipnn2:
	kfree(ipnn->connport);
out_mknod_dput_ipnn:
	kmem_cache_free(ipn_network_cache,ipnn);
out_mknod_dput:
	dput(dentry);
out_mknod_unlock:
	mutex_unlock(&nd.dentry->d_inode->i_mutex);
	path_release(&nd);
out_mknod_parent:
	if (err==-EEXIST)
		err=-EADDRINUSE;
	up(&ipn_glob_mutex);
	return err;
}

/* IPN CONNECT */
static int ipn_connect(struct socket *sock, struct sockaddr *addr,
		int addr_len, int flags){
	struct sockaddr_un *sunaddr=(struct sockaddr_un*)addr;
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct nameidata nd;
	struct ipn_network *ipnn,*previousipnn;
	int err=0;
	int portno;

	/* the socket cannot be connected twice */
	if (sock->state != SS_UNCONNECTED) 
		return EISCONN;

	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;

	if ((previousipnn=ipn_node->ipn) == NULL) { /* unbound */
		unsigned char mustshutdown=0;
		err = ipn_mkname(sunaddr, addr_len);
		if (err < 0)
			goto out;
		addr_len=err;
		err = path_lookup(sunaddr->sun_path, LOOKUP_FOLLOW, &nd);
		if (err)
			goto out;
		err = vfs_permission(&nd, MAY_READ);
		if (err) {
			if (err == -EACCES || err == -EROFS)
				mustshutdown|=RCV_SHUTDOWN;
			else
				goto put_fail;
		}
		err = vfs_permission(&nd, MAY_WRITE);
		if (err) {
			if (err == -EACCES)
				mustshutdown|=SEND_SHUTDOWN;
			else
				goto put_fail;
		}
		mustshutdown |= ipn_node->shutdown;
		/* if the combination of shutdown and permissions leaves
		 * no abilities, connect returns EACCES */
		if (mustshutdown == SHUTDOWN_XMASK) {
			err=-EACCES;
			goto put_fail;
		} else {
			err=0;
			ipn_node->shutdown=mustshutdown;
		}
		if (!S_ISSOCK(nd.dentry->d_inode->i_mode)) {
			err = -ECONNREFUSED;
			goto put_fail;
		}
		ipnn=ipn_find_network_byinode(nd.dentry->d_inode);
		if (!ipnn || (ipnn->flags & IPN_FLAG_TERMINATED)) {
			err = -ECONNREFUSED;
			goto put_fail;
		}
		if (ipn_node->protocol == IPN_ANY)
			ipn_node->protocol=ipnn->protocol;
		else if (ipnn->protocol != ipn_node->protocol) {
			err = -EPROTO;
			goto put_fail;
		}
		path_release(&nd);
		ipn_node->ipn=ipnn;
	} else
		ipnn=ipn_node->ipn;

	if (down_interruptible(&ipnn->ipnn_mutex)) {
		err=-ERESTARTSYS;
		goto out;
	}
	portno = ipn_protocol_table[ipnn->protocol]->ipn_p_newport(ipn_node);
	if (portno >= 0 && portno<ipnn->maxports) {
		sock->state = SS_CONNECTED;
		ipn_node->portno=portno;
		ipnn->connport[portno]=ipn_node;
		if (!(ipn_node->flags & IPN_NODEFLAG_BOUND)) {
			ipnn->refcnt++;
			list_del(&ipn_node->nodelist);
		}
		list_add_tail(&ipn_node->nodelist,&ipnn->connectqueue);
		ipn_net_update_counters(ipnn,
				(ipn_node->shutdown & RCV_SHUTDOWN)?0:1,
				(ipn_node->shutdown & SEND_SHUTDOWN)?0:1);
	} else {
		ipn_node->ipn=previousipnn; /* undo changes on ipn_node->ipn */
		err=-EADDRNOTAVAIL;
	}
	up(&ipnn->ipnn_mutex);
	up(&ipn_glob_mutex);
	return err;

put_fail:
	path_release(&nd);
out:
	up(&ipn_glob_mutex);
	return err;
}

static int ipn_getname(struct socket *sock, struct sockaddr *uaddr, 
		int *uaddr_len, int peer) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	struct sockaddr_un *sunaddr=(struct sockaddr_un *)uaddr;
	int err=0;

	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (ipnn) {
		*uaddr_len = ipnn->sunaddr_len;
		memcpy(sunaddr,&ipnn->sunaddr,*uaddr_len);
	} else
		err = -ENOTCONN;
	up(&ipn_glob_mutex);
	return err;
}

/* IPN POLL */
static unsigned int ipn_poll(struct file *file, struct socket *sock, 
		poll_table *wait) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	unsigned int mask=0;

	if (ipnn) {
		poll_wait(file,&ipn_node->read_wait,wait);
		if (ipnn->flags & IPN_FLAG_LOSSLESS)
			poll_wait(file,&ipnn->send_wait,wait);
		/* POLLIN if recv succeeds, 
		 * POLL{PRI,RDNORM} if there are {oob,non-oob} messages */
		if (ipn_node->totmsgcount > 0) mask |= POLLIN;
		if (!(list_empty(&ipn_node->msgqueue))) mask |= POLLRDNORM;
		if (!(list_empty(&ipn_node->oobmsgqueue))) mask |= POLLPRI;
		if ((!(ipnn->flags & IPN_FLAG_LOSSLESS)) |
				(atomic_read(&ipnn->msgpool_nelem) < ipnn->msgpool_size))
			mask |= POLLOUT | POLLWRNORM;
	} 
	return mask;
}

/* connect netdev (from ioctl). connect a bound socket to a 
 * network device TAP or GRAB */
static int ipn_connect_netdev(struct socket *sock,struct ifreq *ifr)
{
	int err=0;
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (sock->state != SS_UNCONNECTED) 
		return -EISCONN;
	if (!ipnn)
		return -ENOTCONN;  /* Maybe we need a different error for "NOT BOUND" */
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (down_interruptible(&ipnn->ipnn_mutex)) {
		up(&ipn_glob_mutex);
		return -ERESTARTSYS;
	}
	ipn_node->dev=ipn_netdev_alloc(ipn_node->net,ifr->ifr_flags,ifr->ifr_name,&err);
	if (ipn_node->dev) {
		int portno;
		portno = ipn_protocol_table[ipnn->protocol]->ipn_p_newport(ipn_node);
		if (portno >= 0 && portno<ipnn->maxports) {
			sock->state = SS_CONNECTED;
			ipn_node->portno=portno;
			ipn_node->flags |= ifr->ifr_flags & IPN_NODEFLAG_DEVMASK;
			ipnn->connport[portno]=ipn_node;
			err=ipn_netdev_activate(ipn_node);
			if (err) {
				sock->state = SS_UNCONNECTED;
				ipn_protocol_table[ipnn->protocol]->ipn_p_delport(ipn_node);
				ipn_node->dev=NULL;
				ipn_node->portno= -1;
				ipn_node->flags &= ~IPN_NODEFLAG_DEVMASK;
				ipnn->connport[portno]=NULL;
			} else  {
				ipn_protocol_table[ipnn->protocol]->ipn_p_postnewport(ipn_node);
				list_del(&ipn_node->nodelist);
				list_add_tail(&ipn_node->nodelist,&ipnn->connectqueue);
			}
		} else {
			ipn_netdev_close(ipn_node); 
			err=-EADDRNOTAVAIL;
			ipn_node->dev=NULL;
		}
	} else 
		err=-EINVAL;
	up(&ipnn->ipnn_mutex);
	up(&ipn_glob_mutex);
	return err;
}

/* join a netdev, a socket gets connected to a persistent node
 * not connected to another socket */
static int ipn_join_netdev(struct socket *sock,struct ifreq *ifr)
{
	int err=0;
	struct net_device *dev;
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_node *ipn_joined;
	struct ipn_network *ipnn=ipn_node->ipn;
	if (sock->state != SS_UNCONNECTED)
		return -EISCONN;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (down_interruptible(&ipnn->ipnn_mutex)) {
		up(&ipn_glob_mutex);
		return -ERESTARTSYS;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	dev=__dev_get_by_name(ifr->ifr_name);
#else
	dev=__dev_get_by_name(ipn_node->net,ifr->ifr_name);
#endif
	if (!dev) 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
		dev=__dev_get_by_index(ifr->ifr_ifindex);
#else
		dev=__dev_get_by_index(ipn_node->net,ifr->ifr_ifindex);
#endif
	if (dev && (ipn_joined=ipn_netdev2node(dev)) != NULL) { /* the interface does exist */
		int i;
		for (i=0;i<ipnn->maxports && ipn_joined != ipnn->connport[i] ;i++)
			;
		if (i < ipnn->maxports) { /* found */
			/* ipn_joined is substituted to ipn_node */
			((struct ipn_sock *)sock->sk)->node=ipn_joined;
			ipn_joined->flags |= IPN_NODEFLAG_INUSE;
			ipnn->refcnt--;
			kmem_cache_free(ipn_node_cache,ipn_node);
		} else
			err=-EPERM;
	} else
		err=-EADDRNOTAVAIL;
	up(&ipnn->ipnn_mutex);
	up(&ipn_glob_mutex);
	return err;
}

/* set persistence of a node looking for it by interface name
 * (it is for sysadm, to close network interfaces)*/
static int ipn_setpersist_netdev(struct ifreq *ifr, int value)
{
	struct net_device *dev;
	struct ipn_node *ipn_node;
	int err=0;
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	dev=__dev_get_by_name(ifr->ifr_name);
#else
	dev=__dev_get_by_name(&init_net,ifr->ifr_name);
#endif
	if (!dev)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
		dev=__dev_get_by_index(ifr->ifr_ifindex);
#else
		dev=__dev_get_by_index(&init_net,ifr->ifr_ifindex);
#endif
	if (dev && (ipn_node=ipn_netdev2node(dev)) != NULL) 
		_ipn_setpersist(ipn_node,value);
	else
		err=-EADDRNOTAVAIL;
	up(&ipn_glob_mutex);
	return err;
}

/* IPN IOCTL */
static int ipn_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	void __user* argp = (void __user*)arg;
	struct ifreq ifr;

	if (ipn_node->shutdown == SHUTDOWN_XMASK)
		return -ECONNRESET;

	/* get arguments */
	switch (cmd) {
		case IPN_CHECK:
			return IPN_CHECK;
		case IPN_SETPERSIST_NETDEV:
		case IPN_CLRPERSIST_NETDEV:
		case IPN_CONN_NETDEV:
		case IPN_JOIN_NETDEV:
		case SIOCSIFHWADDR:
			if (copy_from_user(&ifr, argp, sizeof ifr))
				return -EFAULT;
			ifr.ifr_name[IFNAMSIZ-1] = '\0';
	}

	/* actions for unconnected and unbound sockets */
	switch (cmd) {
		case IPN_SETPERSIST_NETDEV:
			return ipn_setpersist_netdev(&ifr,1);
		case IPN_CLRPERSIST_NETDEV:
			return ipn_setpersist_netdev(&ifr,0);
		case SIOCSIFHWADDR:
			if (capable(CAP_NET_ADMIN))
				return -EPERM;
			if (ipn_node->dev && (ipn_node->flags &IPN_NODEFLAG_TAP))
				return dev_set_mac_address(ipn_node->dev, &ifr.ifr_hwaddr);
			else
				return -EADDRNOTAVAIL;
	}
	if (ipnn == NULL || (ipnn->flags & IPN_FLAG_TERMINATED))
		return -ENOTCONN;
	/* actions for connected or bound sockets */
	switch (cmd) {
		case IPN_CONN_NETDEV:
			return ipn_connect_netdev(sock,&ifr);
		case IPN_JOIN_NETDEV:
			return ipn_join_netdev(sock,&ifr);
		case IPN_SETPERSIST:
			return ipn_setpersist(ipn_node,arg);
		default:
			if (ipnn) {
				int rv;
				if (down_interruptible(&ipnn->ipnn_mutex))
					return -ERESTARTSYS;
				rv=ipn_protocol_table[ipn_node->protocol]->ipn_p_ioctl(ipn_node,cmd,arg);
				up(&ipnn->ipnn_mutex);
				return rv;
			} else
				return -EOPNOTSUPP;
	}
}

/* shutdown: close socket for input or for output.
 * shutdown can be called prior to connect and it is not reversible */
static int ipn_shutdown(struct socket *sock, int mode) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	int oldshutdown=ipn_node->shutdown;
	mode = (mode+1)&(RCV_SHUTDOWN|SEND_SHUTDOWN);

	ipn_node->shutdown |= mode;

	if(ipnn) {
		if (down_interruptible(&ipnn->ipnn_mutex)) {
			ipn_node->shutdown = oldshutdown;
			return -ERESTARTSYS;
		}
		oldshutdown=ipn_node->shutdown-oldshutdown;
		if (sock->state == SS_CONNECTED && oldshutdown) {
			ipn_net_update_counters(ipnn,
					(ipn_node->shutdown & RCV_SHUTDOWN)?0:-1,
					(ipn_node->shutdown & SEND_SHUTDOWN)?0:-1);
		}

		/* if recv channel has been shut down, flush the recv queue */
		if ((ipn_node->shutdown & RCV_SHUTDOWN))
			ipn_flush_recvqueue(ipn_node);
		up(&ipnn->ipnn_mutex);
	}
	return 0;
}

/* injectmsg: a new message is entering the ipn network.
 * injectmsg gets called by send and by the grab/tap node */
int ipn_proto_injectmsg(struct ipn_node *from, struct msgpool_item *msg)
{
	struct ipn_network *ipnn=from->ipn;
	int err=0;
	if (down_interruptible(&ipnn->ipnn_mutex))
		err=-ERESTARTSYS;
	else {
		ipn_protocol_table[ipnn->protocol]->ipn_p_handlemsg(from, msg);
		up(&ipnn->ipnn_mutex);
	}
	return err;
}

/* SEND MSG */
static int ipn_sendmsg(struct kiocb *kiocb, struct socket *sock,
		struct msghdr *msg, size_t len) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	struct msgpool_item *newmsg;
	int err=0;

	if (unlikely(sock->state != SS_CONNECTED)) 
			return -ENOTCONN;
	if (unlikely(ipn_node->shutdown & SEND_SHUTDOWN)) {
		if (ipn_node->shutdown == SHUTDOWN_XMASK)
			return -ECONNRESET;
		else
			return -EPIPE;
	}
	if (len > ipnn->mtu)
		return -EOVERFLOW;
	newmsg=ipn_msgpool_alloc_locking(ipnn);
	if (!newmsg)
		return -ENOMEM;
	newmsg->len=len;
	err=memcpy_fromiovec(newmsg->data, msg->msg_iov, len);
	if (!err) 
		ipn_proto_injectmsg(ipn_node, newmsg);
	ipn_msgpool_put(newmsg,ipnn);
	return err;
}

/* enqueue an oob message. "to" is the destination */
void ipn_proto_oobsendmsg(struct ipn_node *to, struct msgpool_item *msg)
{
	if (to) {
		if (!to->dev) { /* no oob to netdev */
			struct msgitem *msgitem;
			struct ipn_network *ipnn=to->ipn;
			spin_lock(&to->msglock);
			if ((to->shutdown & RCV_SHUTDOWN_NO_OOB) == 0 && 
					(ipnn->flags & IPN_FLAG_LOSSLESS ||
					 to->oobmsgcount < ipnn->msgpool_size)) {
				if ((msgitem=kmem_cache_alloc(ipn_msgitem_cache,GFP_KERNEL))!=NULL) {
					msgitem->msg=msg;
					to->totmsgcount++;
					to->oobmsgcount++;
					list_add_tail(&msgitem->list, &to->oobmsgqueue);
					ipn_msgpool_hold(msg);
				}
			}
			spin_unlock(&to->msglock);
			wake_up_interruptible(&to->read_wait);
		}
	}
}

/* ipn_proto_sendmsg is called by protocol implementation to enqueue a 
 * for a destination (to).*/
void ipn_proto_sendmsg(struct ipn_node *to, struct msgpool_item *msg)
{
	if (to) {
		if (to->dev) {
			ipn_netdev_sendmsg(to,msg);
		} else {
			/* socket send */
			struct msgitem *msgitem;
			struct ipn_network *ipnn=to->ipn;
			spin_lock(&to->msglock);
			if (likely((to->shutdown & RCV_SHUTDOWN)==0)) {
				if (unlikely((ipnn->flags & IPN_FLAG_LOSSLESS) == 0 ||
							            to->totmsgcount >= ipnn->msgpool_size))
					schedule();
				if (ipnn->flags & IPN_FLAG_LOSSLESS ||
						to->totmsgcount < ipnn->msgpool_size) { 
					if ((msgitem=kmem_cache_alloc(ipn_msgitem_cache,GFP_KERNEL))!=NULL) {
						msgitem->msg=msg;
						to->totmsgcount++;
						list_add_tail(&msgitem->list, &to->msgqueue);
						ipn_msgpool_hold(msg);
					}
				}
			}
			spin_unlock(&to->msglock);
			wake_up_interruptible(&to->read_wait);
		}
	}
}

/* IPN RECV */
static int ipn_recvmsg(struct kiocb *kiocb, struct socket *sock,
		struct msghdr *msg, size_t len, int flags) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	struct msgitem *msgitem;
	struct msgpool_item *currmsg;

	if (unlikely(sock->state != SS_CONNECTED)) 
			return -ENOTCONN;

	if (unlikely((ipn_node->shutdown & XRCV_SHUTDOWN) == XRCV_SHUTDOWN)) {
		if (ipn_node->shutdown == SHUTDOWN_XMASK) /*EOF, nothing can be read*/
			return 0;
		else
			return -EPIPE; /*trying to read on a write only node */
	}

	/* wait for a message */
	spin_lock(&ipn_node->msglock);
	while (ipn_node->totmsgcount == 0) {
		spin_unlock(&ipn_node->msglock);
		if (wait_event_interruptible(ipn_node->read_wait,
					!(ipn_node->totmsgcount == 0)))
			return -ERESTARTSYS;
		spin_lock(&ipn_node->msglock);
	}
	/* oob gets delivered first. oob are rare */
	if (likely(list_empty(&ipn_node->oobmsgqueue)))
		msgitem=list_first_entry(&ipn_node->msgqueue, struct msgitem, list);
	else {
		msgitem=list_first_entry(&ipn_node->oobmsgqueue, struct msgitem, list);
		msg->msg_flags |= MSG_OOB;
		ipn_node->oobmsgcount--;
	}
	list_del(&msgitem->list);
	ipn_node->totmsgcount--;
	spin_unlock(&ipn_node->msglock);
	currmsg=msgitem->msg;
	if (currmsg->len < len)
		len=currmsg->len;
	memcpy_toiovec(msg->msg_iov, currmsg->data, len);
	ipn_msgpool_put(currmsg,ipnn);
	kmem_cache_free(ipn_msgitem_cache,msgitem);

	return len;
}

/* resize a network: change the # of communication ports (connport) */
static int ipn_netresize(struct ipn_network *ipnn,int newsize)
{
	int oldsize,min;
	struct ipn_node **newconnport;
	struct ipn_node **oldconnport;
	int err;
	if (down_interruptible(&ipnn->ipnn_mutex))
		        return -ERESTARTSYS;
	oldsize=ipnn->maxports;
	if (newsize == oldsize) {
		up(&ipnn->ipnn_mutex);
		return 0;
	}
	min=oldsize;
	/* shrink a network. all the ports we are going to eliminate
	 * must be unused! */
	if (newsize < oldsize) {
		int i;
		for (i=newsize; i<oldsize; i++)
			if (ipnn->connport[i]) {
				up(&ipnn->ipnn_mutex);
				return -EADDRINUSE;
			}
		min=newsize;
	}
	oldconnport=ipnn->connport;
	/* allocate the new connport array and copy the old one */
	newconnport=kzalloc(newsize * sizeof(struct ipn_node *),GFP_KERNEL);
	if (!newconnport) {
		up(&ipnn->ipnn_mutex);
		return -ENOMEM;
	}
	memcpy(newconnport,oldconnport,min * sizeof(struct ipn_node *));
	ipnn->connport=newconnport;
	ipnn->maxports=newsize;
	/* notify the protocol that the netowrk has been resized */
	err=ipn_protocol_table[ipnn->protocol]->ipn_p_resizenet(ipnn,oldsize,newsize);
	if (err) {
		/* roll back if the resize operation failed for the protocol */
		ipnn->connport=oldconnport;
		ipnn->maxports=oldsize;
		kfree(newconnport);
	} else 
		/* successful mission, network resized */
		kfree(oldconnport);
	up(&ipnn->ipnn_mutex);
	return err;
}

/* IPN SETSOCKOPT */
static int ipn_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int optlen) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;

	if (ipn_node->shutdown == SHUTDOWN_XMASK)
		return -ECONNRESET;
	if (level != 0 && level != ipn_node->protocol+1)
		return -EPROTONOSUPPORT;
	if (level > 0) {
		/* protocol specific sockopt */
		if (ipnn) {
			int rv;
			if (down_interruptible(&ipnn->ipnn_mutex))
				return -ERESTARTSYS;
			rv=ipn_protocol_table[ipn_node->protocol]->ipn_p_setsockopt(ipn_node,optname,optval,optlen);
			up(&ipnn->ipnn_mutex);
			return rv;
		} else
			return -EOPNOTSUPP;
	} else {
		if (optname == IPN_SO_DESCR) {
			if (optlen > IPN_DESCRLEN)
				return -EINVAL;
			else {
				memset(ipn_node->descr,0,IPN_DESCRLEN);
				if (copy_from_user(ipn_node->descr,optval,optlen))
					ipn_node->descr[0]=0;
				else
					ipn_node->descr[optlen-1]=0;
				return 0;
			}
		} else {
			if (optlen < sizeof(int))
				return -EINVAL;
			else if ((optname & IPN_SO_PREBIND) && (ipnn != NULL))
				return -EISCONN;
			else {
				int val;
				get_user(val, (int __user *) optval);
				if ((optname & IPN_SO_PREBIND) && !ipn_node->pbp) {
					struct pre_bind_parms std=STD_BIND_PARMS;
					ipn_node->pbp=kzalloc(sizeof(struct pre_bind_parms),GFP_KERNEL);
					if (!ipn_node->pbp)
						return -ENOMEM;
					*(ipn_node->pbp)=std;
				}
				switch (optname) {
					case IPN_SO_PORT:
						if (sock->state == SS_UNCONNECTED)
							ipn_node->portno=val;
						else
							return -EISCONN;
						break;
					case IPN_SO_CHANGE_NUMNODES:
						if ((ipn_node->flags & IPN_NODEFLAG_BOUND)!=0) {
							if (val <= 0)
								return -EINVAL;
							else
								return ipn_netresize(ipnn,val);
						} else
							val=-ENOTCONN;
						break;
					case IPN_SO_WANT_OOB_NUMNODES:
						if (val)
							ipn_node->flags |= IPN_NODEFLAG_OOB_NUMNODES;
						else
							ipn_node->flags &= ~IPN_NODEFLAG_OOB_NUMNODES;
						break;
					case IPN_SO_HANDLE_OOB:
						if (val)
							ipn_node->shutdown &= ~RCV_SHUTDOWN_NO_OOB;
						else
							ipn_node->shutdown |= RCV_SHUTDOWN_NO_OOB;
						break;
					case IPN_SO_MTU:
						if (val <= 0)
							return -EINVAL;
						else
							ipn_node->pbp->mtu=val;
						break;
					case IPN_SO_NUMNODES:
						if (val <= 0)
							return -EINVAL;
						else
							ipn_node->pbp->maxports=val;
						break;
					case IPN_SO_MSGPOOLSIZE:
						if (val <= 0)
							return -EINVAL;
						else
							ipn_node->pbp->msgpoolsize=val;
						break;
					case IPN_SO_FLAGS:
						ipn_node->pbp->flags=val;
						break;
					case IPN_SO_MODE:
						ipn_node->pbp->mode=val;
						break;
				}
				return 0;
			}
		}
	}
}

/* IPN GETSOCKOPT */
static int ipn_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	int len;

	if (ipn_node->shutdown == SHUTDOWN_XMASK)
		return -ECONNRESET;
	if (level != 0 && level != ipn_node->protocol+1)
		return -EPROTONOSUPPORT;
	if (level > 0) {
		if (ipnn) {
			int rv;
			/* protocol specific sockopt */
			if (down_interruptible(&ipnn->ipnn_mutex))
				return -ERESTARTSYS;
			rv=ipn_protocol_table[ipn_node->protocol]->ipn_p_getsockopt(ipn_node,optname,optval,optlen);
			up(&ipnn->ipnn_mutex);
			return rv;
		} else
			return -EOPNOTSUPP;
	} else {
		if (get_user(len, optlen))
			return -EFAULT;
		if (optname == IPN_SO_DESCR) {
			if (len < IPN_DESCRLEN)
				return -EINVAL;
			else {
				if (len > IPN_DESCRLEN)
					len=IPN_DESCRLEN;
				if(put_user(len, optlen))
					return -EFAULT;
				if(copy_to_user(optval,ipn_node->descr,len))
					return -EFAULT;
				return 0;
			}
		} else {
			int val=-2;
			switch (optname) {
				case IPN_SO_PORT:
					val=ipn_node->portno;
					break;
				case IPN_SO_MTU:
					if (ipnn)
						val=ipnn->mtu;
					else if (ipn_node->pbp)
						val=ipn_node->pbp->mtu;
					break;
				case IPN_SO_NUMNODES:
					if (ipnn)
						val=ipnn->maxports;
					else if (ipn_node->pbp)
						val=ipn_node->pbp->maxports;
					break;
				case IPN_SO_MSGPOOLSIZE:
					if (ipnn)
						val=ipnn->msgpool_size;
					else if (ipn_node->pbp)
						val=ipn_node->pbp->msgpoolsize;
					break;
				case IPN_SO_FLAGS:
					if (ipnn)
						val=ipnn->flags;
					else if (ipn_node->pbp)
						val=ipn_node->pbp->flags;
					break;
				case IPN_SO_MODE:
					if (ipnn)
						val=-1;
					else if (ipn_node->pbp)
						val=ipn_node->pbp->mode;
					break;
			}
			if (val < -1)
				return -EINVAL;
			else {
				if (len < sizeof(int))
					return -EOVERFLOW;
				else {
					len = sizeof(int);
					if(put_user(len, optlen))
						return -EFAULT;
					if(copy_to_user(optval,&val,len))
						return -EFAULT;
					return 0;
				}
			}
		}
	}
}

/* BROADCAST/HUB implementation */

static int ipn_bcast_newport(struct ipn_node *newport) {
	struct ipn_network *ipnn=newport->ipn;
	int i;
	for (i=0;i<ipnn->maxports;i++) {
		if (ipnn->connport[i] == NULL) 
			return i;
	}
	return -1;
}

static int ipn_bcast_handlemsg(struct ipn_node *from, 
		struct msgpool_item *msgitem){
	struct ipn_network *ipnn=from->ipn;

	struct ipn_node *ipn_node;
	list_for_each_entry(ipn_node, &ipnn->connectqueue, nodelist) {
		if (ipn_node != from)
			ipn_proto_sendmsg(ipn_node,msgitem);
	}
	return 0;
}

static void ipn_null_delport(struct ipn_node *oldport) {}
static void ipn_null_postnewport(struct ipn_node *newport) {}
static  void ipn_null_predelport(struct ipn_node *oldport) {}
static int ipn_null_newnet(struct ipn_network *newnet) {return 0;}
static int ipn_null_resizenet(struct ipn_network *net,int oldsize,int newsize) {
	return 0;}
static void ipn_null_delnet(struct ipn_network *oldnet) {}
static int ipn_null_setsockopt(struct ipn_node *port,int optname,
		char __user *optval, int optlen) {return -EOPNOTSUPP;}
static int ipn_null_getsockopt(struct ipn_node *port,int optname,
		char __user *optval, int *optlen) {return -EOPNOTSUPP;}
static int ipn_null_ioctl(struct ipn_node *port,unsigned int request,
		unsigned long arg) {return -EOPNOTSUPP;}

/* Protocol Registration/deregisteration */

void ipn_init_protocol(struct ipn_protocol *p)
{
	if (p->ipn_p_delport == NULL) p->ipn_p_delport=ipn_null_delport;
	if (p->ipn_p_postnewport == NULL) p->ipn_p_postnewport=ipn_null_postnewport;
	if (p->ipn_p_predelport == NULL) p->ipn_p_predelport=ipn_null_predelport;
	if (p->ipn_p_newnet == NULL) p->ipn_p_newnet=ipn_null_newnet;
	if (p->ipn_p_resizenet == NULL) p->ipn_p_resizenet=ipn_null_resizenet;
	if (p->ipn_p_delnet == NULL) p->ipn_p_delnet=ipn_null_delnet;
	if (p->ipn_p_setsockopt == NULL) p->ipn_p_setsockopt=ipn_null_setsockopt;
	if (p->ipn_p_getsockopt == NULL) p->ipn_p_getsockopt=ipn_null_getsockopt;
	if (p->ipn_p_ioctl == NULL) p->ipn_p_ioctl=ipn_null_ioctl;
}

int ipn_proto_register(int protocol,struct ipn_protocol *ipn_service)
{
	int rv=0;
	if (ipn_service->ipn_p_newport == NULL ||
			ipn_service->ipn_p_handlemsg == NULL)
		return -EINVAL;
	ipn_init_protocol(ipn_service);
	if (down_interruptible(&ipn_glob_mutex)) 
		return -ERESTARTSYS;
	if (protocol > 1 && protocol <= IPN_MAX_PROTO) {
		protocol--;
		if (ipn_protocol_table[protocol])
			rv= -EEXIST;
		else {
			ipn_service->refcnt=0;
			ipn_protocol_table[protocol]=ipn_service;
			printk(KERN_INFO "IPN: Registered protocol %d\n",protocol+1);
		}
	} else
		rv= -EINVAL;
	up(&ipn_glob_mutex);
	return rv;
}

int ipn_proto_deregister(int protocol) 
{
	int rv=0;
	if (down_interruptible(&ipn_glob_mutex)) 
		return -ERESTARTSYS;
	if (protocol > 1 && protocol <= IPN_MAX_PROTO) {
		protocol--;
		if (ipn_protocol_table[protocol]) {
			if (ipn_protocol_table[protocol]->refcnt == 0) {
				ipn_protocol_table[protocol]=NULL;
				printk(KERN_INFO "IPN: Unregistered protocol %d\n",protocol+1);
			} else
				rv=-EADDRINUSE;
		} else 
			rv= -ENOENT;
	} else
		rv= -EINVAL;
	up(&ipn_glob_mutex);
	return rv;
}

/* MAIN SECTION */
/* Module constructor/destructor */
static struct net_proto_family ipn_family_ops = {
	.family = PF_IPN,
	.create = ipn_create,
	.owner  = THIS_MODULE,
};

/* IPN constructor */
static int ipn_init(void)
{
	int rc;

	ipn_init_protocol(&ipn_bcast);
	ipn_network_cache=kmem_cache_create("ipn_network",sizeof(struct ipn_network),0,0,NULL);
	if (!ipn_network_cache) {
		printk(KERN_CRIT "%s: Cannot create ipn_network SLAB cache!\n",
				__FUNCTION__);
		rc=-ENOMEM;
		goto out;
	}

	ipn_node_cache=kmem_cache_create("ipn_node",sizeof(struct ipn_node),0,0,NULL);
	if (!ipn_node_cache) {
		printk(KERN_CRIT "%s: Cannot create ipn_node SLAB cache!\n",
				__FUNCTION__);
		rc=-ENOMEM;
		goto out_net;
	}

	ipn_msgitem_cache=kmem_cache_create("ipn_msgitem",sizeof(struct msgitem),0,0,NULL);
	if (!ipn_msgitem_cache) {
		printk(KERN_CRIT "%s: Cannot create ipn_msgitem SLAB cache!\n",
				__FUNCTION__);
		rc=-ENOMEM;
		goto out_net_node;
	}

	rc=ipn_msgbuf_init();
	if (rc != 0) {
		printk(KERN_CRIT "%s: Cannot create ipn_msgbuf SLAB cache\n",
				__FUNCTION__);
		goto out_net_node_msg;
	}

	rc=proto_register(&ipn_proto,1);
	if (rc != 0) {
		printk(KERN_CRIT "%s: Cannot register the protocol!\n",
				__FUNCTION__);
		goto out_net_node_msg_msgbuf;
	}

	sock_register(&ipn_family_ops);
	ipn_netdev_init();
	printk(KERN_INFO "IPN: Virtual Square Project, University of Bologna 2007\n");
	return 0;

out_net_node_msg_msgbuf:
	ipn_msgbuf_fini();
out_net_node_msg:
	kmem_cache_destroy(ipn_msgitem_cache);
out_net_node:
	kmem_cache_destroy(ipn_node_cache);
out_net:
	kmem_cache_destroy(ipn_network_cache);
out:
	return rc;
}

/* IPN destructor */
static void ipn_exit(void)
{
	ipn_netdev_fini();
	if (ipn_msgitem_cache)
		kmem_cache_destroy(ipn_msgitem_cache);
	if (ipn_node_cache)
		kmem_cache_destroy(ipn_node_cache);
	if (ipn_network_cache)
		kmem_cache_destroy(ipn_network_cache);
	ipn_msgbuf_fini();
	sock_unregister(PF_IPN);
	proto_unregister(&ipn_proto);
	printk(KERN_INFO "IPN removed\n");
}

module_init(ipn_init);
module_exit(ipn_exit);

EXPORT_SYMBOL_GPL(ipn_proto_register);
EXPORT_SYMBOL_GPL(ipn_proto_deregister);
EXPORT_SYMBOL_GPL(ipn_proto_sendmsg);
EXPORT_SYMBOL_GPL(ipn_proto_oobsendmsg);
EXPORT_SYMBOL_GPL(ipn_msgpool_alloc);
EXPORT_SYMBOL_GPL(ipn_msgpool_put);
