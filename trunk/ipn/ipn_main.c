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
#include <net/sock.h>
#include "af_ipn.h"
#include "ipn_netdev.h"
#include "ipn_hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIEW-OS TEAM");
MODULE_DESCRIPTION("IPN-VDE Kernel Module");

#define MAX_PROTO 4

/* Network table and hash */
struct hlist_head ipn_network_table[IPN_HASH_SIZE + 1];
DEFINE_SPINLOCK(ipn_table_lock);
static struct kmem_cache *ipn_node_cache;
static struct kmem_cache *ipn_msgitem_cache;
static DECLARE_MUTEX(ipn_glob_mutex);

/* Protocol 1: HUB/Broadcast default protocol. Function Prototypes */
static int ipn_bcast_newport(struct ipn_node *newport);
static int ipn_bcast_handlemsg(struct ipn_node *from, 
		struct msgpool_item *msgitem,
		int depth);

/* Protocol table */
static struct ipn_protocol ipn_bcast = {
	.refcnt=0,
	.ipn_p_newport=ipn_bcast_newport, 
	.ipn_p_handlemsg=ipn_bcast_handlemsg};
static struct ipn_protocol *ipn_protocol_table[MAX_PROTO]={&ipn_bcast};

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

/* Network table Management */
static inline void ipn_insert_network(struct hlist_head *list, struct ipn_network *ipnn)
{
	spin_lock(&ipn_table_lock);
	hlist_add_head(&ipnn->hnode, list);
	spin_unlock(&ipn_table_lock);
}

static inline void ipn_remove_network(struct ipn_network *ipnn)
{
	spin_lock(&ipn_table_lock);
	hlist_del(&ipnn->hnode);
	spin_unlock(&ipn_table_lock);
}

static struct ipn_network *ipn_find_network_byinode(struct inode *i)
{
	struct ipn_network *ipnn;
	struct hlist_node *node;

	spin_lock(&ipn_table_lock);
	hlist_for_each_entry(ipnn, node,
			&ipn_network_table[i->i_ino & (IPN_HASH_SIZE - 1)], hnode) {
		struct dentry *dentry = ipnn->dentry;

		if(atomic_read(&ipnn->refcnt) > 0 && dentry && dentry->d_inode == i)
			goto found;
	}
	ipnn = NULL;
found:
	spin_unlock(&ipn_table_lock);
	return ipnn;
}

static int ipn_check_node_connected(struct ipn_node *ipn_node)
{
	struct ipn_network *ipnn;
	struct hlist_node *node;
	int i,j;
	spin_lock(&ipn_table_lock);
	for (i=0;i<IPN_HASH_SIZE;i++)
	{
		hlist_for_each_entry(ipnn, node, &ipn_network_table[i], hnode) {
			for(j=0;j<ipnn->maxports;j++) {
				if (ipnn->connport[j] == ipn_node) {
					spin_unlock(&ipn_table_lock);
					return 1;
				}
			}
		}
	}
	spin_unlock(&ipn_table_lock);
	return 0;
}

static int ipn_setpersist(struct ipn_node *ipn_node, int persist);
static void cleanup_persistent_nodes(void)
{
	struct ipn_network *ipnn;
	struct hlist_node *node;
	int i,j;
	spin_lock(&ipn_table_lock);
	for (i=0;i<IPN_HASH_SIZE;i++)
	{
		hlist_for_each_entry(ipnn, node, &ipn_network_table[i], hnode) {
			for(j=0;j<ipnn->maxports;j++) {
				struct ipn_node *ipn_node=ipnn->connport[j];
				if (ipn_node && (ipn_node->dev) && (ipn_node->flags & IPN_NODEFLAG_INUSE) == 0)
					ipn_setpersist(ipn_node,0);
			}
		}
	}
	spin_unlock(&ipn_table_lock);
}

/* msgpool management */

struct msgitem {
	struct list_head list;
	struct msgpool_item *msg;
};

struct msgpool_item *ipn_msgpool_alloc(struct ipn_network *ipnn)
{
	struct msgpool_item *new;
	new=kmem_cache_alloc(ipnn->msgpool_cache,GFP_KERNEL);
	atomic_set(&new->count,1);
	atomic_inc(&ipnn->msgpool_nelem);
	return new;
}

static struct msgpool_item *ipn_msgpool_alloc_locking(struct ipn_network *ipnn)
{
	if (ipnn->flags & IPN_FLAG_LOSSLESS) {
		while (atomic_read(&ipnn->msgpool_nelem) >= ipnn->msgpool_size) {
			if (wait_event_interruptible_exclusive(ipnn->send_wait,
						atomic_read(&ipnn->msgpool_nelem) < ipnn->msgpool_size))
				return NULL;
		}
	}
	return ipn_msgpool_alloc(ipnn);
}

static inline void ipn_msgpool_hold(struct msgpool_item *msg)
{
	atomic_inc(&msg->count);
}

void ipn_msgpool_put(struct msgpool_item *old,
		struct ipn_network *ipnn)
{
	if (atomic_dec_and_test(&old->count)) {
		kmem_cache_free(ipnn->msgpool_cache,old);
		atomic_dec(&ipnn->msgpool_nelem);
		if (ipnn->flags & IPN_FLAG_LOSSLESS) /* could be done anyway */
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

static int ipn_create(struct socket *sock, int protocol)
{
	struct ipn_sock *ipn_sk;
	struct ipn_node *ipn_node;
	//printk("IPN create %d\n",protocol);
	if (sock->type != SOCK_RAW)
		return -EPROTOTYPE;
	if (protocol > 0)
		protocol=protocol-1;
	else
		protocol=IPN_BROADCAST-1;
	if (protocol < 0 || protocol >= MAX_PROTO ||
			ipn_protocol_table[protocol] == NULL)
		return -EPROTONOSUPPORT;
	ipn_sk = (struct ipn_sock *) sk_alloc(PF_IPN, GFP_KERNEL, &ipn_proto, 1);

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
	ipn_node->protocol=protocol;
	ipn_node->flags=IPN_NODEFLAG_INUSE;
	ipn_node->shutdown=0;
	ipn_node->descr[0]=0;
	ipn_node->portno=IPN_PORTNO_ANY;
	ipn_node->dev=NULL;
	ipn_node->proto_private=NULL;
	spin_lock_init(&ipn_node->msglock);
	INIT_LIST_HEAD(&ipn_node->msgqueue);
	ipn_node->ipn=NULL;
	init_waitqueue_head(&ipn_node->read_wait);
	ipn_node->pbp=NULL;
	return 0;
}

static void ipn_flush_recvqueue(struct ipn_node *ipn_node)
{
	struct ipn_network *ipnn=ipn_node->ipn;
	/* delete all pending msgs */
	spin_lock(&ipn_node->msglock);
	while (!list_empty(&ipn_node->msgqueue)) {
		struct msgitem *msgitem=
			list_first_entry(&ipn_node->msgqueue, struct msgitem, list);
		list_del(&msgitem->list);
		ipn_node->msgcount--;
		ipn_msgpool_put(msgitem->msg,ipnn);
		kmem_cache_free(ipn_msgitem_cache,msgitem);
	}
	spin_unlock(&ipn_node->msglock);
}

static int ipn_release_node(struct ipn_node *ipn_node)
{
	if (!(ipn_node->flags & IPN_NODEFLAG_PERSIST)) 
	{
		struct ipn_network *ipnn=ipn_node->ipn;
		if (ipnn) {
			if (down_interruptible(&ipnn->ipnn_mutex)) {
				up(&ipn_glob_mutex);
				return -ERESTARTSYS;
			}
			if (ipn_node->portno >= 0) {
				ipn_protocol_table[ipnn->protocol]->ipn_p_predelport(ipn_node);
				ipnn->connport[ipn_node->portno]=NULL;
			}
			up(&ipnn->ipnn_mutex);
			ipn_flush_recvqueue(ipn_node);
			if (ipn_node->dev)
				ipn_netdev_close(ipn_node);
			if (ipn_node->portno >= 0) {
				ipn_protocol_table[ipnn->protocol]->ipn_p_delport(ipn_node);
			}

			/* No more network elements */
			if (atomic_dec_and_test(&ipnn->refcnt))
			{
				ipn_protocol_table[ipnn->protocol]->ipn_p_delnet(ipnn);
				ipn_remove_network(ipnn);
				ipn_protocol_table[ipnn->protocol]->refcnt--;
				if (ipnn->dentry) {
					dput(ipnn->dentry);
					mntput(ipnn->mnt);
				}
				module_put(THIS_MODULE);
				if (ipnn->msgpool_cache)
					kmem_cache_destroy(ipnn->msgpool_cache);
				kfree(ipnn);
			}
		}
		if (ipn_node->pbp) {
			kfree(ipn_node->pbp);
			ipn_node->pbp=NULL;
		} 
		kmem_cache_free(ipn_node_cache,ipn_node);
	} else
		ipn_node->flags &= ~IPN_NODEFLAG_INUSE;
	return 0;
}

static int ipn_release (struct socket *sock)
{
	struct ipn_sock *ipn_sk=(struct ipn_sock *)sock->sk;
	struct ipn_node *ipn_node=ipn_sk->node;
	int rv;
	//printk("IPN release\n");
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	rv=ipn_release_node(ipn_node);
	if (!rv)
		sock_put((struct sock *) ipn_sk);
	up(&ipn_glob_mutex);
	return rv;
}

static int ipn_setpersist(struct ipn_node *ipn_node, int persist)
{
	if (ipn_node->dev == NULL)
		return -ENODEV;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	if (persist)
		ipn_node->flags |= IPN_NODEFLAG_PERSIST;
	else {
		ipn_node->flags &= ~IPN_NODEFLAG_PERSIST;
		if (!(ipn_node->flags & IPN_NODEFLAG_INUSE))
			ipn_release_node(ipn_node);

	}
	up(&ipn_glob_mutex);
	return 0;
}

struct pre_bind_parms {
	unsigned short maxports;
	unsigned short flags;
	unsigned short msgpoolsize;
	unsigned short mtu;
	unsigned short mode;
};

/* STD_PARMS:  BITS_PER_BYTE nodes, no flags, BITS_PER_BYTE pending msgs, 
 * Ethernet + VLAN MTU*/
#define STD_BIND_PARMS {BITS_PER_BYTE, 0, BITS_PER_BYTE, 1514, 0x777};

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
			(ipn_node->protocol >= MAX_PROTO ||
			 ipn_protocol_table[ipn_node->protocol] == NULL)) {
		err= -EPROTONOSUPPORT;
		goto out;
	}

	addr_len = ipn_mkname(sunaddr, addr_len);
	if (addr_len < 0) {
		err=addr_len;
		goto out;
	}

	/* check if there is already a socket with that name */
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
		err = vfs_mknod(nd.dentry->d_inode, dentry, mode, 0);
		if (err)
			goto out_mknod_dput;
		mutex_unlock(&nd.dentry->d_inode->i_mutex);
		dput(nd.dentry);
		nd.dentry = dentry;
		/* create a new ipn_network item */
		if (ipn_node->pbp) 
			parms=*ipn_node->pbp;
		/* kzalloc the network structure (it cannot be a slub because the size depends
		 * on maxports */
		ipnn=kzalloc(sizeof(struct ipn_network) +
				(parms.maxports * sizeof(struct ipn_node *)),GFP_KERNEL);
		if (!ipnn) {
			err=-ENOMEM;
			goto out_mknod_dput;
		}
		if (!try_module_get(THIS_MODULE)) {
			err = -EINVAL;
			goto out_mknod_dput;
		}
		memcpy(&ipnn->sunaddr,sunaddr,addr_len);
		ipnn->mtu=parms.mtu;
		ipnn->msgpool_cache=kmem_cache_create(ipnn->sunaddr.sun_path,sizeof(struct msgpool_item)+ipnn->mtu,0,0,NULL,NULL);
		if (!ipnn->msgpool_cache) {
			err=-ENOMEM;
			goto out_mknod_dput_putmodule;
		}
		atomic_set(&ipnn->refcnt,1);
		ipnn->dentry=nd.dentry;
		ipnn->mnt=nd.mnt;
		init_MUTEX(&ipnn->ipnn_mutex);
		ipnn->sunaddr_len=addr_len;
		ipnn->protocol=ipn_node->protocol;
		if (ipnn->protocol < 0) ipnn->protocol = 0;
		ipn_protocol_table[ipnn->protocol]->refcnt++;
		ipnn->flags=parms.flags;
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
		err = vfs_permission(&nd, MAY_EXEC);
		if (err)
			goto put_fail;
		err = -ECONNREFUSED;
		if (!S_ISSOCK(nd.dentry->d_inode->i_mode))
			goto put_fail;
		ipnn=ipn_find_network_byinode(nd.dentry->d_inode);
		if (!ipnn)
			goto put_fail;
		atomic_inc(&ipnn->refcnt);
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
		/*printk("NODE %d PERM %d BOTH %d\n",ipn_node->shutdown,mustshutdown,mustshutdown|ipn_node->shutdown);*/
		mustshutdown |= ipn_node->shutdown;
		if (mustshutdown == (RCV_SHUTDOWN | SEND_SHUTDOWN)) {
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
		if (!ipnn) {
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

	/* is it possible to close ipn_glob_mutex here? */
	if (down_interruptible(&ipnn->ipnn_mutex)) {
		err=-ERESTARTSYS;
		goto out;
	}
	portno = ipn_protocol_table[ipnn->protocol]->ipn_p_newport(ipn_node);
	if (portno >= 0 && portno<ipnn->maxports) {
		sock->state = SS_CONNECTED;
		ipn_node->portno=portno;
		ipnn->connport[portno]=ipn_node;
		if (!(ipn_node->flags & IPN_NODEFLAG_BOUND))
			atomic_inc(&ipnn->refcnt);
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

	if (ipnn) {
		*uaddr_len = ipnn->sunaddr_len;
		memcpy(sunaddr,&ipnn->sunaddr,*uaddr_len);
	} else
		err = -ENOTCONN;
	return err;
}

static unsigned int ipn_poll(struct file *file, struct socket *sock, 
		poll_table *wait) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	unsigned int mask=0;

	if (ipnn) {
		poll_wait(file,&ipn_node->read_wait,wait);
		if (ipnn->flags & IPN_FLAG_LOSSLESS)
			poll_wait(file,&ipnn->send_wait,wait);
		if (!(list_empty(&ipn_node->msgqueue))) mask |= POLLIN | POLLRDNORM;
		if ((!(ipnn->flags & IPN_FLAG_LOSSLESS)) |
				(atomic_read(&ipnn->msgpool_nelem) < ipnn->msgpool_size))
			mask |= POLLOUT | POLLWRNORM;
	} 
	return mask;
}

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
	ipn_node->dev=ipn_netdev_alloc(ifr->ifr_flags,ifr->ifr_name,&err);
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
			} else 
				ipn_protocol_table[ipnn->protocol]->ipn_p_postnewport(ipn_node);
		} else {
			ipn_netdev_close(ipn_node); /*unregister unregistered dev problem!*/
			err=-EADDRNOTAVAIL;
			ipn_node->dev=NULL;
		}
	} else 
		err=-EINVAL;
	up(&ipnn->ipnn_mutex);
	up(&ipn_glob_mutex);
	return err;
}

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
	dev=dev_get_by_name(ifr->ifr_name);
	if (!dev) 
		dev=dev_get_by_index(ifr->ifr_ifindex);
	if (dev && (ipn_joined=ipn_netdev2node(dev)) != NULL) { /* the interface does exist */
		int i;
		for (i=0;i<ipnn->maxports && ipn_joined != ipnn->connport[i] ;i++)
			;
		if (i < ipnn->maxports) { /* found */
			/* ipn_joined is substituted to ipn_node */
			((struct ipn_sock *)sock->sk)->node=ipn_joined;
			ipn_node->flags |= IPN_NODEFLAG_INUSE;
			atomic_dec(&ipnn->refcnt);
			kmem_cache_free(ipn_node_cache,ipn_node);
		} else
			err=-EPERM;
	} else
		err=-EADDRNOTAVAIL;
	up(&ipnn->ipnn_mutex);
	up(&ipn_glob_mutex);
	return err;
}

static int ipn_setpersist_netdev(struct ifreq *ifr, int value)
{
	struct net_device *dev;
	struct ipn_node *ipn_node;
	int err=0;
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (down_interruptible(&ipn_glob_mutex))
		return -ERESTARTSYS;
	dev=dev_get_by_name(ifr->ifr_name);
	if (!dev)
		dev=dev_get_by_index(ifr->ifr_ifindex);
	if (dev && (ipn_node=ipn_netdev2node(dev)) != NULL &&
			ipn_check_node_connected(ipn_node) ) { /* the interface does exist */
		ipn_setpersist(ipn_node,value);
	} else
		err=-EADDRNOTAVAIL;
	up(&ipn_glob_mutex);
	return err;
}

static int ipn_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	void __user* argp = (void __user*)arg;
	struct ifreq ifr;

	switch (cmd) {
		case IPN_SETPERSIST_NETDEV:
		case IPN_CLRPERSIST_NETDEV:
		case IPN_CONN_NETDEV:
		case IPN_JOIN_NETDEV:
		case SIOCSIFHWADDR:
			if (copy_from_user(&ifr, argp, sizeof ifr))
				return -EFAULT;
			ifr.ifr_name[IFNAMSIZ-1] = '\0';
	}

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
	if (ipn_node->ipn == NULL)
		return -ENOTCONN;
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

static int ipn_shutdown(struct socket *sock, int mode) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	mode = (mode+1)&(RCV_SHUTDOWN|SEND_SHUTDOWN);

	ipn_node->shutdown |= mode;

	/* if recv channel has been shut down, flush the recv queue */
	if ((ipn_node->shutdown & RCV_SHUTDOWN) && ipnn)
		ipn_flush_recvqueue(ipn_node);

	return 0;
}

int ipn_proto_injectmsg(struct ipn_node *from, struct msgpool_item *msg, 
		int depth)
{
	struct ipn_network *ipnn=from->ipn;
	int err=0;
	if (down_interruptible(&ipnn->ipnn_mutex))
		err=-ERESTARTSYS;
	else {
		ipn_protocol_table[ipnn->protocol]->ipn_p_handlemsg(from, msg, depth);
		up(&ipnn->ipnn_mutex);
	}
	return err;
}


static int ipn_sendmsg(struct kiocb *kiocb, struct socket *sock,
		struct msghdr *msg, size_t len) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	struct msgpool_item *newmsg;
	int err=0;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (ipn_node->shutdown & SEND_SHUTDOWN)
		return -EPIPE;
	if (len > ipnn->mtu)
		return -EOVERFLOW;
	newmsg=ipn_msgpool_alloc_locking(ipnn);
	if (!newmsg)
		return -ENOMEM;
	newmsg->len=len;
	err=memcpy_fromiovec(newmsg->data, msg->msg_iov, len);
	if (!err) 
		ipn_proto_injectmsg(ipn_node, newmsg, 0);
	ipn_msgpool_put(newmsg,ipnn);
	return err;
}

void ipn_proto_sendmsg(struct ipn_node *to, struct msgpool_item *msg,
		int depth)
{
	if (to) {
		/* printk("SEND MSG TO %d\n",to->portno); */
		if (to->dev) {
			ipn_netdev_sendmsg(to,msg);
		} else {
			/* socket send */
			struct msgitem *msgitem;
			struct ipn_network *ipnn=to->ipn;
			spin_lock(&to->msglock);
			if (ipnn->flags & IPN_FLAG_LOSSLESS ||
					to->msgcount < ipnn->msgpool_size) {
				msgitem=kmem_cache_alloc(ipn_msgitem_cache,GFP_KERNEL);
				msgitem->msg=msg;
				to->msgcount++;
				list_add_tail(&msgitem->list, &to->msgqueue);
				ipn_msgpool_hold(msg);
			}
			spin_unlock(&to->msglock);
			wake_up_interruptible(&to->read_wait);
		}
	}
}

static int ipn_recvmsg(struct kiocb *kiocb, struct socket *sock,
		struct msghdr *msg, size_t len, int flags) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;
	struct msgitem *msgitem;
	struct msgpool_item *currmsg;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (ipn_node->shutdown & RCV_SHUTDOWN)
		return -EPIPE;

	spin_lock(&ipn_node->msglock);
	while (list_empty(&ipn_node->msgqueue)) {
		spin_unlock(&ipn_node->msglock);
		if (wait_event_interruptible(ipn_node->read_wait,
					!(list_empty(&ipn_node->msgqueue))))
			return -ERESTARTSYS;
		spin_lock(&ipn_node->msglock);
	}
	msgitem=list_first_entry(&ipn_node->msgqueue, struct msgitem, list);
	list_del(&msgitem->list);
	ipn_node->msgcount--;
	spin_unlock(&ipn_node->msglock);
	currmsg=msgitem->msg;
	if (currmsg->len < len)
		len=currmsg->len;
	memcpy_toiovec(msg->msg_iov, currmsg->data, len);
	ipn_msgpool_put(currmsg,ipnn);
	kmem_cache_free(ipn_msgitem_cache,msgitem);

	return len;
}

static int ipn_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int optlen) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;

	if (level != 0 && level != ipn_node->protocol+1)
		return -EPROTONOSUPPORT;
	if (level > 0) {
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
				memcpy(ipn_node->descr,optval,optlen);
				ipn_node->descr[optlen-1]=0;
				return 0;
			}
		} else {
			if (optlen < sizeof(int))
				return -EINVAL;
			else if ((optname & IPN_SO_PREBIND) && (ipnn != NULL))
				return -EISCONN;
			else {
				int val=*((int *)optval);
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
							val=-EISCONN;
						break;
					case IPN_SO_MTU:
						ipn_node->pbp->mtu=val;
						break;
					case IPN_SO_NUMNODES:
						ipn_node->pbp->maxports=val;
						break;
					case IPN_SO_MSGPOOLSIZE:
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

static int ipn_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen) {
	struct ipn_node *ipn_node=((struct ipn_sock *)sock->sk)->node;
	struct ipn_network *ipnn=ipn_node->ipn;

	if (level != 0 && level != ipn_node->protocol+1)
		return -EPROTONOSUPPORT;
	if (level > 0) {
		if (ipnn) {
			int rv;
			if (down_interruptible(&ipnn->ipnn_mutex))
				return -ERESTARTSYS;
			rv=ipn_protocol_table[ipn_node->protocol]->ipn_p_getsockopt(ipn_node,optname,optval,optlen);
			up(&ipnn->ipnn_mutex);
			return rv;
		} else
			return -EOPNOTSUPP;
	} else {
		if (optname == IPN_SO_DESCR) {
			if (*optlen < IPN_DESCRLEN)
				return -EINVAL;
			else {
				if (*optlen > IPN_DESCRLEN)
					*optlen=IPN_DESCRLEN;
				memcpy(optval,ipn_node->descr,*optlen);
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
				if (*optlen < sizeof(int))
					return -EOVERFLOW;
				else {
					*optlen=sizeof(int);
					*((int *) optval) = val;
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
		struct msgpool_item *msgitem,
		int depth){
	struct ipn_network *ipnn=from->ipn;
	int i;
	for (i=0; i<ipnn->maxports; i++)
		if (ipnn->connport[i] && ipnn->connport[i] != from)
			ipn_proto_sendmsg(ipnn->connport[i],msgitem,depth);
	return 0;
}

static void ipn_null_delport(struct ipn_node *oldport) {}
static void ipn_null_postnewport(struct ipn_node *newport) {}
static  void ipn_null_predelport(struct ipn_node *oldport) {}
static int ipn_null_newnet(struct ipn_network *newnet) {return 0;}
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
	if (protocol > 1 && protocol <= MAX_PROTO) {
		protocol--;
		if (ipn_protocol_table[protocol])
			rv= -EEXIST;
		else {
			ipn_service->refcnt=0;
			ipn_protocol_table[protocol]=ipn_service;
			printk(KERN_INFO "IPN-VDE: Registered protocol %d\n",protocol+1);
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
	if (protocol > 1 && protocol <= MAX_PROTO) {
		protocol--;
		if (ipn_protocol_table[protocol]) {
			if (ipn_protocol_table[protocol]->refcnt == 0) {
				ipn_protocol_table[protocol]=NULL;
				printk(KERN_INFO "IPN-VDE: Unregistered protocol %d\n",protocol+1);
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

static int ipn_init(void)
{
	int rc;

	ipn_init_protocol(&ipn_bcast);
	ipn_node_cache=kmem_cache_create("ipn_node",sizeof(struct ipn_node),0,0,NULL,NULL);
	if (!ipn_node_cache) {
		printk(KERN_CRIT "%s: Cannot create ipn_node SLAB cache!\n",
				__FUNCTION__);
		rc=-ENOMEM;
		goto out;
	}

	ipn_msgitem_cache=kmem_cache_create("ipn_msgitem",sizeof(struct msgitem),0,0,NULL,NULL);
	if (!ipn_msgitem_cache) {
		kmem_cache_destroy(ipn_node_cache);
		printk(KERN_CRIT "%s: Cannot create ipn_msgitem SLAB cache!\n",
				__FUNCTION__);
		rc=-ENOMEM;
		goto out;
	}

	if ((rc=ipn_hash_init()) < 0) {
		kmem_cache_destroy(ipn_node_cache);
		kmem_cache_destroy(ipn_msgitem_cache);
		printk(KERN_CRIT "%s: Cannot startup hash table management!\n",
				__FUNCTION__);
		goto out;
	}

	rc=proto_register(&ipn_proto,1);
	if (rc != 0) {
		printk(KERN_CRIT "%s: Cannot create ipn_node SLAB cache!\n",
				__FUNCTION__);
		goto out;
	}

	sock_register(&ipn_family_ops);
	ipn_netdev_init();
	printk(KERN_INFO "IPN-VDE: Virtual Square Project, University of Bologna (c) 2007\n");
out:
	return rc;
}

static void ipn_exit(void)
{
	cleanup_persistent_nodes();
	ipn_netdev_fini();
	ipn_hash_fini();
	if (ipn_msgitem_cache)
		kmem_cache_destroy(ipn_msgitem_cache);
	if (ipn_node_cache)
		kmem_cache_destroy(ipn_node_cache);
	sock_unregister(PF_IPN);
	proto_unregister(&ipn_proto);
	printk(KERN_INFO "IPN-VDE removed\n");
}

module_init(ipn_init);
module_exit(ipn_exit);

EXPORT_SYMBOL_GPL(ipn_proto_register);
EXPORT_SYMBOL_GPL(ipn_proto_deregister);
EXPORT_SYMBOL_GPL(ipn_proto_sendmsg);
EXPORT_SYMBOL_GPL(ipn_msgpool_alloc);
EXPORT_SYMBOL_GPL(ipn_msgpool_put);
