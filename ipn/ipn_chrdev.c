/*
 * Inter process networking (virtual distributed ethernet) module
 * Char device support
 *
 * Copyright (C) 2009   Renzo Davoli, Jacopo Mondi, Enrico Tramacere
 * {renzo,mondi,tramacer}@cs.unibo.it
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
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "af_ipn.h"
#include "ipn_chrdev.h"
#include "ipn_msgbuf.h"

/* struct ipn_chrdev: 
 * this is the type of the ipnn->chrdev field, when ipnn->chrdev is non-null,
 * a character device (or a range of character devices) gives access to the ipn-network.
 * this is also the data structure used by "container of" to retrieve ipnn from the device
 * in O(1) time.
 */
struct ipn_chrdev {
	dev_t dev;
	unsigned int dev_count;
	struct ipn_network *ipnn;
	struct cdev cdev;
};

/* cdev to ipnn mapping */

static struct ipn_network *ipn_chrdev_to_ipnn(void *i_cdev)
{
	struct ipn_chrdev *chrdev;
	chrdev=container_of(i_cdev, struct ipn_chrdev, cdev);
	return chrdev->ipnn;
}

/* open: device open: find the ipnn and add a node to the ipnn */
static int ipn_chrdev_open(struct inode *inode, struct file *filp)
{
	struct ipn_node *ipn_node;
	/*struct ipn_network *ipnn;*/
	int err;
	unsigned char mustshutdown=0;
	err = inode_permission(inode, MAY_READ);
	if (!(filp->f_mode & FMODE_READ) || err == -EACCES || err == -EROFS)
		mustshutdown|=RCV_SHUTDOWN;
	err = inode_permission(inode, MAY_WRITE);
	if (!(filp->f_mode & FMODE_WRITE) || err == -EACCES)
		mustshutdown|=SEND_SHUTDOWN;
	if ((mustshutdown & RCV_SHUTDOWN) && (mustshutdown & SEND_SHUTDOWN))
		return -EACCES;

	err=ipn_node_create_connect(&ipn_node, ipn_chrdev_to_ipnn, inode->i_cdev);
	filp->private_data=ipn_node;
	if (ipn_node) {
		ipn_node->shutdown=mustshutdown;
		ipn_node->chrdev=inode->i_rdev;
	}
	return err;
}

/* file operations read/write/release/poll, mapped onto the
 * ipn_node ops */
static ssize_t ipn_chrdev_write(struct file *filp, const char __user *buf, size_t len, loff_t *f_pos)
{
	struct ipn_node *ipn_node=filp->private_data;
	struct iovec iov={(char __user *)buf,len};
	//printk("ipn_chrdev_write %d\n",len);
	return ipn_node_write(ipn_node, &iov, len);
}

static ssize_t ipn_chrdev_read(struct file *filp, char __user *buf, size_t len, loff_t *f_pos)
{
	struct ipn_node *ipn_node=filp->private_data;
	int noflags;
	struct iovec iov={buf,len};
	//printk("ipn_chrdev_read %d\n",len);
	return ipn_node_read(ipn_node, &iov, len, &noflags, 0);
}

static int ipn_chrdev_release(struct inode *inode, struct file *filp)
{
	struct ipn_node *ipn_node=filp->private_data;
	return ipn_node_release(ipn_node);
}

static unsigned int ipn_chrdev_poll(struct  file *filp, poll_table *wait)
{
	struct ipn_node *ipn_node=filp->private_data;
	return ipn_node_poll(ipn_node,filp,wait);
}

static int ipn_chrdev_ioctl(struct inode *ino, struct  file *filp, unsigned int cmd, unsigned long arg)
{
	struct ipn_node *ipn_node=filp->private_data;
	return ipn_node_ioctl(ipn_node,cmd,arg);
}

struct file_operations ipn_chrdev_fops = {
	.owner = THIS_MODULE,
	.open = ipn_chrdev_open,
	.write = ipn_chrdev_write,
	.read  = ipn_chrdev_read,
	.release = ipn_chrdev_release,
	.poll = ipn_chrdev_poll,
	.ioctl = ipn_chrdev_ioctl
};

/* init a struct ipn_chrdev and add the cdev */
static int ipn_init_cdev(struct ipn_chrdev *ipn_dev, dev_t first, int count)
{
	cdev_init(&ipn_dev->cdev, &ipn_chrdev_fops);
	ipn_dev->cdev.owner = THIS_MODULE;
	ipn_dev->cdev.ops = &ipn_chrdev_fops;
	return cdev_add(&ipn_dev->cdev, first, count);
}

/* register/allocate a chrdev range for this ipn network.
 * ipnn is locked during this op */
int ipn_register_chrdev(struct ipn_network *ipnn, struct chrdevreq *devr) {
	int ret;
	dev_t dev=MKDEV(devr->major,devr->minor);
	if (!capable(CAP_MKNOD))
		return -EPERM;
	if (ipnn->chrdev)
		return -EADDRINUSE;
	if (devr->major == 0) {
		ret=alloc_chrdev_region(&dev, devr->minor, devr->count, devr->name);
		devr->major=MAJOR(dev);
		devr->minor=MINOR(dev);
		/*printk("alloc_chrdev_region %d %d %s\n",ret,devr->major,devr->name);*/
	} else 
		ret=register_chrdev_region(dev, devr->count, devr->name);
	if (ret)
		return ret;
	if ((ipnn->chrdev=kmalloc(sizeof(struct ipn_chrdev), GFP_KERNEL)) == NULL) {
		ret=ENOMEM;
		goto unregister_chrdev;
	}
	ipnn->chrdev->dev=dev;
	ipnn->chrdev->dev_count=devr->count;
	ipnn->chrdev->ipnn=ipnn;
	ret=ipn_init_cdev(ipnn->chrdev, dev, devr->count);
	if (ret)
		goto unregister_chrdev;
	return 0;

unregister_chrdev:
	unregister_chrdev_region(dev, devr->count);
	return ret;
}

/* deregister a chrdev range. ipnn is locked */
int ipn_deregister_chrdev(struct ipn_network *ipnn) {
	if (ipnn->chrdev == 0)
		return EINVAL;
	cdev_del(&ipnn->chrdev->cdev);
	/*printk("deregister_chrdev %d %d\n",MAJOR(ipnn->chrdev->dev),ipnn->chrdev->dev_count);*/
  unregister_chrdev_region(ipnn->chrdev->dev, ipnn->chrdev->dev_count);
	kfree(ipnn->chrdev);
	ipnn->chrdev=NULL;
	return 0;
}

