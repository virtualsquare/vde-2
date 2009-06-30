#ifndef __LINUX_NET_AFIPN_H
#define __LINUX_NET_AFIPN_H
#include <linux/socket.h>

#ifdef IPN_STEALING
/* AF_NETBEUI seems to be unused */
#define AF_IPN AF_NETBEUI
#define PF_IPN AF_IPN
#define ipn_handle_frame_hook br_handle_frame_hook
#else
#ifndef AF_IPN
/* waiting for the official assigment of our AF */
/* #define AF_IPN ??? */
#define AF_IPN AF_NETBEUI
#define PF_IPN AF_IPN
#endif
#define AF_IPN_STOLEN AF_NETBEUI
#define PF_IPN_STOLEN AF_IPN_STOLEN
#endif

#define IPN_ANY 0
#define IPN_BROADCAST 1
#define IPN_HUB 1
#define IPN_VDESWITCH 2
#define IPN_VDESWITCH_L3 3

#define IPN_SO_PREBIND 0x80
#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#define IPN_SO_CHANGE_NUMNODES 2
#define IPN_SO_HANDLE_OOB 3
#define IPN_SO_WANT_OOB_NUMNODES 4
#define IPN_SO_MTU (IPN_SO_PREBIND | 0)
#define IPN_SO_NUMNODES (IPN_SO_PREBIND | 1)
#define IPN_SO_MSGPOOLSIZE (IPN_SO_PREBIND | 2)
#define IPN_SO_FLAGS (IPN_SO_PREBIND | 3)
#define IPN_SO_MODE (IPN_SO_PREBIND | 4)

#define IPN_PORTNO_ANY -1

#define IPN_DESCRLEN 128

#define IPN_FLAG_LOSSLESS 1
#define IPN_FLAG_EXCL 2
#define IPN_FLAG_FLEXMTU 4
#define IPN_FLAG_TERMINATED 0x1000

/* Ioctl defines */
#define IPN_CHECK               _IOW('I', 199, int) 
#define IPN_SETPERSIST_NETDEV  	_IOW('I', 200, int) 
#define IPN_CLRPERSIST_NETDEV  	_IOW('I', 201, int) 
#define IPN_CONN_NETDEV          _IOW('I', 202, int) 
#define IPN_JOIN_NETDEV          _IOW('I', 203, int) 
#define IPN_SETPERSIST           _IOW('I', 204, int) 
#define IPN_REGISTER_CHRDEV      _IOW('I', 301, int) 
#define IPN_UNREGISTER_CHRDEV    _IOW('I', 302, int) 

#define IPN_OOB_NUMNODE_TAG	0

/* ioctl request for IPN_REGISTER_CHRDEV
 * @dev: first device (if major==0 alloc a dynamic major)
 * @count: num of minors
 * @name: device name
 * */
struct chrdevreq {
	unsigned int major;
	unsigned int minor;
	int count;
	char name[64];
};

/* OOB message for change of numnodes
 * Common fields for oob IPN signaling:
 * @level=level of the service who generated the oob
 * @tag=tag of the message
 * Specific fields:
 * @numreaders=number of readers
 * @numwriters=number of writers
 * */
struct numnode_oob {
	int level;
	int tag;
	int numreaders;
	int numwriters;
};

#ifdef __KERNEL__
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#define kmem_cache_create(A,B,C,D,E) kmem_cache_create((A),(B),(C),(D),(E),(E))
#endif

#include <linux/mutex.h>
#include <linux/un.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <net/sock.h>
#include <linux/netdevice.h>

#define IPN_HASH_SIZE	256

/* The AF_IPN socket */
struct msgpool_item;
struct ipn_network;
struct pre_bind_parms;

/* 
 * ipn_node
 *
 * @nodelist=pointers for connectqueue or unconnectqueue (see network)
 * @protocol=kind of service 0->standard broadcast
 * @flags= see IPN_NODEFLAG_xxx
 * @shutdown= SEND_SHUTDOWN/RCV_SHUTDOWN and OOBRCV_SHUTDOWN
 * @descr=description of this port
 * @portno=when connected: port of the netowrk (<0 means unconnected)
 * @msglock=mutex on the msg queue
 * @totmsgcount=total # of pending msgs
 * @oobmsgcount=# of pending oob msgs
 * @msgqueue=queue of messages
 * @oobmsgqueue=queue of messages
 * @read_wait=waitqueue for reading
 * @net=current network
 * @dev=device (TAP or GRAB)
 * @ipn=network we are connected to
 * @pbp=temporary storage for parms that must be set prior to bind
 * @proto_private=handle for protocol private data
 */
struct ipn_node {
	struct list_head nodelist;
	int protocol;
	volatile unsigned char flags; 
	unsigned char shutdown;
	char descr[IPN_DESCRLEN];
	int portno;
	spinlock_t msglock;
	unsigned short totmsgcount;
	unsigned short oobmsgcount;
	struct list_head msgqueue;
	struct list_head oobmsgqueue;
	wait_queue_head_t read_wait;
	struct net *net;
	struct net_device *netdev;
	dev_t chrdev;
	struct ipn_network *ipn;
	struct pre_bind_parms *pbp;
	void *proto_private;
};
#define IPN_NODEFLAG_BOUND 0x1     /* bind succeeded */
#define IPN_NODEFLAG_INUSE 0x2     /* is currently "used" (0 for persistent, unbound interfaces) */
#define IPN_NODEFLAG_PERSIST 0x4   /* if persist does not disappear on close (net interfaces) */
#define IPN_NODEFLAG_TAP   0x10    /* This is a tap interface */
#define IPN_NODEFLAG_GRAB  0x20    /* This is a grab of a real interface */
#define IPN_NODEFLAG_DEVMASK 0x30  /* True if this is a device */
#define IPN_NODEFLAG_OOB_NUMNODES 0x40  /* Node wants OOB for NNODES */

/*
 * ipn_sock
 * 
 * unfortunately we must use a struct sock (most of the fields are useless) as
 * this is the standard "agnostic" structure for socket implementation.
 * This proofs that it is not "agnostic" enough!
 */

struct ipn_sock {
	struct sock sk;
	struct ipn_node *node;
};

/* ipn_chrdev cdev to ipn_dev mapping, defined in ipn_chrdev.c */
struct ipn_chrdev;

/* 
 * ipn_network network descriptor
 *
 * @hnode=hash to find this entry (looking for i-node)
 * @unconnectqueue=queue of unconnected (bound) nodes
 * @connectqueue=queue of connected nodes (faster for broadcasting)
 * @refcnt=reference count (bound or connected sockets)
 * @dentry/@mnt=to keep the file system descriptor into memory
 * @ipnn_lock=lock for protocol functions
 * @protocol=kind of service
 * @flags=flags (IPN_FLAG_LOSSLESS)
 * @maxports=number of ports available in this network
 * @msgpool_nelem=number of pending messages
 * @msgpool_size=max number of pending messages *per net* when IPN_FLAG_LOSSLESS
 * @msgpool_size=max number of pending messages *per port*when LOSSY
 * @mtu=MTU
 * @send_wait=wait queue waiting for a message in the msgpool (IPN_FLAG_LOSSLESS)
 * @msgpool_cache=slab for msgpool (unused yet)
 * @proto_private=handle for protocol private data
 * @connports=array of connected sockets
 * @chrdev=chr device(s) connected to this ipn_network
 */
struct ipn_network {
	struct hlist_node hnode;
	struct list_head unconnectqueue;
	struct list_head connectqueue;
	int refcnt;
	struct dentry		*dentry;
  struct vfsmount		*mnt;
	struct semaphore ipnn_mutex;
	int sunaddr_len;
	struct sockaddr_un sunaddr;
	unsigned int protocol;
	unsigned int flags;
	int numreaders;
	int numwriters;
	atomic_t msgpool_nelem;
	unsigned short maxports;
	unsigned short msgpool_size;
	unsigned short mtu;
	wait_queue_head_t send_wait;
	struct kmem_cache *msgpool_cache;
	void *proto_private;
	struct ipn_node **connport;
	struct ipn_chrdev *chrdev;
};

/* struct msgpool_item 
 * the local copy of the message for dispatching
 * @count refcount
 * @len packet len
 * @data payload
 */
struct msgpool_item {
	atomic_t count;
	int len;
	unsigned char data[0];
};

struct msgpool_item *ipn_msgpool_alloc(struct ipn_network *ipnn,int leaky,int len);
void ipn_msgpool_put(struct msgpool_item *old, struct ipn_network *ipnn);

/* 
 * protocol service:
 *
 * @refcnt: number of networks using this protocol
 * @newport=upcall for reporting a new port. returns the portno, -1=error  
 * @handlemsg=dispatch a message.
 *            should call ipn_proto_sendmsg for each desctination
 *            can allocate other msgitems using ipn_msgpool_alloc to send
 *            different messages to different destinations;
 * @delport=(may be null) reports the terminatio of a port
 * @postnewport,@predelport: similar to newport/delport but during these calls
 *            the node is (still) connected. Useful when protocols need
 *            welcome and goodbye messages.
 * @ipn_p_setsockopt
 * @ipn_p_getsockopt
 * @ipn_p_ioctl=(may be null) upcall to manage specific options or ctls.
 */
struct ipn_protocol {
	int refcnt;
	int (*ipn_p_newport)(struct ipn_node *newport);
	int (*ipn_p_handlemsg)(struct ipn_node *from,struct msgpool_item *msgitem);
	void (*ipn_p_delport)(struct ipn_node *oldport);
	void (*ipn_p_postnewport)(struct ipn_node *newport);
	void (*ipn_p_predelport)(struct ipn_node *oldport);
	int (*ipn_p_newnet)(struct ipn_network *newnet);
	int (*ipn_p_resizenet)(struct ipn_network *net,int oldsize,int newsize);
	void (*ipn_p_delnet)(struct ipn_network *oldnet);
	int (*ipn_p_setsockopt)(struct ipn_node *port,int optname,
			char __user *optval, int optlen);
	int (*ipn_p_getsockopt)(struct ipn_node *port,int optname,
			char __user *optval, int *optlen);
	int (*ipn_p_ioctl)(struct ipn_node *port,unsigned int request, 
			unsigned long arg);
};

int ipn_proto_register(int protocol,struct ipn_protocol *ipn_service);
int ipn_proto_deregister(int protocol);

int ipn_proto_injectmsg(struct ipn_node *from, struct msgpool_item *msg);
void ipn_proto_sendmsg(struct ipn_node *to, struct msgpool_item *msg);
void ipn_proto_oobsendmsg(struct ipn_node *to, struct msgpool_item *msg);

struct ipn_node *ipn_node_create(struct net *net);
int ipn_node_connect(struct ipn_node *ipn_node);
int ipn_node_create_connect(struct ipn_node **ipn_node_out,
		struct ipn_network *(* ipnn_map)(void *),void *ipnn_map_arg);
int ipn_node_release(struct ipn_node *ipn_node);
unsigned int ipn_node_poll(struct ipn_node *ipn_node, struct file *file, poll_table *wait);
int ipn_node_ioctl(struct ipn_node *ipn_node, unsigned int cmd, unsigned long arg);
int ipn_node_write(struct ipn_node *ipn_node, struct iovec *msg_iov, int len);
int ipn_node_read(struct ipn_node *ipn_node, struct iovec *msg_iov, size_t len, int *msg_flags, int flags);

#ifndef IPN_STEALING
extern struct sk_buff *(*ipn_handle_frame_hook)(struct ipn_node *p,
						struct sk_buff *skb);
#endif
#endif
#endif
