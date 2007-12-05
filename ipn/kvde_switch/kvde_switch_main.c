#include <linux/module.h>
#include <linux/if_ether.h>
#include "../af_ipn.h"
#include "../ipn_hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIEW-OS TEAM");
MODULE_DESCRIPTION("VDE SWITCH Kernel Module");

static struct kmem_cache *kvde_net_cache;
#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)

static int ipn_kvde_switch_newport(struct ipn_node *newport) {
	struct ipn_network *ipnn=newport->ipn;
	int i;
	for (i=0;i<ipnn->maxports;i++) {
		if (ipnn->connport[i] == NULL)
			return i;
	}
	return -1;
}

static int ipn_kvde_switch_handlemsg(struct ipn_node *from, struct msgpool_item *msgitem){
	struct ipn_network *ipnn=from->ipn;
	struct ipn_hash *vdeh=(struct ipn_hash *)ipnn->proto_private;
	int port;
	struct ethhdr *ehdr=(struct ethhdr *)msgitem->data;
	if (msgitem->len < sizeof(struct ethhdr))
		return 0;
	if (!IS_BROADCAST(ehdr->h_source)) 
		ipn_hash_add(vdeh,(u16 *)&ehdr->h_source,0,from->portno);
	if (IS_BROADCAST(ehdr->h_dest) || 
			(port = ipn_hash_find(vdeh,(u16 *)&ehdr->h_dest,0)) < 0) {
		/*printk("SWITCH FROM %d -> BROADCAST\n",from->portno);*/
		for (port=0; port<ipnn->maxports; port++)
			if (ipnn->connport[port] && ipnn->connport[port] != from)
				ipn_proto_sendmsg(ipnn->connport[port],msgitem);
	} else {
		/*printk("SWITCH FROM %d -> %d\n",from->portno,port);*/
		ipn_proto_sendmsg(ipnn->connport[port],msgitem);
	}
	return 0;
}

static void ipn_kvde_switch_delport(struct ipn_node *oldport) {
	struct ipn_network *ipnn=oldport->ipn;
	struct ipn_hash *vdeh=(struct ipn_hash *)ipnn->proto_private;
	ipn_hash_flush_port(vdeh,oldport->portno);
}

static int ipn_kvde_switch_newnet(struct ipn_network *newnet) {
	struct ipn_hash *vdeh=kmem_cache_alloc(kvde_net_cache,GFP_KERNEL);
	if (!vdeh)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE))
		return -EINVAL;
	newnet->proto_private=vdeh;
	ipn_hash_new(vdeh,256,30);
	return 0;
}

static void ipn_kvde_switch_delnet(struct ipn_network *oldnet) {
	struct ipn_hash *vdeh=(struct ipn_hash *) oldnet->proto_private;
	ipn_hash_free(vdeh);
	kmem_cache_free(kvde_net_cache,vdeh);
	module_put(THIS_MODULE);
}

static int ipn_kvde_switch_setsockopt(struct ipn_node *port,int optname,
		    char __user *optval, int optlen) {return -EOPNOTSUPP;}
static int ipn_kvde_switch_getsockopt(struct ipn_node *port,int optname,
		    char __user *optval, int *optlen) {return -EOPNOTSUPP;}
static int ipn_kvde_switch_ioctl(struct ipn_node *port,unsigned int request,
		    unsigned long arg) {return -EOPNOTSUPP;}

/* static void ipn_kvde_switch_postnewport(struct ipn_node *newport) {} */
/* static  void ipn_kvde_switch_predelport(struct ipn_node *oldport) {} */
static struct ipn_protocol vde_switch_proto={
	.ipn_p_newport=ipn_kvde_switch_newport,
	.ipn_p_handlemsg=ipn_kvde_switch_handlemsg,
	.ipn_p_delport=ipn_kvde_switch_delport,
	/*.ipn_p_postnewport=ipn_kvde_switch_postnewport,*/
	/*.ipn_p_predelport=ipn_kvde_switch_predelport,*/
	.ipn_p_newnet=ipn_kvde_switch_newnet,
	.ipn_p_delnet=ipn_kvde_switch_delnet,
	.ipn_p_setsockopt=ipn_kvde_switch_setsockopt,
	.ipn_p_getsockopt=ipn_kvde_switch_getsockopt,
	.ipn_p_ioctl=ipn_kvde_switch_ioctl

};

static int kvde_switch_init(void)
{
	int rc=0;
	kvde_net_cache=kmem_cache_create("kvde_net",sizeof(struct ipn_hash),0,0,NULL,NULL);
	if (!kvde_net_cache) {
		rc=-ENOMEM;
		goto out;
	}
	rc=ipn_proto_register(IPN_SWITCH,&vde_switch_proto);
out:
	return rc;
}

static void kvde_switch_exit(void)
{
	ipn_proto_deregister(IPN_SWITCH);
	if(kvde_net_cache)
		kmem_cache_destroy(kvde_net_cache);
}

module_init(kvde_switch_init);
module_exit(kvde_switch_exit);

