/* 
 * tc bfifo module 
 * Usage: tc set <dev> bfifo limit <bytes>	
 *
 * */ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"
#include "vde_buff.h"
#include "vde_l3.h"

/** Private per-interface structure
 *
 */
struct tc_bfifo
{
	uint32_t qlen;
	uint32_t limit;	
	uint32_t dropped;
};

#define bfifo_tcpriv(x) (struct tc_bfifo*)(tcpriv(x))

/*
 * Enqueue function. Try to add the packet 'vdb' to the output queue
 * of the interface 'vif'
 *
 * return value: 1 = packet was enqueued, 0 = packet was rejected
 */
int bfifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif)
{
	struct tc_bfifo *bfifo = bfifo_tcpriv(vif); 
	if ( (bfifo->qlen + vdb->len)  < bfifo->limit){
		bfifo->qlen += vdb->len;
		ufifo_enqueue(vdb,vif);
		return 1;
	}else{
		/* Queue Full: dropping. */
		free(vdb);
		bfifo->dropped++;
		return 0;
	}
}

/* Dequeue function. Interface is ready to send the packet.
 *
 */
int bfifo_dequeue(struct vde_iface *vif)
{
	struct tc_bfifo *bfifo = bfifo_tcpriv(vif);
	(void)ufifo_dequeue(vif);
	if(bfifo->qlen > 0)
		bfifo->qlen -= vif->q_out->len;
	return (bfifo->qlen > 0);
}



/* Function to initialize the queue on the given interface.
 */
int bfifo_init(struct vde_iface *vif, char *args)
{
	struct tc_bfifo *bfifo=(struct tc_bfifo *)malloc(sizeof(struct tc_bfifo));
	int arglen = strlen(args) - 1;
	
	if ((arglen < 6) || strncmp(args,"limit ",6) || (sscanf(args+6, "%u",&(bfifo->limit)) < 1) )
		return 0;

	bfifo->qlen = 0;
	bfifo->dropped = 0;
	vif->policy_name="bfifo";
	memcpy(vif->tc_priv, bfifo, sizeof(struct tc_bfifo));
	return 1;
}

char *bfifo_tc_stats(struct vde_iface *vif)
{
	struct tc_bfifo *bfifo = bfifo_tcpriv(vif);
	char *statistics=(char*)malloc(256);
	snprintf(statistics,255,"Limit: %u bytes. Dropped: %u packets.", bfifo->limit, bfifo->dropped);
	return statistics;
	
}


/*
 * Module symbol to load into module list.
 *
 */
struct routing_policy module_routing_policy=
{
	.name="bfifo",
	.help="Packet Fifo queue\nUsage: tc set <dev> bfifo limit <limit in bytes>\n",
	.policy_init = bfifo_init,
	.enqueue = bfifo_enqueue,
	.dequeue = bfifo_dequeue,
	.tc_stats = bfifo_tc_stats
};

static void
__attribute__ ((constructor))
init (void)
{
	fprintf(stderr,"Loading library: bfifo.so\n");

}

	static void
	__attribute__ ((destructor))
fini (void)
{

}
