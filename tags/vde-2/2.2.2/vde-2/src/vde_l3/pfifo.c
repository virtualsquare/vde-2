/* 
 * tc pfifo module 
 * Usage: tc set <dev> pfifo limit <packets>	
 *
 * */ 
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>
#include "vde_buff.h"
#include "vde_l3.h"

/** Private per-interface structure
 *
 */
struct tc_pfifo
{
	uint32_t qlen;
	uint32_t limit;	
	uint32_t dropped;
};

#define pfifo_tcpriv(x) (struct tc_pfifo*)(tcpriv(x))

/*
 * Enqueue function. Try to add the packet 'vdb' to the output queue
 * of the interface 'vif'
 *
 * return value: 1 = packet was enqueued, 0 = packet was rejected
 */
int pfifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif)
{
	struct tc_pfifo *pfifo = pfifo_tcpriv(vif); 
	if (pfifo->qlen < pfifo->limit){
		pfifo->qlen++;
		ufifo_enqueue(vdb,vif);
		return 1;
	}else{
		/* Queue Full: dropping. */
		free(vdb);
		pfifo->dropped++;
		return 0;
	}
}

/* Dequeue function. Interface is ready to send the packet.
 *
 */
int pfifo_dequeue(struct vde_iface *vif)
{
	struct tc_pfifo *pfifo = pfifo_tcpriv(vif);
	(void)ufifo_dequeue(vif);
	if(pfifo->qlen > 0)
		pfifo->qlen--;
	return (pfifo->qlen > 0);
}



/* Function to initialize the queue on the given interface.
 */
int pfifo_init(struct vde_iface *vif, char *args)
{
	struct tc_pfifo *pfifo=(struct tc_pfifo *)malloc(sizeof(struct tc_pfifo));
	int arglen = strlen(args) - 1;
	
	if ((arglen < 6) || strncmp(args,"limit ",6) || (sscanf(args+6, "%u",&(pfifo->limit)) < 1) )
		return 0;

	pfifo->qlen = 0;
	pfifo->dropped = 0;
	vif->policy_name="pfifo";
	memcpy(vif->tc_priv, pfifo, sizeof(struct tc_pfifo));
	return 1;
}

char *pfifo_tc_stats(struct vde_iface *vif)
{
	struct tc_pfifo *pfifo = pfifo_tcpriv(vif);
	char *statistics=(char*)malloc(256);
	snprintf(statistics,255,"Limit: %u packets. Dropped: %u packets.", pfifo->limit, pfifo->dropped);
	return statistics;
	
}


/*
 * Module symbol to load into module list.
 *
 */
struct routing_policy module_routing_policy=
{
	.name="pfifo",
	.help="Packet Fifo queue\nUsage: tc set <dev> pfifo limit <packets>\n",
	.policy_init = pfifo_init,
	.enqueue = pfifo_enqueue,
	.dequeue = pfifo_dequeue,
	.tc_stats = pfifo_tc_stats
};

static void
__attribute__ ((constructor))
init (void)
{
	fprintf(stderr,"Loading library: pfifo.so\n");

}

	static void
	__attribute__ ((destructor))
fini (void)
{

}
