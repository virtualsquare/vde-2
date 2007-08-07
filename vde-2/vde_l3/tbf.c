/* 
 * tc token bucket module 
 * Usage: tc set <dev> tbf rate <speed>[K|M] limit <packets> 	
 * Alternate usage: tc set <dev> tbf rate <speed>[K|M] latency <ms>
 *
 *
 *
 * */ 
#include "vde_buff.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

struct timeval add_t(struct timeval x, struct timeval y) 
{ 
	struct timeval ret = {
		.tv_sec = x.tv_sec + y.tv_sec + ((x.tv_usec + y.tv_usec) / 1000000),
		.tv_usec = (x.tv_usec + y.tv_usec) % 1000000
	};
	return ret;
}
#define before(x,y) x.tv_sec < y.tv_sec || (x.tv_sec == y.tv_sec && x.tv_usec < y.tv_usec)

#define tbf_tcpriv(x) (struct tc_tbf*)(tcpriv(x))

/** Private per-interface structure
 *
 */
struct tc_tbf
{
	uint32_t qlen; // Bytes.
	uint32_t limit;	// Bytes.
	uint32_t latency; // ms
	uint32_t rate; // bits/s
	uint32_t dropped; //packets
	uint32_t mtu;
	uint32_t bytes_out;
	struct timeval  delta;
	struct timeval last_out;
};


/*
 * Enqueue function. Try to add the packet 'vdb' to the output queue
 * of the interface 'vif'
 *
 * return value: 1 = packet was enqueued, 0 = packet was rejected
 */
int tbf_enqueue(struct vde_buff *vdb, struct vde_iface *vif)
{
	struct tc_tbf *tbf = tbf_tcpriv(vif); 
	if (tbf->qlen < tbf->limit){
		tbf->qlen+=vdb->len;
		ufifo_enqueue(vdb,vif);
		if(vdb->len > tbf->mtu){
			tbf->mtu = vdb->len;
			tbf->delta.tv_usec = (1000000*tbf->mtu) / tbf->rate;
			if (tbf->latency){
				tbf->limit = (tbf->rate/tbf->mtu) * tbf->latency;
			}
		}
		return 1;
	}else{
		/* Queue Full: dropping. */
		free(vdb);
		tbf->dropped++;
		return 0;
	}
}

/* Dequeue function. Interface is ready to send the packet.
 *
 */
int tbf_dequeue(struct vde_iface *vif)
{
	struct tc_tbf *tbf = tbf_tcpriv(vif);
	struct timeval now;
	struct timeval when;
	gettimeofday(&now,NULL);
	when = add_t (tbf->last_out, tbf->delta);

	if (before(now, when))
		return 0;

	tbf->bytes_out = vif->q_out->len;
	ufifo_dequeue(vif);
	tbf->qlen -= tbf->bytes_out;
	while (tbf->bytes_out >= tbf->mtu){
		memcpy(&tbf->last_out,&now,sizeof(struct timeval));
		tbf->bytes_out -= tbf->mtu;
	}
	return 1;

}



/* Function to initialize the queue on the given interface.
 */
int tbf_init(struct vde_iface *vif, char *args)
{
	struct tc_tbf *tbf=(struct tc_tbf *)malloc(sizeof(struct tc_tbf));
	int arglen = strlen(args) - 1;
	uint32_t latency=0;
	char *rate;	
	if ((arglen < 5) || strncmp(args,"rate",4))
		goto fail;
	args=index(args,' ');
	if(args) *(args++)=(char)0;
	rate=args;
	if(!args || sscanf(args, "%lu",&(tbf->rate)) < 1)
		goto fail;
	args=index(args,' ');
	if(args) *(args++)=(char)0;
	if(index(rate,'K')) tbf->rate *=1000;
	else if(index(rate,'M')) tbf->rate *=1000000;
	if(tbf->rate < 5000)
		goto fail;
	tbf->rate = (tbf->rate >> 3); // from bits/s --> to Bytes/s

	if(strncmp(args,"latency",7)==0){
		args=index(args,' ');
		if(args) *(args++)=(char)0;
		if(!args || sscanf(args, "%lu",&latency) < 1)
			goto fail;
	} else if (strncmp(args,"limit",5)==0){
		args=index(args,' ');
		if(args) *(args++)=(char)0;
		if(!args || sscanf(args, "%lu",&(tbf->limit)) < 1)
			goto fail;



	} else goto fail;
	
	tbf->mtu=1000;
	
	if(latency){
		tbf->limit = (tbf->rate/tbf->mtu) * latency;
	}


	tbf->latency = latency;
	gettimeofday(&tbf->last_out,NULL);
	tbf->qlen = 0;
	tbf->dropped = 0;
	tbf->bytes_out = 0;
	tbf->delta.tv_sec = 0;
	tbf->delta.tv_usec = (1000000*tbf->mtu) / tbf->rate;
	vif->policy_name="tbf";
	memcpy(vif->tc_priv, tbf, sizeof(struct tc_tbf));
	return 1;

fail:
	return 0; 

}

char *tbf_tc_stats(struct vde_iface *vif)
{
	struct tc_tbf *tbf = tbf_tcpriv(vif);
	char *statistics=(char*)malloc(256);
	snprintf(statistics,255,"Shaping at Rate = %lu Bytes/s, bucket limit: %lu bytes. Overlimits: %lu packets. MTU=%lu", tbf->rate, tbf->limit, tbf->dropped, tbf->mtu);
	return statistics;
	
}


/*
 * Module symbol to load into module list.
 *
 */
struct routing_policy module_routing_policy=
{
	.name="tbf",
	.help="Packet Fifo queue\nUsage: tc set <dev> tbf rate <speed>[K|M] ( limit <bytes> | latency <ms> )\n",
	.policy_init = tbf_init,
	.enqueue = tbf_enqueue,
	.dequeue = tbf_dequeue,
	.tc_stats = tbf_tc_stats
};

static void
__attribute__ ((constructor))
init (void)
{
	fprintf(stderr,"Loading library: tbf.so\n");

}

	static void
	__attribute__ ((destructor))
fini (void)
{

}
