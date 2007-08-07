/* VDE_ROUTER (C) 2007 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 * This is a tiny v4 router that can be used to link 
 * together two or more vde switches.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/poll.h>
#ifndef HAVE_POLL
#include <utils/poll.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <config.h>
#include <libvdeplug/libvdeplug.h>
#include "vde_buff.h"

#include <vde.h>
#include <dlfcn.h>

#define MAXCMD 255
#define DEBUG 0

#if defined(VDE_FREEBSD) || defined(VDE_DARWIN)
#define ICMP_DEST_UNREACH 3
#define ICMP_PROT_UNREACH 2
#endif

/*
 * The main structure. Contains: interfaces, routing table,
 * arp pending, etc.
 */
struct vde_router VDEROUTER; 



/* This is the default routing policy ( Unlimited fifo )
 *
 *
 */
int ufifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif)
{
	struct vde_buff *qo = vif->q_out;
	if (qo == NULL){
		vif->q_out=vdb;
		return;
	}
	while (qo->next!=NULL){
		qo=qo->next;
	}
	qo->next = vdb;
	return 1;
}

int ufifo_dequeue(struct vde_iface *vif){
	struct vde_buff *vdb_out=vif->q_out;
	raw_send(vif,vdb_out);
	vif->q_out=vdb_out->next;
	return (vif->q_out?1:0);
}

int ufifo_init(struct vde_iface *vif, char *args)
{
	vif->policy_name = "ufifo";
	return (strlen(args) == 0);
}

char *nostats(struct vde_iface *vif)
{
	return "No Statistics Available.";
}


struct routing_policy unlimited_fifo_routing_policy ={
	.name = "ufifo",
	.help = "Unlimited FIFO (Default)\nUsage: tc set <dev> ufifo\n",
	.enqueue = ufifo_enqueue,
	.dequeue = ufifo_dequeue,
	.tc_stats = nostats,
	.policy_init = ufifo_init
};


inline struct vde_ethernet_header *ethhead(struct vde_buff *vdb)
{
	return (struct vde_ethernet_header*)(vdb->data);
}

inline struct iphdr *iphead(struct vde_buff *vdb)
{
	return (struct iphdr*)(vdb->data + 14);
}

inline void *payload(struct vde_buff *vdb)
{
	return (uint8_t*)(vdb->data + 14 + sizeof(struct iphdr));
}

void *
tcpriv(struct vde_iface *vi)
{
	return (void *)(vi->tc_priv);
}

void policy_register(struct routing_policy *r)
{
	struct routing_policy *p = VDEROUTER.modlist;
	if(p==NULL){
		VDEROUTER.modlist = r;
		return;
	}
	while (p->next!=NULL){
		p=p->next;
	}
	r->next=NULL;
	p->next=r;
}

struct routing_policy *getpolicy(char *name)
{
	struct routing_policy *p = VDEROUTER.modlist;
	struct routing_policy *new;
	void *di;
	char libname[300],libname2[300],libname3[300];
	snprintf(libname,255,"%s.so",name);
	snprintf(libname2,255,"/usr/lib/vde2/vde_l3/%s.so",name);
	snprintf(libname3,255,"/usr/local/lib/vde2/vde_l3/%s.so",name);

	while (p){
		if (!strncmp(name,p->name,255))
			return p;
		p=p->next;
	}
	

	di = dlopen(libname,RTLD_LAZY);
	if (di == NULL)
		di = dlopen(libname2,RTLD_LAZY);
	if (di == NULL)
		di = dlopen(libname3,RTLD_LAZY);

	if (di == NULL){
		fprintf(stderr,"Error loading module %s: %s\n",libname,dlerror());
		return NULL;
	}else{
		new = (struct routing_policy *) dlsym(di,"module_routing_policy");
		if(new!=NULL){
			policy_register(new);
			return new;
		}else{
			fprintf(stderr,"Error registering module %s: %s\n",libname,dlerror());
			return NULL;
		}

	}	
}


void set_interface_policy (struct vde_iface *vif, struct routing_policy *rp)
{
	vif->enqueue = rp->enqueue;
	vif->dequeue = rp->dequeue;

	if (rp->tc_stats)
		vif->tc_stats = rp->tc_stats;
	else
		vif->tc_stats = nostats;

	vif->policy_init = rp->policy_init;

}


static const int mgmtmode=0700;
static int max_total_sockets=0;

static char *progname;


/* Small utility functions, to talk to humans.
 */
static char *ip2ascii(uint32_t ip){
	char *res = calloc(1,16);
	snprintf(res,16,"%u.%u.%u.%u",((ip>>24)&0xFF),((ip>>16)&0xFF),((ip>>8)&0xFF),(ip&0xFF));
	return res;
}

uint8_t *ip2mac(uint32_t ip)
{
	uint8_t *ret =(uint8_t *) malloc(6);
	uint32_t bigendian_ip = htonl(ip);
	*ret = 0;
	*(ret+1) = 0xAA;
	memcpy(ret+2,&bigendian_ip,4); 
	return ret;
}


static char *mac2ascii(uint8_t *mac){
	char *res = calloc(1,18);
	snprintf(res,18,"%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]); 
	return res;
}


/*
 * Get an interface from its id
 */
static struct vde_iface *get_interface(int id){
	struct vde_iface *ifc = VDEROUTER.interfaces;
	while(ifc){
		if(ifc->id == id)
			return ifc;
		ifc = ifc->next;
	}
	return NULL;
}



void usage(char *p)
{
	fprintf(stderr,"Usage: %s [-G default_gw] -v vde_sock1:ipaddess1/netmask1 [-v ...] [-v vde_sockN:ipaddessN/netmaskN]\n",p);
	fprintf(stderr,"          [-r network/netmask:gateway ] [-r ...] \n");
	
	fprintf(stderr,"Options:\n");
	fprintf(stderr,"-v VDESOCK:ADDRESS/NETMASK adds a network interface\n" \
		       "\twith address ADDRESS and netmask NETMASK. \n" \
		       "\tThe interface is connected to the vde socket VDESOCK.\n" \
		       "\t(At least one '-v' argument is required.)\n" \
		       "\n");
			
	fprintf(stderr,"-r ADDRESS/NETMASK:GATEWAY adds a static route to the network\n" \
		       "\tADDRESS with netmask NETMASK, through the gateway GATEWAY. \n" \
		       "\n");
	fprintf(stderr,"-G ADDRESS sets the router default gateway to ADDRESS.\n" \
		       "\n");

	
	exit(1);
}


/* physically copy a vde_buff
 */
struct vde_buff *buff_clone( struct vde_buff *orig)
{
	struct vde_buff *clone = (struct vde_buff *)calloc(1,sizeof(struct vde_buff));
	memcpy (clone,orig,sizeof(struct vde_buff));
	clone->data = (char *)calloc(1,orig->len);
	memcpy(clone->data,orig->data,orig->len);
	return clone;
}

/** 
 * Send a packet directly using the ethernet
 */
size_t raw_send(struct vde_iface *of,struct vde_buff *vdb)
{
#if(DEBUG)
	fprintf(stderr,"Sending a %luB packet. VDECONN@%p. Protocol = %d through iface %d.\n",vdb->len,&(of->vdec),ntohs(*((uint16_t *)(vdb->data+12))),of->id);
#endif
	return vde_send(of->vdec,vdb->data,vdb->len,0);
}


int ip_input(struct vde_buff *vdb);
int ip_output(struct vde_buff *vdb, uint32_t dst, uint8_t protocol);
size_t arp_query(struct vde_iface *oif, uint32_t tgt);
struct vde_iface *is_neightbor(uint32_t addr);


/* ip output wrapper
 */
int ip_output_ready(struct vde_buff *vdb){
	struct iphdr *iph = iphead(vdb);
	return ip_output(vdb,ntohl(iph->daddr), iph->protocol);
}

/* List utilities
 *
 *
 */
static struct vde_iface *add_iface(struct vde_iface *new, struct vde_iface *list)
{
	if(list==NULL)
		return new;
	
	list->next=add_iface(new,list->next);
	return list;
}

static struct vde_route *add_route(struct vde_route *new, struct vde_route *list)
{
	if(list==NULL)
		return new;
	
	list->next=add_route(new,list->next);
	return list;
}

static struct arp_entry *add_arp_entry(struct arp_entry *new, struct arp_entry *list)
{
	if(list==NULL)
		return new;
	
	list->next=add_arp_entry(new,list->next);
	return list;
}


/* Dequeue all pending packets that were
 * waiting for arp IP/MAC association.
 */
static void dequeue_pending(uint32_t addr)
{
	struct vde_buff *pq = VDEROUTER.arp_pending;
	struct vde_buff *tmp;
	struct iphdr *h=iphead(pq);
	if(ntohs(h->daddr) == addr){
		ip_output(pq, addr, h->protocol);
		VDEROUTER.arp_pending = pq->next;
	}
	while(pq->next){
		h=iphead(pq->next);
		if (h->daddr == addr) {
			ip_output(pq->next,addr,h->protocol);
			tmp=pq->next;	
			pq->next = tmp->next;
			//free(tmp);
		}
		pq=pq->next;
	}
}

/*
 * Get an arp entry from its ip.
 */
static struct arp_entry *get_arp_entry(uint32_t ipaddr)
{
	struct arp_entry *a=VDEROUTER.arp_table;
	while (a){
		if (a->ipaddr == ipaddr)
			return a;
		a = a->next;
	}
	return NULL;
}


/* Prepare a vde_buff to be sent through a local interface
 */
int neightbor_send(struct vde_iface *to, struct vde_buff *vdb) 
{
	struct arp_entry *ae;
	struct vde_ethernet_header *he;
	struct iphdr *iph = iphead(vdb);
	int packets_in = 0;
	ae = get_arp_entry(iph->daddr);	
	he=ethhead(vdb);
	if(ae){
		memcpy(he->src,to->mac, 6);
		memcpy(he->dst,ae->mac, 6);
		packets_in = to->enqueue(vdb,to);
		
	}else{	
		memset(he->src,0,6);
//		VDEROUTER.arp_pending=enqueue(vdb,VDEROUTER.arp_pending);
		arp_query(to, ntohl(iph->daddr));	
	}
	return packets_in;
}

/* Prepare a vde_buff to be sent through a gateway 
 */
int gateway_send(struct vde_buff *vdb, uint32_t gw)
{
	struct arp_entry *ae;
	struct vde_ethernet_header *he;
	struct vde_iface *to = is_neightbor(gw);
	int packets_in = 0;
	ae = get_arp_entry(htonl(gw));	
	he=ethhead(vdb);
	if(ae){
		memcpy(he->src,to->mac, 6);
		memcpy(he->dst,ae->mac, 6);
		packets_in = to->enqueue(vdb,to);
		
	}else{	
		memset(he->dst, 0, 6);
//		VDEROUTER.arp_pending=enqueue(vdb,VDEROUTER.arp_pending);
		arp_query(to, gw);	
	}

	return packets_in;
}

/* 
 * Swap src/dst mac addresses at given mem addresses
 */
static void swap_macaddr(uint8_t addr1[], uint8_t addr2[])
{
	uint8_t tmp[6];
	memcpy(tmp,addr1,6);
	memcpy(addr1,addr2,6);
	memcpy(addr2,tmp,6);
}

/* 
 * Swap src/dst ip addresses at given mem addresses
 */
static void swap_ipaddr(uint32_t *addr1, uint32_t *addr2)
{
	uint32_t tmp;
	memcpy(&tmp,addr1,4);
	memcpy(addr1,addr2,4);
	memcpy(addr2,&tmp,4);
}


/*****
 * Allocate a new vde_buff packet of given size
 */
static struct vde_buff *vdebuff_alloc(size_t size)
{
	struct vde_buff *ret;
	struct vde_ethernet_header *veh;


	ret=(struct vde_buff *)calloc(1,sizeof(struct vde_buff));
//	fprintf(stderr,"ALLOCATING %lu Bytes of memory: ",size);
	ret->data=(char *)calloc(1,size+1);
	if(ret==NULL || ret->data==NULL){
		perror("Out of Memory.\n");
		exit(1);
	}
//	fprintf(stderr,"Done.\n",size);
	veh=ethhead(ret);
	// Set default packet type (IP)
	veh->buftype = htons(PTYPE_IP);
	ret->len = size;
	ret->next = NULL;
	return ret;
}

/***
 * Gets interface's mac address in a new array
 */
static inline char *macaddr(struct vde_iface *vif)
{
	char *mac=(char*)calloc(1,ETHERNET_ADDRESS_SIZE);
	memcpy(mac,vif->mac,6);
	return mac;
}



size_t vde_router_receive(struct vde_iface i)
{

	return 0;
}


/* RFC 826 */
int is_arp_pending(struct vde_iface *of, uint8_t *mac){return 0;}





/**
 * Prepare and send an arp query
 */
size_t arp_query(struct vde_iface *oif, uint32_t tgt)
{
	struct vde_ethernet_header *vdeh;
	struct arp_header *ah;
	struct vde_buff *vdb;

	/* Allocate 60B buffer for ARP request */
	vdb = vdebuff_alloc(60);

	/* populate eth header */
	vdeh = ethhead(vdb);
	memcpy(vdeh->dst, ETH_BCAST, 6);
	memcpy(vdeh->src, oif->mac ,6);
	vdeh->buftype = htons(PTYPE_ARP);
	
	/* build arp payload */
	ah =(struct arp_header *)iphead(vdb);
	ah->htype = htons(HTYPE_ETH);
	ah->ptype = htons(PTYPE_IP);
	ah->hsize = ETHERNET_ADDRESS_SIZE;
	ah->psize = IP_ADDRESS_SIZE;
	ah->opcode = htons(ARP_REQUEST);
	memcpy(ah->s_mac, oif->mac,6);
	ah->s_addr = htonl(oif->ipaddr); 
	memset(ah->d_mac,0,6);
	ah->d_addr = htonl(tgt);
	
	return(raw_send(oif,vdb));
	
}

/**
 * Reply to given arp request, if needed
 */
size_t arp_reply(struct vde_iface *oif, struct vde_buff *vdb)
{
	struct vde_ethernet_header *vdeh;
	struct arp_header *ah;
	vdeh=ethhead(vdb);
	swap_macaddr(vdeh->src,vdeh->dst);
	memcpy(vdeh->src,oif->mac,6);
	ah =(struct arp_header *)iphead(vdb);
	ah->opcode = htons(ARP_REPLY);
	swap_macaddr(ah->s_mac, ah->d_mac);
        memcpy(ah->s_mac, oif->mac,6);
	swap_ipaddr(&(ah->s_addr), &(ah->d_addr));

	return(raw_send(oif,vdb));
}



/* Internet Protocol */

/* get the interface struct from its address
 */
struct vde_iface *get_iface_by_ipaddr(uint32_t addr)
{
	struct vde_iface *vif = VDEROUTER.interfaces;
	while(vif){
		if(vif->ipaddr == addr)
			return vif;
		vif = vif->next;
	}
	return NULL;
}

/*
 * Gets the interface through which we should be able to reach 
 * the given ip address. If the destination is not a neighbor, 
 * returns a NULL pointer.
 */
struct vde_iface *is_neightbor(uint32_t addr)
{
	struct vde_iface *vif = VDEROUTER.interfaces;
	while(vif){
		if((vif->ipaddr&vif->nm) == (addr&vif->nm))
			return vif;
		vif = vif->next;
	}
	return NULL;
}



/**
 * Returns the ip address of the gateway for this destination.
 * If more than one route matches, the route with the stricter 
 * netmask is chosen.
 */
uint32_t get_gateway(uint32_t addr)
{
	struct vde_route *vdr = VDEROUTER.route_table;
	uint32_t res = 0;
	uint32_t max_netmask = 0;
	while(vdr){
		if((vdr->network & vdr->nm) == (addr & vdr->nm) && vdr->nm > max_netmask){
			res = vdr->gw;
			max_netmask = vdr->nm;
		}
		vdr = vdr->next;
	}
	if(!res)
		return VDEROUTER.default_gw;
	return res;
}

/* Parse an incoming arp packet */
int parse_arp(struct vde_buff *vdb)
{	
	struct arp_header *ah; 
	struct vde_iface *vif;
	struct arp_entry *ae=(struct arp_entry*)malloc(sizeof(struct arp_entry));;
	ah = (struct arp_header *)iphead(vdb);
	vif = get_iface_by_ipaddr(ntohl(ah->d_addr));
	if(!vif)
		return -1;
	memcpy(ae->mac,ah->s_mac,6);
	ae->ipaddr=ah->s_addr;
	
	VDEROUTER.arp_table = add_arp_entry(ae,VDEROUTER.arp_table);
	switch(ntohs(ah->opcode)){
	case ARP_REQUEST:
		arp_reply(vif, vdb);
		return 0;
	case ARP_REPLY:
		if(is_arp_pending(vif,ah->s_mac)){
			dequeue_pending(ntohl(ah->s_addr));
			return 0;
		}
		break;
	}
	return -1;
}

/*
 *
 *
 * Wrapper for neightbor/gateway send
 *
 * */
int ip_send(struct vde_buff *vdb)
{
	struct vde_iface *oif;
	struct iphdr *iph=iphead(vdb);
	uint32_t gateway;
	oif = is_neightbor(ntohl(iph->daddr));
	if (oif!=NULL){
		return neightbor_send(oif,vdb);
	}
	gateway = get_gateway(ntohl(iph->daddr));
	if(gateway)
		return gateway_send(vdb,gateway);
	else 
		return -1;
}

/*
 * Forward the ip packet to next hop. TTL is decreased,
 * checksum is set again for coherence, and TTL overdue
 * packets are not forwarded.
 */
int ip_forward(struct vde_buff *vdb){
	struct iphdr *iph=iphead(vdb);
	iph->ttl--;
	iph->check++;
	if(iph->ttl < 1)
		return -1;
	else 
		return ip_send(vdb);
}

/** 
 * Get a IP  packet
 */
int parse_ip(struct vde_buff *vdb)
{
	struct vde_ethernet_header *eh;
	struct iphdr *iph=iphead(vdb);
	struct arp_entry *ae;
	eh=ethhead(vdb);

	if(!get_arp_entry(iph->saddr)){
		ae=(struct arp_entry*)malloc(sizeof(struct arp_entry));;
		memcpy(ae->mac,eh->src,6);
		ae->ipaddr = iph->saddr;		
		VDEROUTER.arp_table = add_arp_entry(ae,VDEROUTER.arp_table);
	}
	if (get_iface_by_ipaddr(ntohl(iph->daddr))){
		return ip_input(vdb);
	}else{
		return ip_forward(vdb);
	}
}

/**
 * Calculate checksum of a given string
 */
uint16_t checksum(uint8_t *buf, int len)
{
	uint32_t sum = 0, carry=0;
	int i=0;
	for(i=0; i<len; i++){
		if (i%2){	
			sum+=buf[i];
		}else{
			sum+=( buf[i] << 8);
		}
	}
	carry = (sum&0xFFFF0000) >>16;
	sum = (sum&0x0000FFFF);
	return (uint16_t) ~(sum + carry)  ;
}

/**
 * Calculate ip-header checksum. it's a wrapper for checksum();
 */
uint16_t ip_checksum(struct iphdr *iph)
{
	iph->check = 0U;
	return checksum((uint8_t*)iph,sizeof(struct iphdr));
}

#define DEFAULT_TTL 64

/**
 * Layer 4 protocols should call this to transmit.
 */
int ip_output(struct vde_buff *vdb, uint32_t dst, uint8_t protocol)
{
	struct iphdr *iph=iphead(vdb);
	struct vde_iface *oif;
	memset(iph,0x45,1);	
	iph->tos = 0;
	iph->frag_off=htons(0x4000); // Don't fragment.
	iph->tot_len = htons(vdb->len - sizeof(struct vde_ethernet_header));
	iph->id = 0;
	iph->protocol = protocol;
	iph->ttl = DEFAULT_TTL;
	iph->check = htons(ip_checksum(iph));
	
	oif = is_neightbor(dst);
	if (!oif)
		oif=is_neightbor(get_gateway(dst));

	if(!oif){
#if DEBUG
		fprintf(stderr, "Cannot determine the route to %08x",dst);
#endif
		return -1;
	}

	
	iph->saddr = htonl(oif->ipaddr);
	iph->daddr = htonl(dst);
	iph->check = htons(ip_checksum(iph));
	return ip_send(vdb);
}

/** 
 * Send a ICMP_PROTOCOL_UNREACHABLE if so.
 *
 */
static int service_unreachable(struct vde_buff *buf_in)
{
	struct iphdr *iph_in;
	struct icmp *ich;
	struct vde_buff *vdb;
	static uint16_t ident=0;
	

	vdb=vdebuff_alloc(sizeof(struct vde_ethernet_header) +
		sizeof(struct iphdr) + 8);

	ich=(struct icmp *)payload(vdb);
	ich->icmp_type = ICMP_DEST_UNREACH;
	ich->icmp_code = ICMP_PROT_UNREACH;
	ich->icmp_hun.ih_idseq.icd_id = ident++;
	ich->icmp_hun.ih_idseq.icd_seq = 0;
	if(ident == 0xFFFF)
		ident = 0;
	ich->icmp_cksum = 0;
	ich->icmp_cksum = htons(checksum(payload(vdb), vdb->len - sizeof(struct iphdr) - 14));
	
	iph_in = iphead(buf_in);
	return ip_output(vdb,ntohl(iph_in->saddr),PROTO_ICMP); 	

}

/* Parse an incoming icmp packet
 */
int parse_icmp(struct vde_buff *vdb)
{
	struct icmp *ich;
	struct iphdr *iph;
	ich = (struct icmp *) payload(vdb);
	iph = iphead(vdb);
	if (ich->icmp_type == ICMP_ECHO){
		swap_ipaddr(&iph->saddr,&iph->daddr);
		ich->icmp_type = ICMP_ECHOREPLY;
		ich->icmp_cksum = 0;
		ich->icmp_cksum = htons(checksum(payload(vdb), vdb->len - 34));
		iph->check = htons(ip_checksum(iph));
	}
		
	ip_output_ready(vdb);
	return 1;
		
}


// Returns if the ip is unicast
static uint32_t inline unicast_ip(uint32_t ip){
	if(ip&0xE0000000)
		return 0;
	else
		return ip;
}


uint32_t ascii2ip(char *c){
	uint8_t *z=(uint8_t *)malloc(4);
	if(!index(c,'.'))
		return 0;
	if(sscanf(c,"%hu.%hu.%hu.%hu",z,z+1,z+2,z+3) < 0)
		return 0;
	return ntohl(*((uint32_t *)z));
}

//return >0 for valid netmasks.
uint32_t valid_nm(uint32_t nm)
{
	int i=31;
	uint32_t valid=0;
	for (i=31; i>=0; i--){
		valid+=(1<<i);
		if(nm == valid)
			return nm;
	}
	return 0;
}

uint32_t ascii2nm(char *c){
	uint32_t res=ascii2ip(c);
	int nmval=0,i=31;
	if(!res){
		if (sscanf(c,"%d",&nmval)<0){
			return 0;
		}else{
			while(nmval>0 && nmval<32 && (i >= (32 - nmval)))
				res+=(1<<i--);
		}
	}
	return valid_nm(res);
}

//check if mac address is multicast
 
static int is_multicast_mac(uint8_t *mac)
{
	if((mac[0]&0x01) && (mac[2]&0x5E))
		return 1;
	else return 0;
}

static void printoutc(int fd, const char *format, ...)
{
	va_list arg;
	char outbuf[MAXCMD+1];

	va_start (arg, format);
	vsnprintf(outbuf,MAXCMD,format,arg);
	strcat(outbuf,"\n");
	write(fd,outbuf,strlen(outbuf));
}

static int showinfo(int fd,char *s)
{
	return -1;
}

static int help(int fd,char *s)
{
	printoutc(fd, "help      					Display this inline help");
	printoutc(fd, "ifconfig [veN [ADDRESS [netmask NETMASK]]]   	Display virtual ethernet options/configure virtual ethernet N");
	printoutc(fd, "route list					Print out the routing table");
	printoutc(fd, "route net ADDRESS/NETMASK gw GATEWAY     	Add static route");
	printoutc(fd, "route default gw GATEWAY     			Add default route");
	printoutc(fd, "tc ls     					Show each interface routing policy");
	printoutc(fd, "tc set DEV POLICY ARGS     			Change interface routing policy");
	printoutc(fd, "shutdown:  					shut the channel down");
	printoutc(fd, "logout:    					log out from this mgmt session");
	return 0;
}


static int route(int fd,char *s)
{
	int arglen=strlen(s);
	struct vde_iface *pi;
	struct vde_route *pr;
	s[arglen]='\0';
	if(arglen==1){
		goto routecmdfail;
	}

	//Route list
	if(arglen == 5 && strncmp(s,"list",4)==0){
		printoutc(fd,"Destination\tGateway\t\tGenmask\t\tIface");
		pi = VDEROUTER.interfaces;
		while(pi){
			printoutc(fd,"%s\t%s\t\t%s\t\tve%d",ip2ascii(pi->ipaddr&pi->nm),ip2ascii(0),ip2ascii(pi->nm),pi->id);
			pi=pi->next;
		}
		pr = VDEROUTER.route_table;
		while(pr){
			pi=is_neightbor(pr->gw);
			if(pi)
				printoutc(fd,"%s\t%s\t\t%s\t\tve%d",ip2ascii(pr->network&pr->nm),ip2ascii(pr->gw),ip2ascii(pr->nm),pi->id);
			pr=pr->next;
		}
		pi=is_neightbor(VDEROUTER.default_gw);
		if(VDEROUTER.default_gw)
			printoutc(fd,"%s\t\t%s\t\t%s\t\tve%d",ip2ascii(0),ip2ascii(VDEROUTER.default_gw),ip2ascii(0),pi->id);
	}
	//Route default
	if(strncmp(s,"default gw ",11)==0){
		VDEROUTER.default_gw = unicast_ip(ascii2ip(s+11));
		if(!VDEROUTER.default_gw){
			printoutc(fd,"Invalid gateway.");
			goto routecmdfail;
		}
		printoutc(fd,"Default route changed to %s", ip2ascii(VDEROUTER.default_gw));
		return 0;
	}
	//Route change/add
	if(strncmp(s,"net ",4)==0){
		char *addr,*nm,*gw;
		struct vde_route *new = malloc (sizeof(struct vde_route));
		addr=s+4;
		if(!addr)
			goto routecmdfail;
		nm=index(addr,'/');
		if(!nm)
			goto routecmdfail;
		*(nm++)=0;
		gw=index(nm,':');
		if(!gw)
			goto routecmdfail;
		*(gw++)=0;
		new->network = unicast_ip(ascii2ip(addr));
		new->gw = unicast_ip(ascii2ip(gw));
		new->nm = ascii2nm(nm);

		pr = VDEROUTER.route_table;
		while(pr){
			if(new->network == pr->network && new->nm == pr->nm){
				pr->gw = new->gw;
				printoutc(fd,"Route successfully updated.");
				return 0;
			}
			pr = pr->next;
		}
		VDEROUTER.route_table = add_route(new, VDEROUTER.route_table);
		printoutc(fd,"Route successfully added.");
	}

	return 0;

routecmdfail:
	printoutc(fd, "'route' command usage:");
	printoutc(fd, "route list					Print out the routing table");
	printoutc(fd, "route net ADDRESS/NETMASK:GATEWAY     	Add/change static route");
	printoutc(fd, "route default gw GATEWAY     			Change default route");
		
}

#define IF_SHALL 0
#define IF_SH1 1
#define IF_CHIP 2
#define IF_CHALL 3


static int if_display(int fd, char *iface){
	struct vde_iface *pi;
	int showone = 0;
	int iface_id;
	if(strncmp(iface,"all",3)==0){
		pi=VDEROUTER.interfaces;
	}else{

		if(strncmp(iface,"ve",2)!=0){
			return -1;
		}
	
		iface_id = atoi(iface+2);
		pi = get_interface(iface_id);
		if(!pi){
			printoutc(fd, "Interface %s not found.",iface);
			return -1;
		}
		showone = 1;
	}
	while(pi){
		printoutc(fd, "ve%d\tLink encap: vde HWaddr %s",pi->id, mac2ascii(pi->mac));
		printoutc(fd, "\tinet addr:%s Netmask:%s", ip2ascii(pi->ipaddr),  ip2ascii(pi->nm));
		printoutc(fd,"");			
		if(showone) return 0;
		pi = pi->next;
	}
	return 0; 

}


static int ifconfig(int fd, char *s)
{
	int arglen=strlen(s)-1;
	struct vde_iface *pi;
	char *addr,*nmtag,*nm,*iface;
	int iface_id;
	int mode;
	uint32_t tmp;

	s[arglen]='\0';
	if(arglen == 0){
		if(if_display(fd,"all") < 0)
			goto cmdfail;
		else 
			return 0;
	}

	iface=s;
	addr=index(iface,' ');
	if(!addr){
		if(if_display(fd,iface)<0)
			goto cmdfail;
		else
			return 0;
	}
	
	*(addr++)=0;
	nmtag=index(addr,' ');
	if(!nmtag){
		mode=IF_CHIP;
	} else {
		*(nmtag++)=0;
		nm=index(nmtag,' ');
		if(!nm)
			goto cmdfail;
		*(nm++)=0;
		mode = IF_CHALL;
	}
	
	if(strncmp(iface,"ve",2)!=0){
		goto cmdfail;
	}
	
	iface_id = atoi(iface+2);
	pi = get_interface(iface_id);
	if(!pi){
		printoutc(fd, "Interface %s not found.",iface);
		goto cmdfail;
	}
	
	tmp = unicast_ip(ascii2ip(addr));
	if(!tmp)
		goto cmdfail;
	pi->ipaddr = tmp;	
	printoutc(fd, "IP address for %s successfully changed.",iface);
	if (mode == IF_CHALL){
		tmp = ascii2nm(nm);
		if(!tmp)
			goto cmdfail;
		pi->nm = tmp;
		printoutc(fd, "Netmask for %s successfully changed.",iface);
	}
	return 0;

cmdfail:
	printoutc(fd, "'ifconfig' command usage:");
	printoutc(fd, "ifconfig [veN [ADDRESS [netmask NETMASK]]]");
	return 0;	
}

static int traffic_control(int fd, char *s)
{
	int arglen=strlen(s)-1;
	struct vde_iface *pi;
	struct routing_policy *pp;
	char *iface, *policy, *args; 
	int ifnum;
	s[arglen]='\0';
	if(arglen==1){
		goto tccmdfail;
	}

	//tc ls
	if (arglen == 2 && strncmp(s,"ls",2)==0){
		pi = VDEROUTER.interfaces;
		while (pi){
			printoutc(fd, "vd%d: %s. %s", pi->id, pi->policy_name, pi->tc_stats(pi));
			pi=pi->next;
		}
	return 0;
	}
	
	//tc set 
	if (arglen > 4 && strncmp(s,"set",3) == 0){
		iface = s+4;
		policy=index(iface,' ');
		if(policy)
			*(policy++)=(char)0;
		if((strncmp(iface,"vd",2)) || (sscanf(iface+2,"%d",&ifnum)<1))
			goto tccmdfail;
		args=index(policy,' ');
		if(args){
			*(args++)=(char)0;
		}else{
			args="";
		}

		if(strlen(policy)<1)
			goto tccmdfail;
		
		// check interface existstence
		pi = VDEROUTER.interfaces;
		while (pi && pi->id != ifnum){
			pi=pi->next;
			if (!pi){
				printoutc(fd, "tc: Device vd%d not found.",ifnum);
				goto tccmdfail;
			}
		}
		// try to get module
		pp=getpolicy(policy);
		if(!pp){
			printoutc(fd, "Cannot load rp module %s.so",policy);
			goto tccmdfail;
		}else{
			set_interface_policy(pi, pp);
			if (!pi->policy_init(pi,args)){
				printoutc(fd, "%s: syntax error.\n%s",pp->name,pp->help);
				return 0;
			}
		
		}
		printoutc(fd, "vd%d: queuing discipline set to %s.", pi->id, pi->policy_name);
		return 0;	
	} 

tccmdfail:
	printoutc(fd, "'tc' command usage:");
	printoutc(fd, "tc ls					Print out the routing policy for each interface");
	printoutc(fd, "tc set <DEV> <policy> <arguments>     	Change routing policy");
	return -1;

}

static int logout(int fd,char *s)
{
	return -1;
}

static int doshutdown(int fd,char *s)
{
	exit(0);
}


#define WITHFD 0x80
static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
	unsigned char type;
} commandlist [] = {
	{"help", help, WITHFD},
	{"showinfo",showinfo, WITHFD},
	{"ifconfig",ifconfig, 0},
	{"route",route, 0},
	{"logout",logout, 0},
	{"shutdown",doshutdown, 0},
	{"tc",traffic_control,0}
};

#define NCL sizeof(commandlist)/sizeof(struct comlist)

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	while (*inbuf == ' ' || *inbuf == '\t' || *inbuf == '\n') inbuf++;
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL 
				&& strncmp(commandlist[i].tag,inbuf,strlen(commandlist[i].tag))!=0;
				i++)
			;
		if (i<NCL)
		{
			inbuf += strlen(commandlist[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (commandlist[i].type & WITHFD)
				printoutc(fd,"0000 DATA END WITH '.'");
			rv=commandlist[i].fun(fd,inbuf);
			if (commandlist[i].type & WITHFD)
				printoutc(fd,".");
		}
		return rv;
	}
	return rv;
}

static char header[]="\nVDE Layer 3 Switch  V.%s\n(C) D.Lacamera 2007 - GPLv2\n";
static char prompt[]="\nVDE-L3$ ";

static int mgmtcommand(int fd)
{
	char buf[MAXCMD+1];
	int n,rv;
	int outfd=fd;
	n = read(fd, buf, MAXCMD);
	if (n<0) {
		fprintf(stderr,"%s: read from mgmt %s",progname,strerror(errno));
		return 0;
	}
	else if (n==0) 
		return -1;
	else {
		if (fd==STDIN_FILENO)
			outfd=STDOUT_FILENO;
		buf[n]=0;
		rv=handle_cmd(outfd,buf);
		if (rv>=0)
			write(outfd,prompt,strlen(prompt));
		return rv;
	}
}

static int delmgmtconn(int i,struct pollfd *pfd,int nfds)
{
	if (i<nfds) {
		close(pfd[i].fd);
		if (pfd[i].fd == 0) /* close stdin implies exit */
			exit(0);
		memmove(pfd+i,pfd+i+1,sizeof (struct pollfd) * (nfds-i-1));
		nfds--;
	}
	return nfds;
}

static int openmgmt(char *mgmt)
{
	int mgmtconnfd;
	struct sockaddr_un sun;
	int one = 1;

	if((mgmtconnfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		fprintf(stderr,"%s: mgmt socket: %s",progname,strerror(errno));
		exit(1);
	}
	if(setsockopt(mgmtconnfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		fprintf(stderr,"%s: mgmt setsockopt: %s",progname,strerror(errno));
		exit(1);
	}
	if(fcntl(mgmtconnfd, F_SETFL, O_NONBLOCK) < 0){
		fprintf(stderr,"%s: Setting O_NONBLOCK on mgmt fd: %s",progname,strerror(errno));
		exit(1);
	}
	sun.sun_family = PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",mgmt);
	if(bind(mgmtconnfd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		fprintf(stderr,"%s: mgmt bind %s",progname,strerror(errno));
		exit(1);
	}
	chmod(sun.sun_path,mgmtmode);
	if(listen(mgmtconnfd, 15) < 0){
		fprintf(stderr,"%s: mgmt listen: %s",progname,strerror(errno));
		exit(1);
	}
	return mgmtconnfd;
}



static int newmgmtconn(int fd,struct pollfd *pfd,int nfds)
{
	int new;
	unsigned int len=sizeof(struct sockaddr_un);
	char buf[MAXCMD];
	struct sockaddr addr;
	new = accept(fd, &addr, &len);
	if(new < 0){
		fprintf(stderr,"%s: mgmt accept %s",progname,strerror(errno));
		return nfds;
	}
	if (nfds < max_total_sockets) {
		snprintf(buf,MAXCMD,header,PACKAGE_VERSION);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		return ++nfds;
	} else {
		fprintf(stderr,"%s: too many mgmt connections",progname);
		close (new);
		return nfds;
	}

}

int main(int argc, char *argv[])
{
	struct vde_iface *vif;
	struct pollfd *pfd, *pfdout;
	struct vde_buff *vdb_in, *vdb_out;
	struct vde_route *vr;
	int i,pr,pktin;
	int numif=0,npfd=0;
	struct vde_ethernet_header *eh;
	char *vdesock,*argp, *ipaddr, *nm, *gw, *mgmt=NULL;
	struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
	int option_index;
	struct routing_policy *rp;
	uint32_t rp_arg = 30;

	int mgmtindex;

	static struct option long_options[] = {
		{"help",0 , 0, 'h'},
		{"route",1 , 0, 'r'},
		{"defaultgw", 1, 0, 'G'},
		{"vdeplug", 1, 0, 'v'},
		{"mgmt", 1, 0, 'M'},
//TODO		{"daemon",0 , 0,'d'},
	};
	progname=strdup(argv[0]);
	VDEROUTER.route_table = NULL;
	VDEROUTER.arp_table = NULL;
	VDEROUTER.arp_pending = NULL;
	VDEROUTER.modlist = NULL;
	VDEROUTER.default_gw = 0U;
	policy_register(&unlimited_fifo_routing_policy);
	
	while(1) {
		int c;
		c = GETOPT_LONG (argc, argv, "hM:r:G:v:",
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage(progname);
				break;
			case 'M':
				mgmt=strdup(optarg);
				unlink(mgmt);
				break;
			case 'r':
				ipaddr=strdup(optarg);
				argp = index(ipaddr,'/');
				if(argp==NULL)
					usage(progname);
				*(argp++) = 0;
				gw = strdup(argp);
				argp = index(gw,':');
				if(argp==NULL)
					usage(progname);
				*(argp++) = 0;
				gw=strdup(argp);
				if (!gw)
					usage(progname);
				vr=(struct vde_route *)malloc(sizeof(struct vde_route));
				vr->network = unicast_ip(ascii2ip(ipaddr));
				vr->nm = ascii2nm(nm);
				vr->gw = unicast_ip(ascii2ip(gw));
				if(!vr->network){
					fprintf(stderr,"route: Cannot set network address to '%s'\n",ipaddr);
					usage(progname);
				}
				if(!vr->nm){
					fprintf(stderr,"route: Cannot set netmask to '%s'\n",nm);
					if(nm!=NULL && nm[0]=='0'){
						fprintf(stderr,"(Did you mean to set default gateway? then -G)\n",nm);
					}
					usage(progname);
				}
				if(!vr->gw){
					fprintf(stderr,"route: Cannot set gateway address to '%s'\n",gw);
					usage(progname);
				}
				VDEROUTER.route_table = add_route(vr, VDEROUTER.route_table);
				break;
				
			case 'G':
				VDEROUTER.default_gw=unicast_ip(ascii2ip(optarg));
				if(!VDEROUTER.default_gw){
					fprintf(stderr,"Cannot set default gateway address to '%s'\n",optarg);
					usage(progname);
				}
				break;
			case 'v':
				vdesock=strdup(optarg);
				argp = index(vdesock,':');
				if(argp==NULL)
					usage(progname);
				*(argp++) = 0;
				ipaddr = strdup(argp);
				argp = index(ipaddr,'/');
				if(argp==NULL)
					usage(progname);
				*(argp++) = 0;
				nm=strdup(argp);
				if (!nm)
					usage(progname);
				
				vif = (struct vde_iface *) malloc(sizeof (struct vde_iface));
				
				vif->vdec = vde_open(vdesock,"vde_L3",&open_args);
				if(!vif->vdec){
					fprintf(stderr,"vdeplug %s: %s\n",vdesock,strerror(errno));

				}	
				
				vif->ipaddr = unicast_ip(ascii2ip(ipaddr));
				if(!vif->ipaddr){
					fprintf(stderr,"vdeplug %s: Cannot set ip address to '%s'\n",vdesock,ipaddr);
					usage(progname);
				}
					
				vif->nm = ascii2nm(nm);
				if(!vif->nm){
					fprintf(stderr,"vdeplug %s: Cannot set netmask to '%s'\n",vdesock,nm);
					if(nm!=NULL && nm[0]=='0'){
						fprintf(stderr,"(Did you mean to set default gateway? then -G)\n",vdesock,nm);
					}
					usage(progname);
				}

				vif->id=numif++;	
				memcpy(vif->mac,ip2mac(vif->ipaddr),6);
				vif->q_in = NULL;
				vif->q_out = NULL;
				vif->next = NULL;
				rp = getpolicy("ufifo");
				if (!rp)
					fprintf(stderr,"Error getting policy ufifo: %s",dlerror());
				set_interface_policy(vif,rp);
				if(!vif->policy_init(vif,"")){
					fprintf(stderr,"Error setting default policy.\n");
					exit(1);
				}
				
				VDEROUTER.interfaces = add_iface(vif, VDEROUTER.interfaces);
				break;
				
			default:
				usage(progname);
				break;
		}
	}
	if (optind < argc)
		usage(progname);
	if (!numif)
		usage(progname);
	max_total_sockets = numif + 4;
	pfd = (struct pollfd *) malloc ((max_total_sockets) * sizeof(struct pollfd));
	vif = VDEROUTER.interfaces;
	i=0;
	while (vif) {
		pfd[i].fd = vde_datafd(vif->vdec);
     		pfd[i++].events=POLLIN | POLLHUP;
		vif = vif->next;
	}
	npfd = numif;
	if(mgmt != NULL) {
		int mgmtfd=openmgmt(mgmt);
		mgmtindex=npfd;
		pfd[mgmtindex].fd=mgmtfd;
		pfd[mgmtindex].events=POLLIN | POLLHUP;
		npfd++;
	}
	
for(;;)
  {	
	pr = poll(pfd,npfd,10);
	if (pr < 0){
		perror("poll");
		exit(2);
	}	
	pktin = 0;
	if(pr > 0){
		for(i=0,vif=VDEROUTER.interfaces; i<numif && vif!=NULL; i++, vif = vif->next){
			if(pfd[i].revents == POLLIN){
				pr--;
				vdb_in=vdebuff_alloc(1550);	
				if(!vdb_in)
					continue;
				vdb_in->len=vde_recv(vif->vdec,vdb_in->data,1548,0);
#if(DEBUG)
				fprintf(stderr,"Rcvd a %luB packet. VDECONN@%p. Protocol = %d.\n",vdb_in->len,&(vif->vdec),ntohs(*((uint16_t *)(vdb_in->data+12))));
#endif
				eh=ethhead(vdb_in);
				//Next line is a mac address filter.
				if((memcmp(eh->dst,vif->mac,6) == 0) || (is_multicast_mac(eh->dst)) && (memcmp(eh->src,vif->mac,6)!=0)){
					if(eh->buftype == ntohs(PTYPE_ARP)){
						pktin += parse_arp(vdb_in);
					}
					if(eh->buftype == ntohs(PTYPE_IP)){
						pktin += parse_ip(vdb_in);
					}
				}
			}
		}
		if (pr>0) { // if there are still events to handle (performance: packet switching first)
			int mgmtfdstart=numif;
			if (mgmtindex >= 0) {
				if (pfd[mgmtindex].revents != 0) {
					npfd=newmgmtconn(pfd[mgmtindex].fd,pfd,npfd);
					pr--;
				}
				mgmtfdstart=mgmtindex+1;
			}
			if (mgmtfdstart >= 0 && npfd > mgmtfdstart) {
				register int i;
				for (i=mgmtfdstart;i<npfd;i++) {
					if (pfd[i].revents & POLLHUP ||
							(pfd[i].revents & POLLIN && mgmtcommand(pfd[i].fd) < 0))
						npfd=delmgmtconn(i,pfd,npfd);
					if (pfd[i].revents) pr--;
				}
			} 
		}

	}// END POLLRET > 0 
	int outqueues = 0, outloop = 0;
	pfdout = (struct pollfd *) malloc ((max_total_sockets) * sizeof(struct pollfd));
	vif=VDEROUTER.interfaces;
	while (vif){ 
		pfdout[outqueues].fd = vde_datafd(vif->vdec);
		pfdout[outqueues++].events = POLLOUT;
		vif = vif->next;
	}

	vif=VDEROUTER.interfaces;
	if (poll(pfdout,outqueues,0) > 0){
		for(outloop = 0; outloop < outqueues; outloop++){
			if(pfdout[outloop].revents&POLLOUT && vif->q_out){
				vif->dequeue(vif);
			}
			vif=vif->next; 
		}
	}

	while(VDEROUTER.arp_pending){
		vdb_out=VDEROUTER.arp_pending;
		ip_output_ready(vdb_out);
		VDEROUTER.arp_pending=vdb_out->next;
		//free(vdb_out);
	}
  }	
}

/*
 * After being parsed, this is the point where packets
 * get to higher protocols
 */
int ip_input(struct vde_buff *vdb)
{

	struct iphdr *iph=iphead(vdb);
	if(*((uint8_t*)(iph)) != 0x45)
		return -1;
	switch(iph->protocol){
		case PROTO_ICMP:
			return parse_icmp(vdb);
		case PROTO_TCP:
		case PROTO_UDP:
		default:
			return service_unreachable(vdb);
	}
//	return -1; // not reached
}

