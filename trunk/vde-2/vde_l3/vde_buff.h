/* VDE_ROUTER (C) 2007 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 * This is a tiny v4 router that can be used to link 
 * together two or more vde switches.
 *
 */

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <libvdeplug/libvdeplug.h>

#define PTYPE_IP 0x0800
#define PTYPE_ARP 0x0806

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

#if defined(VDE_FREEBSD) || defined(VDE_DARWIN)
struct iphdr
{
#if BYTE_ORDER == LITTLE_ENDIAN
	unsigned int ihl:4;
	unsigned int version:4;
#elif BYTE_ORDER == BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
};
#endif

struct 
__attribute__ ((__packed__)) 
vde_ethernet_header
{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t buftype;
};


struct 
__attribute__ ((__packed__)) 
vde_buff
{
	struct vde_buff *next;
//	struct vde_ethernet_header eth_h;
//	struct iphdr 	ip_h;
	char	*data;
	unsigned long	len;
};

struct 
vde_route
{
	struct vde_route *next;
	uint32_t network;
	uint32_t nm;
	uint32_t gw;
};


struct vde_iface
{
	uint8_t id; 	// Interface number

	VDECONN *vdec;		// vde connector
	uint8_t mac[6];	// 6-byte unicast mac address
	uint32_t ipaddr;	// 4-byte ip address
	uint32_t nm;		// netmask
	struct vde_buff *q_in;	
	struct vde_buff *q_out;	
	struct vde_iface *next;
	
};


struct 
arp_entry
{
	uint8_t mac[6];
	uint32_t ipaddr;
	struct arp_entry *next;
};



struct 
vde_router
{
	struct vde_iface *interfaces;
	struct vde_route *route_table;
	struct arp_entry *arp_table;
	struct vde_buff *arp_pending;
	uint32_t default_gw;
	
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



/* Arp */
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define ETHERNET_ADDRESS_SIZE 6
#define IP_ADDRESS_SIZE 4

#define ETH_BCAST "\xFF\xFF\xFF\xFF\xFF\xFF" 
#define HTYPE_ETH 1

struct
__attribute__ ((__packed__)) 
arp_header
{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hsize;
	uint8_t	psize;
	uint16_t opcode;
	uint8_t s_mac[6];
	uint32_t s_addr;
	uint8_t d_mac[6];
	uint32_t d_addr;	
};
