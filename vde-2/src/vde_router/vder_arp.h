#ifndef __VDER_ARP
#define __VDER_ARP
struct vder_arp_entry *vder_get_arp_entry(struct vder_iface *vif, uint32_t addr);
size_t vder_arp_query(struct vder_iface *oif, uint32_t tgt);
size_t vder_arp_reply(struct vder_iface *oif, struct vde_buff *vdb);
/* Parse an incoming arp packet */;
int vder_parse_arp(struct vder_iface *vif, struct vde_buff *vdb);
#endif

