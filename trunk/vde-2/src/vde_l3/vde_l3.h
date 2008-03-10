#ifndef _VDE_L3_H_
#define _VDE_L3_H__
/* pfifo.c */
int pfifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif);
int pfifo_dequeue(struct vde_iface *vif);
int pfifo_init(struct vde_iface *vif, char *args);
char *pfifo_tc_stats(struct vde_iface *vif);
/* bfifo.c */
int bfifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif);
int bfifo_dequeue(struct vde_iface *vif);
int bfifo_init(struct vde_iface *vif, char *args);
char *bfifo_tc_stats(struct vde_iface *vif);
/* tbf.c */
struct timeval add_t(struct timeval x, struct timeval y);
int tbf_enqueue(struct vde_buff *vdb, struct vde_iface *vif);
int tbf_dequeue(struct vde_iface *vif);
int tbf_init(struct vde_iface *vif, char *args);
char *tbf_tc_stats(struct vde_iface *vif);
/* vde_l3.c */
int ufifo_enqueue(struct vde_buff *vdb, struct vde_iface *vif);
int ufifo_dequeue(struct vde_iface *vif);
int ufifo_init(struct vde_iface *vif, char *args);
char *nostats(struct vde_iface *vif);
void *tcpriv(struct vde_iface *vi);
struct routing_policy *getpolicy(char *name);
void set_interface_policy(struct vde_iface *vif, struct routing_policy *rp);
uint8_t *ip2mac(uint32_t ip);
void usage(char *p);
struct vde_buff *buff_clone(struct vde_buff *orig);
int ip_output_ready(struct vde_buff *vdb);
int neightbor_send(struct vde_iface *to, struct vde_buff *vdb);
int gateway_send(struct vde_buff *vdb, uint32_t gw);
size_t vde_router_receive(struct vde_iface i);
int is_arp_pending(struct vde_iface *of, uint8_t *mac);
size_t arp_query(struct vde_iface *oif, uint32_t tgt);
size_t arp_reply(struct vde_iface *oif, struct vde_buff *vdb);
struct vde_iface *get_iface_by_ipaddr(uint32_t addr);
struct vde_iface *is_neightbor(uint32_t addr);
uint32_t get_gateway(uint32_t addr);
int parse_arp(struct vde_buff *vdb);
int ip_send(struct vde_buff *vdb);
int ip_forward(struct vde_buff *vdb);
int parse_ip(struct vde_buff *vdb);
uint16_t checksum(uint8_t *buf, int len);
uint16_t ip_checksum(struct iphdr *iph);
int ip_output(struct vde_buff *vdb, uint32_t dst, uint8_t protocol);
int parse_icmp(struct vde_buff *vdb);
uint32_t ascii2ip(char *c);
uint32_t valid_nm(uint32_t nm);
uint32_t ascii2nm(char *c);
int ip_input(struct vde_buff *vdb);
#endif /* _VDE_L3_H__ */
