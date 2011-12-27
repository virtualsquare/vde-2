#include "vder_udp.h"
#include "vder_arp.h"
#include "vder_dhcpd.h"
#include <stdio.h>

static struct vder_dhcp_negotiation *Negotiation_list;
static struct vder_udp_socket *udpsock;
static struct vder_dhcpd_settings Settings;

static struct vder_dhcp_negotiation *
get_negotiation_by_xid(uint32_t xid)
{
	struct vder_dhcp_negotiation *cur = Negotiation_list;
	while (cur) {
		if (cur->xid == xid)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

static uint8_t dhcp_get_next_option(uint8_t *begin, uint8_t *data, int *len, uint8_t **nextopt)
{
	uint8_t *p;
	uint8_t type;
	uint8_t opt_len;

	if (!begin)
		p = *nextopt;
	else
		p = begin;

	type = *p;
	*nextopt = ++p;
	if ((type == DHCPOPT_END) || (type == DHCPOPT_PAD)) {
		memset(data, 0, *len);
		len = 0;
		return type;
	}
	opt_len = *p;
	p++;
	if (*len > opt_len)
		*len = opt_len;
	memcpy(data, p, *len);
	*nextopt = p + opt_len;
	return type;
}

static int is_options_valid(uint8_t *opt_buffer, int len)
{
	uint8_t *p = opt_buffer;
	while (len > 0) {
		if (*p == DHCPOPT_END)
			return 1;
		else if (*p == DHCPOPT_PAD) {
			p++;
			len--;
		} else {
			uint8_t opt_len;
			p++;
			len--;
			opt_len = *p;
			p += opt_len + 1;
			len -= opt_len;
		}
	}
	return 0;
}

#define DHCP_OFFER_SIZE 308
#define OPENDNS (htonl(0xd043dede))

static void dhcpd_make_reply(struct vder_dhcp_negotiation *dn, uint8_t reply_type)
{

	uint8_t buf_out[DHCP_OFFER_SIZE] = {0};
	struct dhcphdr *dh_out = (struct dhcphdr *) buf_out;
	uint32_t server_address = vder_get_right_localip(Settings.iface, Settings.pool_next);
	uint32_t netmask = vder_get_netmask(Settings.iface, server_address);
	uint32_t bcast = vder_get_broadcast(server_address, netmask);
	uint32_t dns_server = OPENDNS;

	int sent = 0;


	memcpy(dh_out->hwaddr, dn->hwaddr, HLEN_ETHER);
	dh_out->op = DHCP_OP_REPLY;
	dh_out->htype = HTYPE_ETHER;
	dh_out->hlen = HLEN_ETHER;
	dh_out->xid = dn->xid;
	dh_out->yiaddr = dn->arp->ipaddr;
	dh_out->siaddr = server_address;
	dh_out->dhcp_magic = DHCPD_MAGIC_COOKIE;

	/* Option: msg type, len 1 */
	dh_out->options[0] = DHCPOPT_MSGTYPE;
	dh_out->options[1] = 1;
	dh_out->options[2] = reply_type;

	/* Option: server id, len 4 */
	dh_out->options[3] = DHCPOPT_SERVERID;
	dh_out->options[4] = 4;
	memcpy(dh_out->options + 5, &server_address, 4);

	/* Option: Lease time, len 4 */
	dh_out->options[9] = DHCPOPT_LEASETIME;
	dh_out->options[10] = 4;
	memcpy(dh_out->options + 11, &Settings.lease_time, 4);

	/* Option: Netmask, len 4 */
	dh_out->options[15] = DHCPOPT_NETMASK;
	dh_out->options[16] = 4;
	memcpy(dh_out->options + 17, &netmask, 4);

	/* Option: Router, len 4 */
	dh_out->options[21] = DHCPOPT_ROUTER;
	dh_out->options[22] = 4;
	memcpy(dh_out->options + 23, &server_address, 4);

	/* Option: Broadcast, len 4 */
	dh_out->options[27] = DHCPOPT_BCAST;
	dh_out->options[28] = 4;
	memcpy(dh_out->options + 29, &bcast, 4);

	/* Option: DNS, len 4 */
	dh_out->options[33] = DHCPOPT_DNS;
	dh_out->options[34] = 4;
	memcpy(dh_out->options + 35, &dns_server, 4);

	dh_out->options[40] = DHCPOPT_END;

	sent = vder_udpsocket_sendto(udpsock, buf_out, DHCP_OFFER_SIZE, dh_out->yiaddr, DHCP_CLIENT_PORT);
	if (sent < 0) {
		perror("udp sendto");
	}
}

#define dhcpd_make_offer(x) dhcpd_make_reply(x, DHCP_MSG_OFFER)
#define dhcpd_make_ack(x) dhcpd_make_reply(x, DHCP_MSG_ACK)

#define ip_inrange(x) ((ntohl(x) >= ntohl(Settings.pool_start)) && (ntohl(x) <= ntohl(Settings.pool_end)))

static void dhcp_recv(uint8_t *buffer, int len)
{
	struct dhcphdr *dhdr = (struct dhcphdr *) buffer;
	struct vder_dhcp_negotiation *dn = get_negotiation_by_xid(dhdr->xid);
	uint8_t *nextopt, opt_data[20], opt_type;
	int opt_len = 20;


	if (!is_options_valid(dhdr->options, len - sizeof(struct dhcphdr)))
		return;



	if (!dn) {
		dn = malloc(sizeof(struct vder_dhcp_negotiation));
		memset(dn, 0, sizeof(struct vder_dhcp_negotiation));
		dn->xid = dhdr->xid;
		dn->state = DHCPSTATE_DISCOVER;
		memcpy(dn->hwaddr, dhdr->hwaddr, HLEN_ETHER);
		dn->next = Negotiation_list;
		Negotiation_list = dn;
		dn->arp = vder_arp_get_record_by_macaddr(Settings.iface, dn->hwaddr);
		if (!dn->arp) {
			dn->arp = malloc(sizeof(struct vder_arp_entry));
			if (!dn->arp)
				return;
			memcpy(dn->arp->macaddr, dn->hwaddr, HLEN_ETHER);
			dn->arp->ipaddr = Settings.pool_next;
			Settings.pool_next = htonl(ntohl(Settings.pool_next) + 1);
			vder_add_arp_entry(Settings.iface, dn->arp);
		}
	}

	if (!ip_inrange(dn->arp->ipaddr))
		return;


	opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
	while (opt_type != DHCPOPT_END) {
		/* parse interesting options here */
		if (opt_type == DHCPOPT_MSGTYPE) {

			/* server simple state machine */
			uint8_t msg_type = opt_data[0];
			if (msg_type == DHCP_MSG_DISCOVER) {
				dhcpd_make_offer(dn);
				dn->state = DHCPSTATE_OFFER;
				return;
			} else if (msg_type == DHCP_MSG_REQUEST) {
				dhcpd_make_ack(dn);
				return;
			}
		}
		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
}


void *dhcp_server_loop(void *ptr_settings)
{
	uint32_t from_ip;
	uint16_t from_port;

	unsigned char buffer[2000];
	int len;

	memcpy(&Settings, ptr_settings, sizeof(struct vder_dhcpd_settings));
	Settings.pool_next = Settings.pool_start;
	free(ptr_settings);


	if(!Settings.iface)
		return NULL;
	udpsock = vder_udpsocket_open(DHCPD_PORT);
	if (!udpsock) {
		return NULL;
	}

	while(1) {
		len = vder_udpsocket_recvfrom(udpsock, buffer, 2000, &from_ip, &from_port);
		if (len < 0) {
			perror("udp recv");
			return NULL;
		}
		if ((from_ip == 0) && (from_port == DHCP_CLIENT_PORT)) {
			dhcp_recv(buffer, len);
		}
	}
}
