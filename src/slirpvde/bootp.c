/*
 * QEMU BOOTP/DHCP server
 * 
 * Copyright (c) 2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "slirp.h"

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

/* XXX: only DHCP is supported */

#define NB_ADDR 16

#define START_ADDR 15

#define LEASE_TIME (120)

typedef struct {
    uint8_t allocated;
    uint8_t macaddr[6];
    int time;
} BOOTPClient;

BOOTPClient bootp_clients[NB_ADDR];

static const uint8_t rfc1533_cookie[] = { RFC1533_COOKIE };

#ifdef DEBUG
#define dprintf(fmt, args...) \
if (slirp_debug & DBG_CALL) { fprintf(dfd, fmt, ## args); fflush(dfd); }
#else
#define dprintf(fmt, args...)
#endif

static BOOTPClient *get_new_addr(struct in_addr *paddr)
{
    BOOTPClient *bc;
    int i;
    int now=time(NULL);

    for(i = 0; i < NB_ADDR; i++) {
        if (!bootp_clients[i].allocated)
            goto found;
    }
    for(i = 0; i < NB_ADDR; i++) {
        if (now-bootp_clients[i].time > 3*LEASE_TIME)
            goto found;
    }
    return NULL;
 found:
    bc = &bootp_clients[i];
    paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (i + START_ADDR));
    return bc;
}

static BOOTPClient *find_addr(struct in_addr *paddr, const uint8_t *macaddr)
{
    BOOTPClient *bc;
    int i;

    for(i = 0; i < NB_ADDR; i++) {
        if (!memcmp(macaddr, bootp_clients[i].macaddr, 6))
            goto found;
    }
    return NULL;
 found:
    bc = &bootp_clients[i];
    paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (i + START_ADDR));
    return bc;
}

static BOOTPClient *find_reqaddr(struct in_addr *paddr, struct in_addr *reqaddr, const uint8_t *macaddr)
{
    BOOTPClient *bc=NULL;
    int i;
    /*check the net prefix*/
    if ((ntohl(reqaddr->s_addr) & 0xffffff00) ==
		    (ntohl(special_addr.s_addr) & 0xffffff00)) {
	    i=(ntohl(reqaddr->s_addr) & 0xff) - START_ADDR;
	    if (i>=0 && i< NB_ADDR) {
		    bc = &bootp_clients[i];
		    if (bc->allocated &&
				    (memcmp(macaddr, bootp_clients[i].macaddr, 6)==0)) {
			    paddr->s_addr = reqaddr->s_addr;
			    return bc;
		    }
		    else
			    bc=NULL;
	    }
    }
    return bc;
}

static void dhcp_decode(const uint8_t *buf, int size,
                        int *pmsg_type, struct sockaddr_in *preqaddr)
{
    const uint8_t *p, *p_end;
    int len, tag;

    *pmsg_type = 0;    
    preqaddr->sin_addr.s_addr=htonl(0L);

    p = buf;
    p_end = buf + size;
    if (size < 5)
        return;
    if (memcmp(p, rfc1533_cookie, 4) != 0)
        return;
    p += 4;
    while (p < p_end) {
        tag = p[0];
        if (tag == RFC1533_PAD) {
            p++; 
        } else if (tag == RFC1533_END) {
            break;
        } else {
            p++;
            if (p >= p_end)
                break;
            len = *p++;
            dprintf("dhcp: tag=0x%02x len=%d\n", tag, len);

            switch(tag) {
            case RFC2132_MSG_TYPE:
                if (len >= 1)
                    *pmsg_type = p[0];
                break;
            case RFC2132_REQ_ADDR:
		if (len == 4) {
			memcpy(&(preqaddr->sin_addr),p,4);
		}
            default:
                break;
            }
            p += len;
        }
    }
}

static void bootp_reply(struct bootp_t *bp)
{
    BOOTPClient *bc;
    struct mbuf *m;
    struct bootp_t *rbp;
    struct sockaddr_in saddr, daddr, reqaddr;
    struct in_addr dns_addr;
    int dhcp_msg_type, val;
    uint8_t *q,replytype;
    uint8_t client_ethaddr[6];

    /* extract exact DHCP msg type */
    dhcp_decode(bp->bp_vend, DHCP_OPT_LEN, &dhcp_msg_type,&reqaddr);
    dprintf("bootp packet op=%d msgtype=%d reqaddr=%x\n", bp->bp_op, dhcp_msg_type,ntohl(reqaddr.sin_addr.s_addr));
    
    if (dhcp_msg_type != DHCPDISCOVER && 
        dhcp_msg_type != DHCPREQUEST)
        return;
    /* XXX: this is a hack to get the client mac address */
    memcpy(client_ethaddr, bp->bp_hwaddr, 6);
    
    if ((m = m_get()) == NULL)
        return;
    m->m_data += if_maxlinkhdr;
    rbp = (struct bootp_t *)m->m_data;
    m->m_data += sizeof(struct udpiphdr);
    memset(rbp, 0, sizeof(struct bootp_t));

    bc=NULL;
    daddr.sin_addr.s_addr=htonl(0L);
    if (dhcp_msg_type == DHCPREQUEST) {
	    if (reqaddr.sin_addr.s_addr != htonl(0L))
		    bc = find_reqaddr(&daddr.sin_addr, &reqaddr.sin_addr, bp->bp_hwaddr);
	    else 
		    bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
    }
    else if (dhcp_msg_type == DHCPDISCOVER) {
	    bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
	    if (!bc)
            	bc = get_new_addr(&daddr.sin_addr);
    }

    dprintf("offered addr=%08x\n", ntohl(daddr.sin_addr.s_addr));

    saddr.sin_addr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_ALIAS);
    saddr.sin_port = htons(BOOTP_SERVER);

    daddr.sin_port = htons(BOOTP_CLIENT);

    rbp->bp_op = BOOTP_REPLY;
    rbp->bp_xid = bp->bp_xid;
    rbp->bp_htype = 1;
    rbp->bp_hlen = 6;
    memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, 6);

    rbp->bp_yiaddr = daddr.sin_addr; /* IP address */
    rbp->bp_siaddr = saddr.sin_addr; /* IP address */

    q = rbp->bp_vend;
    memcpy(q, rfc1533_cookie, 4);
    q += 4;

    if (bc != NULL) {
        memcpy(bc->macaddr, client_ethaddr, 6);
    	bc->allocated = 1;
	bc->time = time(NULL);
    	replytype=(dhcp_msg_type == DHCPDISCOVER)?DHCPOFFER:DHCPACK;
    }
    else
	replytype=DHCPNACK;

    *q++ = RFC2132_MSG_TYPE;
    *q++ = 1;
    *q++ = replytype;
        
    if ((dhcp_msg_type == DHCPDISCOVER ||
        dhcp_msg_type == DHCPREQUEST) && replytype!=DHCPNACK) {
        *q++ = RFC2132_SRV_ID;
        *q++ = 4;
        memcpy(q, &saddr.sin_addr, 4);
        q += 4;

        *q++ = RFC1533_NETMASK;
        *q++ = 4;
        *q++ = 0xff;
        *q++ = 0xff;
        *q++ = 0xff;
        *q++ = 0x00;
        
        *q++ = RFC1533_GATEWAY;
        *q++ = 4;
        memcpy(q, &saddr.sin_addr, 4);
        q += 4;
        
        *q++ = RFC1533_DNS;
        *q++ = 4;
        dns_addr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_DNS);
        memcpy(q, &dns_addr, 4);
        q += 4;

        *q++ = RFC2132_LEASE_TIME;
        *q++ = 4;
        val = htonl(LEASE_TIME);
        memcpy(q, &val, 4);
        q += 4;
    }
    *q++ = RFC1533_END;
    
    //m->m_len = sizeof(struct bootp_t);
    m->m_len = q - (uint8_t *) (m->m_data);
		client_eth_register(client_ethaddr,&daddr.sin_addr);
    udp_output2(NULL, m, &saddr, &daddr, IPTOS_LOWDELAY);
}

void bootp_input(struct mbuf *m)
{
    struct bootp_t *bp = (struct bootp_t *)m->m_data;

    if (bp->bp_op == BOOTP_REQUEST) {
        bootp_reply(bp);
    }
}
