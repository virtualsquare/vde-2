/* ----------------------------------------------------------------------------
 *
    VDE_OVER_NS 
	(C) 2007 Daniele Lacamera

    Derived from:
    NSTX -- tunneling network-packets over DNS

     (C) 2000 by Florian Heinz and Julien Oster

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  -------------------------------------------------------------------------- */
#ifndef _NSTXDNS_H
#define _NSTXDNS_H

#define DNS_QUERY    0x01
#define DNS_RESPONSE 0x02

#define DNS_MAXPKT 512

struct rr
{
   char *data;
   int len;
   int link;
   
   struct rr *next;
};

struct dnspkt
{
   unsigned short id;
   int type;
   struct rr *query;
   struct rr *answer;
};

void dns_setsuffix (char *);

struct dnspkt *dns_alloc (void);
void dns_free (struct dnspkt *);

void dns_setid (struct dnspkt *, unsigned short);
void dns_settype (struct dnspkt *, int);
int dns_addquery (struct dnspkt *, const char *);
int dns_addanswer (struct dnspkt *, const char *, int, int);

int dns_getpktsize (const struct dnspkt *);
struct dnspkt *dns_extractpkt (const unsigned char *, int);
const char *dns_getquerydata (struct dnspkt *);
char *dns_getanswerdata (struct dnspkt *, int *);

const char *dns_fqdn2data (const char *);
const char *dns_data2fqdn (const char *);

const unsigned char *txt2data (const unsigned char *, int *);
unsigned char *dns_constructpacket (struct dnspkt *, int *);

int dns_getfreespace (const struct dnspkt *, int);

#endif /* _NSTXDNS_H */
