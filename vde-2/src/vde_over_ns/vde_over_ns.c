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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <pwd.h>
#include <sysexits.h>
#include <syslog.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "fun.h"
#include "pstack.h"
#include "dns.h"

#define DNSTIMEOUT 3
#define DRQLEN 10

#define BUFLEN 2000

static int nsid;

static void nstx_getpacket (void);
static struct nstx_senditem * alloc_senditem(void);
static void queue_senditem(const char *buf, int len);
static char *dequeue_senditem (int *len);
struct nstx_senditem * nstx_sendlist = NULL;
static char *vdesock = NULL;
static void nstxc_handle_reply(char *, int);
static int nstxc_send_packet(char *, int);

static void
usage(const char *prog, int code)
{
	fprintf (stderr, "usage: %s [-c DNSSERVER] [-s VDESOCK] [-i IP] [-D] <domainname>\n"
	    "Options:\n"
	    "\t-i IP (bind to port 53 on this IP only)\n"
	"\n"
	    "\t-D (call daemon(3) to detach from terminal)\n"
	"\n"
	    "\t-c DNSSERVER: Client mode. Tries to 'connect' to DNSSERVER.\n"
	    "\t\t(if this is not specified, server mode will be enabled by default.) \n"
	"\n"
	    "\t-s VDESOCKET: Attach to socket VDESOCKET \n"
	    "\t\t(if not specified, use stdin/stdout) \n"
	"\n"
	    "example:\n"
	    "\t%s -s /tmp/vde.ctl -c 1.2.3.4 tun.vdevirtualnetwork.foo [Client mode]\n"
	    "\t%s -s /var/vde-master-switch.ctl tun.vdevirtualnetwork.foo [Server mode]\n", prog, prog, prog);
	exit(code);
}

int main (int argc, char *argv[]) {
   signed char	 ch;
   const char *dir = NULL;
   in_addr_t	 bindto = INADDR_ANY;
   uid_t	 uid = 0;
   int		 daemonize = 0;
   int		 logmask = LOG_UPTO(LOG_INFO);
   char *clientmode_serveraddress=NULL;
   struct nstxmsg *msg;
   
   nsid = time(NULL);

   while ((ch = getopt(argc, argv, "Dh:i:s:c:")) != -1) {
	switch(ch) {
	case 'i':
		bindto = inet_addr(optarg);
		if (bindto == INADDR_NONE) {
			fprintf(stderr, "`%s' is not an IP-address\n",
			    optarg);
			exit(EX_USAGE);
		}
		break;
	case 'D':
		daemonize = 1;
		break;
	case 'g':
		logmask = LOG_UPTO(LOG_DEBUG);
		break;
	case 's':
		vdesock = strdup(optarg);	
		break;
	case 'h':
		usage(argv[0], 0);	/* no return */
	case 'c':
		clientmode_serveraddress = strdup(optarg);
		break;
	default:
		usage(argv[0], EX_USAGE);	/* no return */
	}
   }

   if (argc - optind < 1)
	usage(argv[0], EX_USAGE);

   dns_setsuffix(argv[optind]);
    
	
   if (uid && setuid(uid)) {
	syslog(LOG_ERR, "Can't setuid to %ld: %m", (long)uid);
	exit(EX_NOPERM);
   }
   if (daemonize && daemon(0, 0)) {
	syslog(LOG_ERR, "Can't become a daemon: %m");
	exit(EX_OSERR);
   }

   if (clientmode_serveraddress!=NULL){
	fprintf(stderr,"Client Mode\n");

	qsettimeout(10);
	open_ns(clientmode_serveraddress);
	init_vdesock(vdesock);

	for (;;) {
	    msg = nstx_select(1);
	    if (msg) {
	       if (msg->src == FROMNS) {
		  nstxc_handle_reply (msg->data, msg->len);
	       } else if (msg->src == FROMTUN) {
		  nstxc_send_packet (msg->data, msg->len);
	       }
	    }
	    timeoutqueue(NULL);
	    while (queuelen() < DRQLEN)
	      nstxc_send_packet (NULL, 0);
	  }

	  return 0;

   } else {
	fprintf(stderr,"Server Mode\n");
	  open_ns_bind(bindto);
	   init_vdesock(vdesock);
   
	if (dir) {
		/* Open the log-socket now (with LOG_NDELAY) before chroot-ing */
		openlog(argv[0], LOG_PERROR|LOG_PID|LOG_CONS|LOG_NDELAY, LOG_DAEMON);
		if (chroot(dir)) {
			syslog(LOG_ERR, "Can't chroot to %s: %m", dir);
			exit(EXIT_FAILURE); /* Too many possible causes */
		}
	   } else
		openlog(argv[0], LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	   setlogmask(logmask);
		
		while (1)
		nstx_getpacket();
   
		exit(0);
   }
}

struct nstx_senditem * nstx_get_senditem(void) {
   struct nstx_senditem *ptr = nstx_sendlist;
   
   if (!nstx_sendlist)
     return NULL;
   
   ptr = nstx_sendlist;
   nstx_sendlist = nstx_sendlist->next;
   
   return ptr;
}

static void do_timeout (struct nstxqueue *q)
{
   struct dnspkt *pkt;
   int len;
   char *buf;
   
   pkt = dns_alloc();
   dns_setid(pkt, q->id);
   dns_settype(pkt, DNS_RESPONSE);
   dns_addanswer(pkt, "\xb4\x00\x00\x00", 4, dns_addquery(pkt, q->name));
   buf = (char*)dns_constructpacket (pkt, &len);
   sendns(buf, len, &q->peer);
   free(buf);
}  

void nstx_getpacket (void) {
   int len, link;
   const char *name, *buf, *data;
   struct nstxmsg *msg;
   struct nstxqueue *qitem;
   struct dnspkt *pkt;

   msg = nstx_select(1);
   
   if (msg) {
     if (msg->src == FROMNS) {
	pkt = dns_extractpkt((unsigned char*)msg->data, msg->len);
	if (pkt)
	  {
	     name = dns_getquerydata(pkt);
	     if (name)
	       {
		  syslog(LOG_DEBUG, "getpacket: asked for name `%s'",
			name);
		  queueitem(pkt->id, name, &msg->peer);
		  if ((data = dns_fqdn2data(name)) &&
		      (buf = nstx_decode((unsigned char*)data, &len)))
		    {
		       nstx_handlepacket(buf, len, &send_vde);
		    }
	       }
	     dns_free(pkt);
	  }
     } else if (msg->src == FROMTUN)
	  queue_senditem(msg->data, msg->len);
   }
   
   while (queuelen()) {
      if (!nstx_sendlist)
	break;
      qitem = dequeueitem(-1);
      pkt = dns_alloc();
      dns_setid(pkt, qitem->id);
      dns_settype(pkt, DNS_RESPONSE);
      link = dns_addquery(pkt, qitem->name);
      len = dns_getfreespace(pkt, DNS_RESPONSE);
      buf = dequeue_senditem(&len);
      dns_addanswer(pkt, buf, len, link);
      buf = (char*)dns_constructpacket(pkt, &len);
      sendns(buf, len, &qitem->peer);
   }
   timeoutqueue(do_timeout);
}



static struct nstx_senditem * alloc_senditem(void) {
   struct nstx_senditem *ptr = nstx_sendlist;

   if (!nstx_sendlist) {
      ptr = nstx_sendlist = malloc(sizeof(struct nstx_senditem));
   } else {
      while (ptr->next)
	ptr = ptr->next;
      ptr->next = malloc(sizeof(struct nstx_senditem));
      ptr = ptr->next;
   }

   memset(ptr, 0, sizeof(struct nstx_senditem));
   
   return ptr;
}

static void
queue_senditem(const char *buf, int len) {
   static int id = 0;
   struct nstx_senditem *item;
   
   item = alloc_senditem();
   item->data = malloc(len);
   memcpy(item->data, buf, len);
   item->len = len;
   item->id = ++id;
}

static char *
dequeue_senditem (int *len) {
   static char *buf;
   struct nstx_senditem *item = nstx_sendlist;
   struct nstxhdr *nh;
   int remain, dlen;
   
   remain = item->len - item->offset;
   dlen = *len - sizeof(struct nstxhdr);
   if (dlen > remain)
     dlen = remain;
   *len = dlen + sizeof(struct nstxhdr);
   buf = realloc(buf, *len);
   nh = (struct nstxhdr *)buf;
   memset(nh, 0, sizeof(struct nstxhdr));
   memcpy(buf+sizeof(struct nstxhdr), item->data + item->offset, dlen);
   nh->magic = NSTX_MAGIC;
   nh->seq = item->seq++;
   nh->id = item->id;
   item->offset += dlen;
   if (item->offset == item->len) {
      nh->flags = NSTX_LF;
      nstx_sendlist = item->next;
      free(item->data);
      free(item);
   }
   
   return buf;
}

static void nstxc_handle_reply (char * reply, int len) {
   struct dnspkt *pkt;
   const char *data;
   int datalen;
   
   pkt = dns_extractpkt ((unsigned char*)reply, len);
   if (!pkt)
     return;
   while ((data = dns_getanswerdata(pkt, &datalen))) {
      data = (char*)txt2data((unsigned char*)data, &datalen);
      nstx_handlepacket (data, datalen, &send_vde);
   }
   dequeueitem(pkt->id);
   dns_free(pkt);
}
  
static int nstxc_send_packet (char *data, int datalen) {
  static int id = -1;

  char *p;
  struct nstxhdr nh;
  struct dnspkt *pkt;
  int l;

  if (id < 0)
    id = time(NULL);
        
  nh.magic = NSTX_MAGIC;
  nh.seq = 0;
  nh.id = id++;
  nh.flags = 0;

  do {
    pkt = dns_alloc();
    dns_settype(pkt, DNS_QUERY);
    dns_setid(pkt, nsid);
    
    l = dns_getfreespace(pkt, DNS_QUERY);
    if (l <= 0) {
       printf("Fatal: no free space in dns-packet?!\n");
       exit(1);
    }
    p = malloc(l);
    l -= sizeof(nh);
    if (l > datalen) {
       l = datalen;
       nh.flags = NSTX_LF;
    }
    memcpy (p, (char*)&nh, sizeof(nh));
    if (data)
       memcpy (p + sizeof(nh), data, l);
    data += l;
    datalen -= l;
    
    dns_addquery(pkt, dns_data2fqdn(nstx_encode((unsigned char*)p, sizeof(nh)+l)));
    free(p);
    p = (char*)dns_constructpacket(pkt, &l);
    sendns(p, l, NULL);
    free(p);

    queueid(nsid);
    nsid++;
    nh.seq++;
  } while (datalen);

  return 0;
}
