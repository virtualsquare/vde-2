/*   
 *   VIRTUALSQUARE wiki.virtualsquare.org
 *
 *   vtrill.c: vtrill support
 *   
 *   Copyright 2012 Renzo Davoli VirtualSquare University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, either version 2 
 *   of the License, or (at your option) any later version, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id: umview.c 974 2011-08-08 08:52:20Z rd235 $
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> /*ntoh conversion*/

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include "switch.h"
#include "hash.h"
#include "qtimer.h"
#include "port.h"
#include "fcntl.h"
#include "consmgmt.h"
#include "bitarray.h"

//#define malloc(X) ({void *rv; rv=malloc(X); printf("MALLOC L%d %d -> %p\n",__LINE__,(X),rv);rv;}) 
//#define free(X) ({printf("FREE L%d %p\n",__LINE__,(X));free(X);})
//#define ffree(X) ({printf("FAKEFREE L%d %p\n",__LINE__,(X)); 0;})
//#define realloc(X,Y) ({void *rv; rv=realloc((X),(Y)); printf("REALLOC L%d %p %d-> %p\n",__LINE__,(X),(Y),rv);rv;}) 
#define MAXTIME INT32_MAX

#ifdef VDE_VTRILL
#include <vtrill.h>
#define VTRILL_MAC_HEADER_LEN 18
//// #define DEBUGDELAYS
#ifdef DEBUGDELAYS
#define STDHELLOPERIOD 1
#define STDLSPEXPIRE 12
#define STDLSPRENEW 3
#define MINPATHDELAY 4
#else
#define STDHELLOPERIOD 6
#define STDLSPEXPIRE 1200
#define STDLSPRENEW 300
#define MINPATHDELAY 10
#endif
#define STDCSNPPERIOD 5
#define STDHOLDPERIOD 3*STDHELLOPERIOD
#define STDPRIO 0x80

#ifdef DEBUGOPT
#define DBGNODEPLUS (dl) 
#define DBGNODEMINUS (dl+1)
#define DBGNEIGHPLUS (dl+2) 
#define DBGNEIGHMINUS (dl+3) 
static struct dbgcl dl[]= {
	{"vtrill/node/+","new vtrill node",D_VTRILL_NODE|D_PLUS},
	{"vtrill/node/-","del vtrill node",D_VTRILL_NODE|D_MINUS},
	{"vtrill/neigh/+","new vtrill neighbor",D_VTRILL_NEIGH|D_PLUS},
	{"vtrill/neigh/-","del vtrill neighbor",D_VTRILL_NEIGH|D_MINUS},
};
#endif

/* NICKNAME */
unsigned char mynickname[2];
/* INFO FROM port.c */
static int numports;
static char vtrillvlan[2] = {0xff,0xff};
/* fast uint_16 -> index in vtrilltable mapping */
static uint16_t *nickmap;
/* my priority (to be a broadcast root) */
static unsigned char myprio=STDPRIO;
/* the set of active ports */
static bitarray portset;
/* Timing */
/* IIH packet period */
static int helloperiod=STDHELLOPERIOD;
/* hold time before stating a local node "reachable" */
static int holdperiod=STDHOLDPERIOD;
/* Validity of a lsp */
static int lspexpire=STDLSPEXPIRE;
/* time before lsp expiration to renew it */
static int lsprenew=STDLSPRENEW;
/* period for CSNP packets */
static int csnpperiod=STDCSNPPERIOD;
/* delay from a modification to minpath computation 
	 (to wait that the situation settles down) */
static int minpathdelay=MINPATHDELAY;
/* time when the next MINPATH is scheduled */
static time_t nextminpath = MAXTIME;

/* Timers: hello, lsp, and csnp */
static int vtrill_timerhello;
static int vtrill_timerlsp; /* starts minpath when needed */
static int vtrill_timercsnp;
struct vtrillnode;
/* bitmap of used vtrilltable elements */
static bitarray vtrilltable_ok;
/* vtrill node table */
static struct vtrillnode **vtrilltable;
/* indexes for dynamic allocation */
static long vtrilltablemax; /* max valid entry */
static long vtrilltablesize; /* # of preallocated elements */
static long vtrilltablefree=-1; /* head of the free list */

/* local lsp database: local reachability */
static struct lsplist *mylsps;
#define VTRILLTABLESTEP 16

static void vtrill_restart(void);
//static void setmynickname();
#define TRILL_PACKET_SIZE 1542
/* packet prototypes */
#define IIH_PDU 15
#define LSP_PDU 18
#define CSNP_PDU 24
#define PSNP_PDU 26
#define IIH_HDRLEN 19
#define LSP_HDRLEN 23
#define CSNP_HDRLEN 21
#define PSNP_HDRLEN 13
#define TLV_AREA 1
#define TLV_NEIGHBOR 6
#define TLV_PADDING 8
#define TLV_LSPENTRY 9
#define TLV_EXTREACH 22
#define TLV_HOSTNAME 137

/* IS-IS header */
static unsigned char isis_proto[]={
	0x01,0x80,0xc2,0x00,0x00,0x14, /*destination=all L1 */
	0x00,0x00,0x00,0x00,0x00,0x00, /*src*/
	0x81,0x00, 
	0x00,0x00, /* VLAN */
	0x22,0xf4, /* type = ISIS */
	0x83, /* Routing Protocol Discriminator */
	00, /* length */
	0x01,0x02,
	00, /* PDU type */
	0x01,0x00,0x00
};

/* packet formats */
#define ISIS_COMMON_FIELDS \
	struct ethheader header;\
  unsigned char vlan[2]; \
	unsigned char isistype[2]; \
	unsigned char rpd;\
	unsigned char hdrlen;\
	unsigned char vers;\
	unsigned char idlen;\
	unsigned char pdutype;\
	unsigned char pduvers;\
	unsigned char reserved;\
	unsigned char maxarea

struct isis {
	ISIS_COMMON_FIELDS;
} __attribute__((packed));

struct iih {
	ISIS_COMMON_FIELDS;
	unsigned char circuit;
	unsigned char nickname[2];
	unsigned char holdingtime[2];
	unsigned char pdulen[2];
	unsigned char prio;
	unsigned char designlanid[3];
	unsigned char tlvbuf[0];
}__attribute__((packed));

struct lsp {
	ISIS_COMMON_FIELDS;
	unsigned char pdulen[2];
	unsigned char remlifetime[2];
	unsigned char lspid[4];
	unsigned char seqno[4];
	unsigned char chksum[2];
	unsigned char flags;
	unsigned char tlvbuf[0];
}__attribute__((packed));

struct csnp {
	ISIS_COMMON_FIELDS;
	unsigned char pdulen[2];
	unsigned char sourcenick[3];
	unsigned char start_lspid[4];
	unsigned char end_lspid[4];
	unsigned char tlvbuf[0];
}__attribute__((packed));

struct psnp {
	ISIS_COMMON_FIELDS;
	unsigned char pdulen[2];
	unsigned char sourcenick[3];
	unsigned char tlvbuf[0];
}__attribute__((packed));

struct tlv {
	unsigned char type;
	unsigned char len;
	unsigned char data[0];
}__attribute__((packed));

#define VTSTAT_DOWN 0
#define VTSTAT_NEW 1
#define VTSTAT_INIT 2
#define VTSTAT_RUN 4
#define VTSTAT_REMOTE 0x10

#define NEIGH_FRESH 0x1
#define NEIGH_UP 0x2

/* IIH LAYER: list of local neighbor (per port) */
struct neighlist {
	unsigned char nickname[2];
	unsigned char mac[ETH_ALEN];
	unsigned char prio;
	time_t expiretime;
	time_t seenselftime;
	int flags;
	struct neighlist *next;
};

/* IIH layer: per port data */
#define PORTDATA_DESIGNATED 1
struct portdata {
	int flags;
	int metric;
	struct neighlist *neighbors;
};

/* list of lsp: used both for my lsps and for
	 the list of lsps of all the nodes */
struct lsplist {
	struct lsp *lsp;
	uint16_t len;
	time_t expiretime;
	struct lsplist *next;
};

/* NODE! */
#define VTRILLNODE_MODIFIED 1
#define VTRILLNODE_VISITED 2
#define VTRILLNODE_TVISITED 4
#define VTRILLNODE_DEPRECATED 8
struct vtrillnode {
	unsigned char flags;
	unsigned char prio;
	uint16_t refcount;
	uint16_t intnick;
	uint16_t maxhop;
	uint16_t nparents;
	uint16_t parents[NTREE];
	uint16_t parentadj[NTREE];
	unsigned char mac[ETH_ALEN];
	unsigned int distance;
	unsigned int treedist;
	int port;
	struct lsplist *lsps;
	uint16_t nadj;
	uint16_t *adjindex;
	uint16_t *adjmetric;
	bitarray tmpset;
	int usagecount;
	uint16_t nfirsthop;
	uint16_t *firsthop;
};

void vtrillsetnumports (int val)
{
	numports=val;
}

static void intinc4(unsigned char *seq)
{
	if (++seq[3]==0) {
		if (++seq[2]==0) {
			if (++seq[1]==0)
				++seq[0];
		}
	}
}

static void intdec4(unsigned char *seq)
{
	if (seq[3]--==0) {
		if (seq[2]--==0) {
			if (seq[1]--==0)
				seq[0]--;
		}
	}
}

static void setlen(int len, unsigned char *slen)
{
	slen[0] = len>>8;
	slen[1] = len;
}

/********************* GLUE TO PORT.C ********************/

static struct nextmultivtrill nexttree[NTREE];
static int tree_usagecount;

int unicast_vtrill_port(int integress, unsigned char *mac, int *ttl)
{
	struct vtrillnode *node;
	struct vtrillnode *nextnode;
	int selector;
	/* consistency check of egress switch nickname */
	if (integress == 0 || integress > 0xffc0)
		return -1;
	/* Is the nickname known? */
	if (nickmap[integress] == 0xffff)
		return -1;
	node=vtrilltable[nickmap[integress]];
	if (node == NULL)
		return -1;
	/* egress is known but unreachable */
	if (node->nfirsthop == 0)
		return -1;
	*ttl = node->maxhop;
	selector=((node->usagecount)++ % node->nfirsthop);
	nextnode=vtrilltable[node->firsthop[selector]];
	/* set the destination mac address to the next hop */
	memcpy(mac,nextnode->mac,ETH_ALEN);
	/* the packet must be forwarded to an active port */
	if (ba_check(portset,nextnode->port))
		return nextnode->port;
	else
		return -1;
}

struct nextmultivtrill *broadcast_vtrill(unsigned char *egress_tree)
{
	uint16_t tree=INTNICK(egress_tree);
	/* if the tree# has been already defined, multicast the packets
		 to the neighbors, otherwise choose a tree first */
	if (tree == 0xffff) {
		tree = (tree_usagecount++) % NTREE;
		egress_tree[0] = tree>>8; egress_tree[1]=tree;
	}
	return &nexttree[tree];
}

/********************* VTRILL table management *****************/

/* nick -> struct vtrillnode */ /* ext TODO */
static struct vtrillnode *getvtrillnode(unsigned char *nick)
{
	int intnick = INTNICK(nick);
	if (intnick == 0 || intnick > 0xffc0)
		return NULL;
	if (nickmap[intnick] == 0xffff)
		return NULL;
	/* assert(nickmap[intnick] < vtrilltablemax */
	return vtrilltable[nickmap[intnick]];
}

/* create a new trill node */
static struct vtrillnode *newvtrillnode(unsigned char *nick,unsigned char *mac)
{
	unsigned int intnick = (nick[0]<<8) + nick[1];
	int index;
	static struct vtrillnode *new;
	if (intnick == 0 || intnick > 0xffc0)
		return NULL;
	if (nickmap[intnick] != 0xffff)
		return NULL;
	if (vtrilltablefree >= 0) {
		index=vtrilltablefree;
		vtrilltablefree=(long)vtrilltable[vtrilltablefree];
	} else {
		index=vtrilltablemax++;
		if (index >= vtrilltablesize) {
			register long oldsize=vtrilltablesize;
			vtrilltablesize+=VTRILLTABLESTEP;
			vtrilltable=realloc(vtrilltable,vtrilltablesize*sizeof(void *));
			vtrilltable_ok=ba_realloc(vtrilltable_ok,oldsize,vtrilltablesize);
		}
	}
	DBGOUT(DBGNODEPLUS,"%04x", intnick);
	EVENTOUT(DBGNODEPLUS,  intnick);
	//printf("Malloc %d size %d %ld %ld %ld\n",index,sizeof(struct vtrillnode),vtrilltablefree,vtrilltablemax,vtrilltablesize);
	vtrilltable[index]=new=malloc(sizeof(struct vtrillnode));
	//printf("DONE %x %p\n",intnick,vtrilltable[index]);
	nickmap[intnick] = index;
	ba_set(vtrilltable_ok,index);
	new->flags=0;
	new->prio=0;
	new->refcount=0;
	new->maxhop=0;
	new->distance= INT_MAX;
	memcpy(new->mac,mac,ETH_ALEN);
	new->lsps=NULL;
	new->nparents=0;
	new->intnick=INTNICK(nick);
	new->port=0;
	new->nadj=0;
	new->adjindex=new->adjmetric=NULL;
	new->tmpset=NULL;
	new->usagecount=0;
	new->nfirsthop=0;
	new->firsthop=NULL;
	return new;
}

/* delete a lsp chain */
static void droplspfh(struct vtrillnode *node)
{
	struct lsplist *lsps;
	/* CLEAN OTHER FIELDS XXX */
	while((lsps=node->lsps) != NULL) {
		node->lsps=lsps->next;
		free(lsps->lsp);
		free(lsps);
	}
}

/* delete a vtrill node */
static void delvtrillnode(int index)
{
	struct vtrillnode *node=vtrilltable[index];
	int nadj;
	DBGOUT(DBGNODEMINUS,"%04x", node->intnick);
	EVENTOUT(DBGNODEMINUS,  node->intnick);
	ba_clr(vtrilltable_ok,index);
	//printf("DELETE NODE %x\n",node->intnick);
	if (! (node->flags & VTRILLNODE_DEPRECATED))
		nickmap[node->intnick]=0xffff;
	for (nadj=0; nadj<node->nadj; nadj++)
		vtrilltable[node->adjindex[nadj]]->refcount--;
	if (node->adjindex) free(node->adjindex);
	if (node->adjmetric) free(node->adjmetric);
	if (node->tmpset) free(node->tmpset);
	if (node->firsthop) free(node->firsthop);
	droplspfh(node);
	free(vtrilltable[index]);
	vtrilltable[index]=(void *)vtrilltablefree;
	vtrilltablefree=index;
}

/* deprecate a node (there is a node with the same nick and
   higher priority */
static void deprecatevtrillnode(struct vtrillnode *node)
{
	struct lsplist *lsp=node->lsps;
	nickmap[node->intnick]=0xffff;
	printf("DEPRECATED %04x MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",node->intnick,
			node->mac[0], node->mac[1], node->mac[2], node->mac[3], node->mac[4], node->mac[5]);
	node->flags |= (VTRILLNODE_MODIFIED | VTRILLNODE_DEPRECATED);
	while (lsp != NULL) {
		lsp->expiretime=0;
		lsp=lsp->next;
	}
}

/* tie-breaker: primary key: max prio, secondary key: min mac
	 this returns:
	 0 if mac coincide
	 >0 if first logically greater than the second
	 <0 otherwise */
static inline int tie_breaker(int prio1, unsigned char *mac1,
		        int prio2, unsigned char *mac2)
{
	int diff=memcmp(mac1, mac2, 6);
	int rv;
	if (diff==0)
		rv=0;
	else if (prio1 > prio2 ||
			((prio1 == prio2) && diff < 0))
		rv=1;
	else
	 rv= -1;
	/* printf("TIE_BREAKER %d %02x:%02x:%02x:%02x:%02x:%02x %d %02x:%02x:%02x:%02x:%02x:%02x -> %d\n",
			prio1, mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5],
			prio2, mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5], rv);*/
	return rv;
}

/********************* create/parse tlv ********************/

struct tlvdata {
	unsigned char *p;
	unsigned char *lasttlv;
	unsigned char *pos;
};

/* create a tlv sequence: start procedure */
void tlv_start(void *packet, unsigned char *tlv, struct tlvdata *tlvdata)
{
	tlvdata->p=packet;
	tlvdata->pos=tlv;
	tlvdata->lasttlv=NULL;
}

static inline int tlvlen(int type)
{
	int len;
	switch (type) {
		case TLV_PADDING: len = 1; break;
		case TLV_AREA:
		case TLV_NEIGHBOR: len = 2; break;
		case TLV_HOSTNAME:
		case TLV_EXTREACH: len = 7; break;
		case TLV_LSPENTRY: len = 12; break;
		default: errno=EINVAL; return -1;
	}
	return len;
}

/* "prepare" to add a tlv element at the end */
void tlv_append(struct tlvdata *tlvdata, int curlen)
{
	unsigned char *limit=(tlvdata->p)+curlen;
	while (tlvdata->pos < limit) {
		tlvdata->lasttlv = tlvdata->pos;
		tlvdata->pos += tlvdata->lasttlv[1]+2;
	}
	//printf("tlv_append %d %d\n",curlen,tlvdata->lasttlv-tlvdata->p);
}

/* add a tlv element:
	 if it has the same type of the last one and there is space within
	 the max 255 chars of a tlv, the value gets added in the same tlv */
int tlv_add(struct tlvdata *tlvdata, int type, ...) 
{
	int len;
	int newtlv = (tlvdata->lasttlv==NULL || tlvdata->lasttlv[0] != type);
	va_list ap;
	if ((len=tlvlen(type))<0)
		return -1;
	if (!newtlv && ((tlvdata->pos - tlvdata->lasttlv) + len) > 255)
		newtlv=1;
	if (((tlvdata->pos - tlvdata->p) + len + newtlv?2:0) > TRILL_PACKET_SIZE) {
		errno=ENOMEM;
		return -1;
	}
	if (newtlv) {
		tlvdata->lasttlv = tlvdata->pos;
		tlvdata->lasttlv[0] = type;
		tlvdata->lasttlv[1] = 0;
		tlvdata->pos += 2;
	}
	switch (type) {
		case TLV_AREA: tlvdata->pos[0]=1; tlvdata->pos[1]=0; break;
		case TLV_NEIGHBOR: {
												va_start(ap,type);
												memcpy(tlvdata->pos, va_arg(ap, char *), 2); /* nick */
												va_end(ap);
											}
									 break;
		case TLV_PADDING: tlvdata->pos[0]='x'; break;
		case TLV_LSPENTRY: {
												 va_start(ap,type);
												 int rem_lifetime=va_arg(ap, int);
												 tlvdata->pos[0]=rem_lifetime>>8;
												 tlvdata->pos[1]=rem_lifetime;
												 /* LSPID, nick + ext + frag */
												 /* + SEQ# and checksum (copied from LSP) */
												 memcpy(tlvdata->pos+2, va_arg(ap, char *), 10); 
												 va_end(ap);
											 }
									 break;
		case TLV_EXTREACH: {
												 va_start(ap,type);
												 memcpy(tlvdata->pos, va_arg(ap, char *), 2); /* nick */
												 tlvdata->pos[2]=va_arg(ap, int); /* ext */
												 int metric=va_arg(ap, int);
												 tlvdata->pos[3]=metric>>16;
												 tlvdata->pos[4]=metric>>8;
												 tlvdata->pos[5]=metric;
												 tlvdata->pos[6]=0; /* no subtlv */
												 va_end(ap);
											 }
									 break;
		case TLV_HOSTNAME: {
												 va_start(ap,type);
												 tlvdata->pos[0]=va_arg(ap, int); /* prio */
												 memcpy(tlvdata->pos+1,va_arg(ap, char *), 6); /* MAC addr */
												 va_end(ap);
											 }
									 break;
	}
	tlvdata->lasttlv[1] += len;
	tlvdata->pos += len;
	return 0;
}

/* terminate the tlv editing and get the final length of the packet */
int tlv_end(struct tlvdata *tlvdata)
{
	//printf("tlv_len=%p %p %d\n",tlvdata->pos,tlvdata->p,tlvdata->pos - tlvdata->p);
	return tlvdata->pos - tlvdata->p;
}

/* parse the tlv, the function fun gets called for each tlv value, 
	 "fun" has a variable sequence of arguments, depending upon the tlv type */
int tlv_parse(void *packet, int len, int tlvgsize, unsigned char *tlv, 
		int (fun)(int type, unsigned char *this, void *arg), void *arg)
{
	unsigned char *limit=((unsigned char *)packet)+len;
	if (tlv+tlvgsize < limit) limit=tlv+tlvgsize;
	while (tlv < limit) {
		int type=*tlv;
		int len=tlvlen(type);
		int tlvsize=tlv[1];
		tlv=tlv+2;
		while (len > 0 && tlvsize >= len) {
			int rv=fun(type, tlv, arg); 
			if (rv != 0)
				return rv;
			tlv+=len;
			tlvsize-=len;
		}
	}
	return 0;
}

/* delete the ext reachability #22 tlv for an unreachable node */
int tlv_del_extreach(void *packet, int len, unsigned char *tlv, 
		unsigned char *nickname, int ext)
{
	unsigned char *limit=((unsigned char *)packet)+len;
	unsigned char *found=NULL;
	unsigned char *tlvr=tlv;
	/* find the tlv */
	while (tlv < limit && !found) {
		int type=*tlv;
		int fieldlen=tlvlen(type);
		int tlvsize=tlv[1];
		if (type==TLV_EXTREACH) {
			found=tlv+2;
			while(found < tlv+tlvsize) {
				if (memcmp(nickname, found, 2) == 0 &&
						found[2] == ext) {
					//printf("FOUND!?!\n");
					break;
				}
				found += fieldlen;
			}
			if (found < tlv+tlvsize)
				break;
			found = NULL;
		}
		tlv+=2;
		tlv+=tlvsize;
	}
	//printf("found %p\n",found);
	/* if the tlv exists, swap it with the last one and shorten the packet */
	if (found) {
		unsigned char *lastextreach=NULL;
		unsigned char *lastextreachitem=NULL;
		int fieldlen;
		while (tlvr < limit) {
			int type=*tlvr;
			int tlvsize=tlvr[1];
			fieldlen=tlvlen(type);
			//printf("type %d\n",type);
			if (type==TLV_EXTREACH) {
				lastextreach=tlvr;
				lastextreachitem=tlvr+2;
				while(lastextreachitem < tlvr+tlvsize) {
					lastextreachitem += fieldlen;
				}
			}
			tlvr += 2;
			tlvr += tlvsize;
		}
		//printf("%p %p\n",lastextreach, lastextreachitem);
		fieldlen=tlvlen(TLV_EXTREACH);
		lastextreachitem -= fieldlen;
		//printf("1 %p %p\n",lastextreach, lastextreachitem);
		if (lastextreachitem != found)
			memcpy(found, lastextreachitem, fieldlen);
		//printf("2 %p %p\n",lastextreach, lastextreachitem);
		lastextreach[1] -= fieldlen;
		//printf("3 %p %p\n",lastextreach, lastextreachitem);
		if (lastextreach[1] == 0) {
			fieldlen += 2;
			//printf("mm %p %p %d\n",lastextreach, lastextreach+fieldlen,
					          //(limit-lastextreach) - fieldlen);
			memmove(lastextreach, lastextreach+fieldlen,
					(limit-lastextreach) - fieldlen);
			len -= fieldlen;
		} else {
			memmove(lastextreachitem, lastextreachitem+len, 
					(limit-lastextreachitem) - fieldlen);
			len -= fieldlen;
		}
	}
	//printf("RET len%d\n",len);
	return len;
}

/********************* Priority Queue support for Minimum Path computation ******************/

struct opq {
	unsigned int n;
	struct opqel *root;
};

struct opqel {
	struct opqdata {
		int distance;
		int index;
	} el;
	struct opqel *next[2];
};

/* add an element (distance, index) to the prio queue */
void opq_add(struct opq *q, int distance, int index)
{
	//printf("opq_add %d\n",index);
	unsigned int n;
	unsigned int r;
	unsigned int l;
	n = ++(q->n);
	/* reverse the bit representation ang get the log */
	for (r=l=0;n;l++,n>>=1)
		r = (r << 1) | (n&1);
	r>>=1;
	/* navigate the structure and keep track of the path
		 from the root to the new leaf */
	struct opqel **seq[l];
	for (n=1,seq[0]=&(q->root);n<l;n++,r>>=1)
		seq[n]=&((*seq[n-1])->next[r&1]);
	/* create the leaf */
	n--;
	*seq[n]=malloc(sizeof(struct opqel));
	(*seq[n])->next[0]=(*seq[n])->next[1]=NULL;
	/* force the heap condition returning back to the root */
	while(n>0) {
		if (distance < (*seq[n-1])->el.distance)
			(*seq[n])->el = (*seq[n-1])->el;
		else {
			/* this is the right position of the new insserted value
				 we can leave */
			(*seq[n])->el.distance = distance;
			(*seq[n])->el.index = index;
			return;
		}
		n--;
	}
	(*seq[n])->el.distance = distance;
	(*seq[n])->el.index = index;
}

/* get the minimum distance element. return its index */
int opq_get(struct opq *q)
{
	if (q->root) {
		int rv=q->root->el.index;
		struct opqdata oldel;
		struct opqel **pscan;
		struct opqel *scan;
		unsigned int n;
		unsigned int r;
		unsigned int l;
		n = (q->n)--;
		/* reverse the bit representation ang get the log */
		for (r=l=0;n;l++,n>>=1)
			r = (r << 1) | (n&1);
		r>>=1;
		/* navigate the structure */
		for (n=1,pscan=&(q->root);n<l;n++,r>>=1)
			pscan=&((*pscan)->next[r&1]);
		/* delete the last element and save its value */
		oldel=(*pscan)->el;
		free(*pscan);
		*pscan=NULL;
		/* migrate small element towards the root. */
		scan=q->root;
		while (scan != NULL) {
			if (scan->next[0]) {
				unsigned int index;
				/* find the smallest sibling */
				if (scan->next[1] == NULL ||
						scan->next[0]->el.distance < scan->next[1]->el.distance)
					index=0;
				else
					index=1;
				/* compare the element to the saved value */
				if (scan->next[index]->el.distance < oldel.distance)
				{
					scan->el=scan->next[index]->el;
					scan=scan->next[index];
				} else {
					/* got its new position, store it and leave */
					scan->el=oldel;
					break;
				}
			} else {
				/* the structure terminates here, save the value and leave */
				scan->el=oldel;
				break;
			}
		}
		//printf("opq_get %d\n",rv);
		return rv;
	} else
		return -1;
}

struct opq gpq;

/********************* Minimum Path/Broadcast trees ***************/

/* parse lsp to create the adjagency array of the connection graph */
static int lsp_parse(int type, unsigned char *tlvdata, void *arg)
{
	struct vtrillnode *node=arg;
	if (type == TLV_EXTREACH) {
		uint16_t intnick=(tlvdata[0]<<8)+tlvdata[1];
		/* sanity check */
		if (intnick > 0 && intnick < 0xffc0) {
			if (nickmap[intnick] != 0xffff) {
				int pos=node->nadj;
				//printf("%d %x %p\n",pos,intnick, node->adjindex);
				node->adjindex[pos]=nickmap[intnick]; 
				/* ext=tlvdata[2] not supported yet */
				node->adjmetric[pos]=(tlvdata[3]<<16)+(tlvdata[4]<<8)+tlvdata[5];
				/* Djkstra algorithm may fail on null metrics */
				if (node->adjmetric[pos]==0) node->adjmetric[pos]=1;
				(node->nadj)++;
			} else
				/* something is inconsistent: this tlb is naming an unknown nick,
					 this must be re-processed when new tlb are coming in */
				node->flags |= VTRILLNODE_MODIFIED;
		}
	}
	return 0;
}

/* count the number of adjacent nodes, to resize the adjacency array*/
static int lsp_countadj(int type, unsigned char *tlvdata, void *arg)
{
	int *n=arg;
	if (type == TLV_EXTREACH) 
		(*n)++;
	return 0;
}

/* schedule a minpath computation (after a minpathdelay time).
	 any change in connectivity creates a burst of messages.
	 minpathdelay is needed to wait that the situation settles down a bit
	 (it limits the possibility of repeated computations due to partial data
	 available) */
static inline void request_minpath(time_t now)
{
	if (nextminpath == MAXTIME)
		nextminpath = now + minpathdelay;
}

static uint16_t my_nadj;
static uint16_t *my_adjindex;

/* nickname + priority conversion into int values for min computation
   (broadcast tree roots and tie-breaker for paths of the same length */
static inline int nickvalue(struct vtrillnode *n)
{
	return (n)->intnick | (255 - (n)->prio)<<16;
}

/* search of broadcast tree computation roots */
static uint16_t rootindex[NTREE];
static int rootvalue[NTREE];
/* number of currently reachable nodes */
int nreachable;

static int treemaxttl(int index, int oldindex) {
	struct vtrillnode *node=vtrilltable[index];
	int hopcount=0;
	if (node->tmpset) {
		int i;
		for (i=0;i<node->nadj;i++) {
			uint16_t newindex=node->adjindex[i];
			int tmphopcount;
			if (ba_check(node->tmpset,i) && newindex!=oldindex) {
				//// printf("%x->%x ",node->intnick,vtrilltable[newindex]->intnick);
				tmphopcount=treemaxttl(newindex,index)+1;
				if (tmphopcount > hopcount) 
					hopcount=tmphopcount;
			}
		}
	}
	return hopcount;
}

/* this is the core of the link state algorithm.
	 this function computes:
	 -All minimum paths from the current node to all reachable nodes.
	 For each node it saves all the possible neighbor nodes that permit to
	 reach the destination along a minimal path (possible first hops
	 towards the destination node).

	 -NTREE broadcast trees: the roots are the first NTREE nodes having
	 max priority and, within nodes of the same priority, min nickname

	 -If the nodes have the same data they compute the same broadcast trees:
	 minpath trees from each root.

	 -this function computes the neighbor nodes for each tree and the distance of
	 the farer node */

static void minpath_computation(void)
{
	//// printf(">>>>>>>>>>>>>>>>>>>>>>>>> MINPATH <<<<<<<<<<<<<<<<<<\n");
	register int i;
	int tree;
	int do_it_again=0;
	/* UPDATE MODIFIED ADJACENCIES */
	/* convert the data from LSP packets in adjagency lists */
	for (i=0; i<vtrilltablemax; i++) {
		if (ba_check(vtrilltable_ok,i)) {
			struct vtrillnode *node=vtrilltable[i];
			node->distance = INT_MAX;
			if (node->flags & VTRILLNODE_MODIFIED) {
				struct lsplist *lsps=node->lsps;
				int nadj;
				for (nadj=0; nadj<node->nadj; nadj++)
					vtrilltable[node->adjindex[nadj]]->refcount--;
				nadj=0;
				////printf("MODIFIED %d index (%x)\n",i,node->intnick);
				node->flags &= ~VTRILLNODE_MODIFIED;
				while (lsps != NULL) {
					struct lsp *lsp=lsps->lsp;
					tlv_parse(lsp,lsps->len,
							(lsp->pdulen[0]<<8)+lsp->pdulen[1]-VTRILL_MAC_HEADER_LEN, lsp->tlvbuf,lsp_countadj,&nadj);
					lsps=lsps->next;
				}
				////printf("NADJ=%d\n",nadj);
				node->nadj=0;
				node->adjindex=realloc(node->adjindex, nadj*sizeof(uint16_t));
				node->adjmetric=realloc(node->adjmetric, nadj*sizeof(uint16_t));
				lsps=node->lsps;
				while (lsps != NULL) {
					struct lsp *lsp=lsps->lsp;
					tlv_parse(lsp,lsps->len,
							(lsp->pdulen[0]<<8)+lsp->pdulen[1]-VTRILL_MAC_HEADER_LEN, lsp->tlvbuf,lsp_parse,node);
					lsps=lsps->next;
				}
				for (nadj=0; nadj<node->nadj; nadj++)
					vtrilltable[node->adjindex[nadj]]->refcount++;
#if 0
				printf("TEST ADJ %x %d-> \n",node->intnick,node->nadj);
				int j;
				for (j=0; j<node->nadj; j++) {
					if (node->adjindex[j] == 0xffff)
						printf("ERRRRRRRROR! 0xffff\n");
				}
				for (j=0; j<node->nadj; j++) {
					printf("%d %p",node->adjindex[j],vtrilltable[node->adjindex[j]]);
					printf("%x ",vtrilltable[node->adjindex[j]]->intnick);
				}
				printf("\n");
#endif
			}
			node->flags &= ~VTRILLNODE_VISITED;
			node->maxhop=0;
		}
	}
	int myintnick = INTNICK(mynickname);
	int index = nickmap[myintnick];
	/* this should not happen, I am uncertain during nick renaming */
	//printf("MYSELF=%x %p\n",myintnick,vtrilltable[index]);
	if (index < 0 || vtrilltable[index] == NULL) {
		/* it is inconsistent, startup problem?
			 if it happens, try again later */
		request_minpath(qtime());
		return;
	}
	/* Starting data for multi min path */
	vtrilltable[index]->distance=0;
	vtrilltable[index]->tmpset=NULL;
	my_nadj=vtrilltable[index]->nadj;
	my_adjindex=vtrilltable[index]->adjindex;
	/* add myself to the prio queue and start multi min path */
	opq_add(&gpq, 0, index);
	while ((index=opq_get(&gpq)) >= 0) {
		struct vtrillnode *this = vtrilltable[index];
		//printf("Visiting %x, %d\n",this->intnick,index);
		if (! (this->flags & VTRILLNODE_VISITED)) {
			this->flags |= VTRILLNODE_VISITED;
			for (i=0; i<this->nadj; i++) {
				unsigned int testdistance = this->distance + this->adjmetric[i];
				int diff = testdistance - vtrilltable[this->adjindex[i]]->distance;
				/* if we have reached a deprecated the computation must be repeated */
				if (vtrilltable[this->adjindex[i]]->flags & VTRILLNODE_DEPRECATED) {
					this->flags |= VTRILLNODE_MODIFIED;
					//// printf("DO IT AGAIN!!!!!\n");
					nextminpath=qtime();
					do_it_again=1;
				}
				/*printf("testing adj %x %d < %d %d\n",vtrilltable[this->adjindex[i]]->intnick,testdistance,
						vtrilltable[this->adjindex[i]]->distance, diff);*/
				if (diff < 0) {
					/* this is a shorter path (update distance and inherit firsthop */
					vtrilltable[this->adjindex[i]]->distance=testdistance;
					vtrilltable[this->adjindex[i]]->maxhop=this->maxhop+1;
					if (vtrilltable[this->adjindex[i]]->tmpset == NULL)
						vtrilltable[this->adjindex[i]]->tmpset = ba_alloc(my_nadj);
					if (this->tmpset == NULL) 
						ba_set(vtrilltable[this->adjindex[i]]->tmpset, i);
					 else
						ba_copy(vtrilltable[this->adjindex[i]]->tmpset, this->tmpset, my_nadj);
					opq_add(&gpq,testdistance,this->adjindex[i]);
				} else if (diff==0) {
					/* this path has the same distance (merge firsthop)*/
					if (vtrilltable[this->adjindex[i]]->maxhop <= this->maxhop) 
						vtrilltable[this->adjindex[i]]->maxhop=this->maxhop+1;
					if (this->tmpset != NULL)
						ba_add(vtrilltable[this->adjindex[i]]->tmpset, this->tmpset, my_nadj);
				}
			}
		}
	}
	if (do_it_again)
		return;
	/* compute firsthop for all destination */
	nreachable=0;
	for (i=0; i<NTREE; i++)
		rootvalue[i]=INT_MAX;
	for (i=0; i<vtrilltablemax; i++) {
		if (ba_check(vtrilltable_ok,i)) {
			struct vtrillnode *node=vtrilltable[i];
			int j,value;
			node->treedist=INT_MAX;
			node->nparents=0;
			if (node->tmpset != NULL) {
				register int j,k;
				node->nfirsthop = ba_card(node->tmpset, my_nadj);
				node->firsthop = realloc(node->firsthop, node->nfirsthop * sizeof(uint16_t));
				j=0;
				ba_FORALL(node->tmpset,my_nadj,node->firsthop[j++]=my_adjindex[k],k);
#if 0
				printf ("to reach %x distance %d maxhop %d firsthop= ",node->intnick,node->distance,node->maxhop); 
				for (j=0; j<node->nfirsthop; j++) {
					printf("%x ", vtrilltable[node->firsthop[j]]->intnick);
				}
				printf("\n");
#endif
				free(node->tmpset);
				node->tmpset=NULL;
			} else {
				node->nfirsthop = 0;
				node->firsthop = realloc(node->firsthop, 0);
			}
			if (node->flags & VTRILLNODE_VISITED &&
					!(node->flags & VTRILLNODE_DEPRECATED)) {
				nreachable++;
				/* choose the roots (NTREE steps bubblesort) */
				value=nickvalue(node);
				if (value <= rootvalue[NTREE-1]) {
					for (j=NTREE-1; j>0 && value <= rootvalue[j-1]; j--) {
						rootvalue[j]=rootvalue[j-1];
						rootindex[j]=rootindex[j-1];
					}
					rootvalue[j]=value;
					rootindex[j]=i;
				}
				node->flags &= ~VTRILLNODE_TVISITED;
			} else if (node->refcount==0) 
				delvtrillnode(i); 
			/*else {
				if (node->flags & VTRILLNODE_DEPRECATED) {
					printf("SURVIVED !! %04x",node->intnick);
				}
			}*/
		}
	}
	for (i=nreachable; i<NTREE; i++) {
		rootvalue[i]=rootvalue[i-nreachable];
		rootindex[i]=rootindex[i-nreachable];
	}
#if 0
	printf("TREEROOTS (%d) ",nreachable);
	for (i=0; i<NTREE; i++)
		printf("%x ",vtrilltable[rootindex[i]]->intnick);
	printf("\n");
#endif
	/* broadcast tree computation */
	for (tree=0; tree<NTREE; tree++) {
		int index = rootindex[tree];
		vtrilltable[index]->treedist=0;
		vtrilltable[index]->tmpset=NULL;
		/* add gpq to the prio queue and start the minimization algorithm */
		opq_add(&gpq, 0, index);
		while ((index=opq_get(&gpq)) >= 0) {
			struct vtrillnode *this = vtrilltable[index];
			//printf("tree %d Visiting %x, %d\n",tree,this->intnick,index);
			this->tmpset=ba_alloc(this->nadj);
			if (! (this->flags & VTRILLNODE_TVISITED)) {
				this->flags |= VTRILLNODE_TVISITED;
				for (i=0; i<this->nadj; i++) {
					/* if adjindex[i] is the parent of "this" node: add the tree link */
					if (this->nparents &&
							this->adjindex[i] == this->parents[tree % this->nparents]) {
						ba_set(this->tmpset, i);
						break;
					}
				}
				/* if here i >= this->nadj it means that there is a non bidirectional
					 link */
				for (i=0; i<this->nadj; i++) {
					struct vtrillnode *child = vtrilltable[this->adjindex[i]];
					unsigned int testdistance = this->treedist + this->adjmetric[i];
					int diff = testdistance - child->treedist;
					/*printf("%x %x olddist %d newdist %d\n",this->intnick,child->intnick,
							child->treedist, testdistance);*/
					/* minimizing algorithm step */
					if (diff < 0) {
						if (child->nparents) {
							/* delete old branch */
							struct vtrillnode *oldparent=vtrilltable[child->parents[tree % child->nparents]];
							ba_clr(oldparent->tmpset,child->parentadj[tree % child->nparents]);
						}
						child->treedist=testdistance;
						child->nparents=1;
						/* add new branch */
						child->parents[0]=index;
						child->parentadj[0]=i;
						ba_set(this->tmpset,i);
						opq_add(&gpq,testdistance,this->adjindex[i]);
					} else if (diff==0) {
						int myvalue=nickvalue(this);
						int j;
						struct vtrillnode *chldparent;
						/* the tie-breaker algorithm in case of different paths of the same length
							 is to use the n-th max-prio/min nickname parent node for the n-th tree.
							 (this enforce that the trees take different branches when there are
							 alternative paths). The algorithm is a NTREE element bubblesort. */
						for (j=0; j<NTREE && j<child->nparents; j++)
							if (myvalue < nickvalue(vtrilltable[child->parents[j]]))
								break;
						if (j<NTREE) {
							/* delete old branch */
							chldparent=vtrilltable[child->parents[tree % child->nparents]];
							ba_clr(chldparent->tmpset,child->parentadj[tree % child->nparents]);
							child->nparents++;
							/* add new branch */
							/*printf("#%d j%d - pre %x %x %x %x %x\n", child->nparents, j,
									child->parents[0], child->parents[1], child->parents[2], child->parents[3], child->parents[4]);*/
							memmove(child->parents+(j+1),child->parents+j,(NTREE-(j+1)) * sizeof(uint16_t));
							memmove(child->parentadj+(j+1),child->parentadj+j,(NTREE-(j+1)) * sizeof(uint16_t));
							child->parents[j]=index;
							child->parentadj[j]=i;
							/*printf("#%d j%d - post %x %x %x %x %x\n", child->nparents, j,
									child->parents[0], child->parents[1], child->parents[2], child->parents[3], child->parents[4]);*/
							chldparent=vtrilltable[child->parents[tree % child->nparents]];
							ba_set(chldparent->tmpset,child->parentadj[tree % child->nparents]);
						} else
							child->nparents++;
					}
				}
			}
		}
		/* Create the data structure for the fast dispatching of broadcast packets */
		/* compute the max distance of the nodes on the tree from
			 this node (generally this node is not the root of the tree) */
		nexttree[tree].ttl = treemaxttl(nickmap[myintnick], -1);
		//// printf("\n");
		nexttree[tree].ndst = 0;
		{
			struct vtrillnode *me=vtrilltable[nickmap[myintnick]];
			int n;
			for (i=n=0; i<me->nadj; i++)
				if (ba_check(me->tmpset, i))
					n++;
			nexttree[tree].ndst=n;
			nexttree[tree].dst = realloc(nexttree[tree].dst, n * sizeof(struct nextvtrill));
			for (i=n=0; i<me->nadj; i++)
				if (ba_check(me->tmpset, i)) {
					struct vtrillnode *next=vtrilltable[me->adjindex[i]];
					nexttree[tree].dst[n].index=me->adjindex[i];
					if (ba_check(portset,next->port))
						nexttree[tree].dst[n].port=next->port;
					else
						nexttree[tree].dst[n].port=-1;
					nexttree[tree].dst[n].mac=next->mac;
					n++;
				}
		}

		/* tree post processing, clean the data structure to compute the next tree */
		for (i=0; i<vtrilltablemax; i++) {
			if (ba_check(vtrilltable_ok,i)) {
				struct vtrillnode *node=vtrilltable[i];
				node->flags &= ~VTRILLNODE_TVISITED;
				node->treedist=INT_MAX;
				node->nparents=0;
				if (node->tmpset) {
					free(node->tmpset);
					node->tmpset=NULL;
				}
			}
		}
	}
}

/* polling: is minpath computation required? */
static inline void schedule_minpath(time_t now)
{
	while (now >= nextminpath) {
		nextminpath = MAXTIME;
		minpath_computation();
	}
}

/* ISO Checksum */
int set_test_checksum(int set, unsigned char *data, int count, int chkpos)
{
	uint32_t c0 = 0;
	uint32_t c1 = 0;
	uint32_t factor;
	int index,x,y;
	/* less than 5803 bytes: no overflow */
	for( index = 0; index < chkpos; ++index )
	{
		c0 = (c0 + data[index]) ;
		c1 += c0;
	}
	index+=2;
	c1 += 2*c0;
	for(; index < count; ++index )
	{
		c0 = (c0 + data[index]) ;
		c1 += c0;
	}
	c0 = c0 % 255;
	c1 = c1 % 255;

	factor = (count - 8) * c0;
	x = factor - c0 - c1;
	y = c1 - factor - 1;

	if (x < 0 ) x--;
	if (y > 0 ) y++;
	x %= 255;
	y %= 255;
	if (x == 0) x = 0xFF;
	if (y == 0) y = 0x01;

	if(set) {
		data[chkpos]=x;
		data[chkpos+1]=y;
		return 0;
	} else {
		if (data[chkpos]==(x & 0xff) && data[chkpos+1]==(y & 0xff))
			return 1;
		else
			return 0;
	}
}

/********************* Database sync ***********************/


struct cnsp_data {
	unsigned char *start_lspid;
	unsigned char *end_lspid;
	int scannick;
	struct lsplist *scanlspl;
	struct tlvdata rep_psnptlv;
	int port;
	time_t now;
};

struct pnsp_data {
	int port;
	time_t now;
};

/* parse tlv emenents from snp packets */

static inline void cnsp_nexttlv(struct cnsp_data *cd)
{
	while (1) {
		struct lsplist *candidate;
		if (cd->scanlspl != NULL)
			cd->scanlspl=cd->scanlspl->next;
		if (cd->scanlspl == NULL) {
			if (cd->scannick >= (0xffc0-1))
				return;
			(cd->scannick)++;
			if (nickmap[cd->scannick] != 0xffff) {
			 struct lsplist *lsps=vtrilltable[nickmap[cd->scannick]]->lsps;
			 if (lsps)
				cd->scanlspl=lsps;
			}
		}
		candidate=cd->scanlspl;
		if (candidate != NULL) {
			if (memcmp(candidate->lsp->lspid, cd->start_lspid, 4) >= 0) {
				if (memcmp(candidate->lsp->lspid, cd->end_lspid, 4) <= 0) {
#if 0
					printf("NEXT (%x) = %02x %02x %02x %02x:%02x%02x%02x%02x\n", cd->scannick,
							candidate->lsp->lspid[0], candidate->lsp->lspid[1],
							candidate->lsp->lspid[2], candidate->lsp->lspid[3],
							candidate->lsp->seqno[0], candidate->lsp->seqno[1],
							candidate->lsp->seqno[2], candidate->lsp->seqno[3]);
#endif
					return;
				} else {
					cd->scanlspl=NULL;
					cd->scannick=0xffc0;
				}
			}
		}
	}
}

/* If a lsp entry is in an incoming snp packet and that lsp is missing on this node,
	 add a lsp entry (0 seqno and 0 remaining lifetime) for a lsnp return packet.
	 (it is the resend request) */
static inline void addlsnpentry(struct tlvdata *tlvdata, unsigned char *nick)
{
	char extlspid[10];
	memcpy(extlspid,nick,4);
	memset(extlspid+4,0,6);
	tlv_add(tlvdata, TLV_LSPENTRY, 0, extlspid);
}

/* if a local lsp is missing on the csnp packet sender's site, resend it.
	 we store all LSP as we received them, so we can just resend the packet
	 updating only the remaining lifetime field */
static inline void resendlsp(unsigned int port, struct lsplist *this, time_t now)
{
	time_t remtime = this->expiretime - now;
	if (remtime > 0) {
		this->lsp->remlifetime[0]=remtime>>8;
		this->lsp->remlifetime[1]=remtime;

		port_send_packet(port,this->lsp,this->len);
	}
}

/* psnp, this function sends all the latest LSPs matching the requested LSP-IDs */
int psnp_parse(int type, unsigned char *tlvdata, void *arg)
{
	struct pnsp_data *pnsp_data = arg;
	if (type == TLV_LSPENTRY) {
		struct vtrillnode *node = getvtrillnode(tlvdata+2);
		if (node) {
			struct lsplist *lsps = node->lsps;
			while (lsps != NULL && memcmp(lsps->lsp->lspid, tlvdata+2, 4) != 0)
				lsps = lsps->next;
			if (lsps != NULL)
				resendlsp(pnsp_data->port, lsps, pnsp_data->now);
		}
	}
	return 0;
}

/* incoming partial serial number pdu (PSNP):
	 resend the requested LSP (missing at the other end */ 
static void vtrill_in_psnp(int port, struct packet *p, int len)
{
	struct psnp *psnp=(struct psnp *)p;
	struct pnsp_data pnsp_data;
	pnsp_data.port = port;
	pnsp_data.now = qtime();

	//printf("GOT PSNP\n");
	tlv_parse(psnp,len,(psnp->pdulen[0]<<8)+psnp->pdulen[1]-VTRILL_MAC_HEADER_LEN,
			psnp->tlvbuf,psnp_parse,&pnsp_data);
}

/* cnsp.
	 an incoming csnp includes several LSPENTRY tagged tlvs.
	 during the parse:
	 - it tries each LSPENTRY to match a corresponding lsp item in the
	 local database.
	 - if the local entry is old or missing, it asks the resend by adding a tlv entry on
	 a pcnp packet
	 - if the local entry is newer, it is immediately resent to the source.
	 - when the lsp entries matches, it does nothing 
	 */
int csnp_parse(int type, unsigned char *tlvdata, void *arg)
{
	struct cnsp_data *cnsp_data = arg;
	if (type == TLV_LSPENTRY) {
		if (cnsp_data->scanlspl == NULL)
			addlsnpentry(&(cnsp_data->rep_psnptlv),tlvdata+2);
		else {
			while (cnsp_data->scanlspl) {
				struct lsplist *this = cnsp_data->scanlspl;
				int c=memcmp(tlvdata+2,this->lsp->lspid,8);
				/*printf("cmp (%02x%02x%02x%02x:%02x,%02x%02x%02x%02x:%02x)=%d\n", 
						tlvdata[2], tlvdata[3], tlvdata[4], tlvdata[5], tlvdata[9],
						this->lsp->lspid[0], this->lsp->lspid[1], this->lsp->lspid[2], this->lsp->lspid[3], 
						this->lsp->seqno[3],
						c);*/
				if (c==0) {
					/* CHECK CHECKSUM: resend if wrong*/
					if (memcmp(tlvdata+10,this->lsp->chksum,2) == 0) {
						/* align deadlines if it is okay */
						time_t newexpiretime = cnsp_data->now + (tlvdata[0]<<8) + tlvdata[1];
						if (newexpiretime < this->expiretime)
							this->expiretime = newexpiretime;
					} else {
						//// printf("CHKSUM MISMATCH\n");
						addlsnpentry(&(cnsp_data->rep_psnptlv),tlvdata+2);
						resendlsp(cnsp_data->port, this, cnsp_data->now);
					}
					cnsp_nexttlv(cnsp_data);
					break;
				} else if (c>0) {
					addlsnpentry(&(cnsp_data->rep_psnptlv),tlvdata+2);
					break;
				} else {
					resendlsp(cnsp_data->port, this, cnsp_data->now);
					cnsp_nexttlv(cnsp_data);
				}
			}
		}
	}
	return 0;
}

/* incoming complete sequence number pdu (CSNP)
	 check the consistency with the local LSP database.
	 - newer or missing seqno-> send back a psnp asking for retrasmission
	 - older seqno -> return the newer LSP to the sender */
static void vtrill_in_csnp(int port, struct packet *p, int len)
{
	struct csnp *csnp=(struct csnp *)p;
	struct cnsp_data cnsp_data;
	struct psnp *psnp=alloca(TRILL_PACKET_SIZE);
	int psnplen;

	//printf("GOT CSNP\n");
	/* prepare data for csnp parsing */
	cnsp_data.start_lspid=csnp->start_lspid;
	cnsp_data.end_lspid=csnp->end_lspid;
	cnsp_data.scannick=0;
	cnsp_data.scanlspl=NULL;
	cnsp_nexttlv(&cnsp_data);
	tlv_start(psnp,psnp->tlvbuf,&(cnsp_data.rep_psnptlv));
	cnsp_data.now = qtime();
	cnsp_data.port = port;
	/* this "parsing" scans the packet and the local database side by side,
		 in the meanwhile it sends the lsp or it enqueues tlv to a psnp packet */
	tlv_parse(csnp,len,(csnp->pdulen[0]<<8)+csnp->pdulen[1]-VTRILL_MAC_HEADER_LEN,csnp->tlvbuf,csnp_parse,&cnsp_data);
	/* the cnsp has terminated but there are extra lsps in the local database,
		 it miss they are missing at the designated node: send them */
	while (cnsp_data.scanlspl) {
		resendlsp(port, cnsp_data.scanlspl, cnsp_data.now);
		cnsp_nexttlv(&cnsp_data);
	}
	//printf("vtrill_in_csnp final\n");
	psnplen=tlv_end(&(cnsp_data.rep_psnptlv));
	/* The parsing phase added tlvs to the psnp, so it must be completed with the
		 right headers and sent out */
	if (psnplen > sizeof(struct psnp)) {
		//printf("SEND PSNP %d %d\n",psnplen,sizeof(struct psnp));
		memcpy(psnp,isis_proto,sizeof(isis_proto));
		memcpy(psnp->header.src,switchmac,ETH_ALEN);
		/* PSNP is UNICAST */
		memcpy(psnp->header.dest,csnp->header.src,ETH_ALEN);
		memcpy(psnp->vlan,vtrillvlan,2);
		psnp->hdrlen=PSNP_HDRLEN;
		psnp->pdutype=PSNP_PDU;
		memcpy(psnp->sourcenick,mynickname,2);
		psnp->sourcenick[2]=0;
		setlen(psnplen-VTRILL_MAC_HEADER_LEN,psnp->pdulen);
		port_send_packet(port,psnp,psnplen);
	}
}

/* CNSP sending (along all the ports where the current node is "designated switch" */
static void send_designated(struct csnp *csnp, int len)
{
	register unsigned int port;
	setlen(len-VTRILL_MAC_HEADER_LEN,csnp->pdulen);
	ba_FORALL(portset,numports, ({
				struct portdata *portdata = port_getvtrill(port);
				if (portdata->flags & PORTDATA_DESIGNATED)
					port_send_packet(port,csnp,len);
				}), port);
}

/* set up the updated cnsp packets and send them out */
static void vtrill_csnpsend(void *arg)
{
	struct csnp *csnp=alloca(TRILL_PACKET_SIZE);
	int intnick;
	struct tlvdata tlv;
	time_t now=qtime();
	memcpy(csnp,isis_proto,sizeof(isis_proto));
	memcpy(csnp->header.src,switchmac,ETH_ALEN);
	memcpy(csnp->vlan,vtrillvlan,2);
	csnp->hdrlen=CSNP_HDRLEN;
	csnp->pdutype=CSNP_PDU;
	memcpy(csnp->sourcenick,mynickname,2);
	csnp->sourcenick[2]=0;
	memset(csnp->start_lspid,0,4);
	memset(csnp->end_lspid,0xff,4);
	tlv_start(csnp, csnp->tlvbuf, &tlv);
	for (intnick=1; intnick < 0xffc0; intnick++) {
		if (nickmap[intnick] != 0xffff) {
			struct vtrillnode *thisnode = vtrilltable[nickmap[intnick]];
			struct lsplist **lspl=&(thisnode->lsps);
			while (*lspl) {
				struct lsplist *this=*lspl;
				/* during the scan for csnp packets creation
					 delete expired lsps */
				/* if it is an lsp of a reachable node -> minpath XXX */
				if (this->expiretime <= now) {
					thisnode->flags |= VTRILLNODE_MODIFIED;
					request_minpath(now);
					*lspl=this->next;
					free(this->lsp);
					free(this);
				} else {
					int remlife=this->expiretime-now;
					/* if add fails it means that the entry overflows the current csnp packet.
						 set the starting/ending LSPID, send the packet out and start filling in
						 a new packet */
					while (tlv_add(&tlv, TLV_LSPENTRY, remlife, this->lsp->lspid) < 0) {
						int len=tlv_end(&tlv);
						memcpy(csnp->end_lspid,this->lsp->lspid,4);
						/* trying to add this lspentry tlv, the packet overflowed, so the max lspid of this
							 packet get set to lspid-1, the new one starts from lsp.
							 There should never be gaps between lspid ranges of csnp packets */
						intdec4(csnp->end_lspid);
						send_designated(csnp,len);
						memcpy(csnp->start_lspid,this->lsp->lspid,4);
						memset(csnp->end_lspid,0xff,4);
						tlv_start(csnp, csnp->tlvbuf, &tlv);
					}
					lspl=&(this->next);
				}
			}
		}
	}
	int len=tlv_end(&tlv);
	send_designated(csnp,len);
}

/* constructor/destructor for this "layer" */
static void snp_init()
{
	vtrill_timercsnp=qtimer_add(csnpperiod,0,vtrill_csnpsend,NULL);
}

static void snp_fini()
{
	qtimer_del(vtrill_timercsnp);
}

/********************* Database ***********************/

/* flood algorithm step: send lsp packets along all the ports
	 but the one it received the lsp from.
	 Local packets use incoming port== -1, -1 cannot match any existing
	 ports so the packet get sent on all the ports */
static void lsp_flood(int port, struct packet *p, int len)
{
	int i;
	memcpy(p->header.src,switchmac,ETH_ALEN);
	ba_FORALL(portset, numports, ({
		//printf("flood %d %d\n",port,i);
		if(port != i)
			port_send_packet(i, p, len);
			}), i);
}

static void vtrill_neigh_unreachable(unsigned char *nickname, int prio, unsigned char *mac);
/* this lsp is fresh (never seen before) or not?
	 return 1 or 0 correspondigly */
static int lspfresh(struct lsp *lsp, int len)
{
	struct vtrillnode *sendernode=getvtrillnode(lsp->lspid);
	struct lsplist **lspscan;
	time_t now=qtime();
	/* checksum */
	if (len > TRILL_PACKET_SIZE)
		return 0;
	if (!set_test_checksum(0, lsp->lspid, len-offsetof(struct lsp,lspid), 8))
		return 0;
	if (lsp->tlvbuf[0] != 137 || lsp->tlvbuf[1] != 7) {
		/* this packet is not vtrill! */
		return 0;
	}
	if (sendernode == NULL) {
		/* new nickname! */
		sendernode=newvtrillnode(lsp->lspid,lsp->tlvbuf+3);
	} else {
		int diff=tie_breaker(lsp->tlvbuf[2], lsp->tlvbuf+3, sendernode->prio, sendernode->mac);
		if (diff) {
			/* nickname collision: same nick, different mac addr */
			/* if the prio of the sender is lower, or
				 the mac is greater, drop the packet */
			if (diff < 0)
				return 0;
			else {
				//printf("CHANGE collision!\n");
				if (memcmp(lsp->lspid, mynickname, 2) == 0 &&
						memcmp(lsp->tlvbuf+3, switchmac, ETH_ALEN) != 0) {
					/* This switch has to change its nickname! */
					//printf("CHANGE NICKNAME!\n");
					mynickname[0]=mynickname[1]=0;
					vtrill_restart();
					return 0;
				}
				vtrill_neigh_unreachable(lsp->lspid, sendernode->prio, sendernode->mac);
				deprecatevtrillnode(sendernode);
				sendernode=newvtrillnode(lsp->lspid,lsp->tlvbuf+3);
			}
		}
	}
	//printf("lspfresh5 %p %d %d\n",sendernode,sendernode->prio,lsp->tlvbuf[2]);
	sendernode->prio=lsp->tlvbuf[2];
  lspscan=&(sendernode->lsps);
	while(*lspscan != NULL &&
			memcmp(&(lsp->lspid), &((*lspscan)->lsp->lspid), 4) < 0)
		lspscan=&((*lspscan)->next);
	if (*lspscan != NULL &&
			memcmp(&(lsp->lspid), &((*lspscan)->lsp->lspid), 4) == 0) {
		/* found! */
		int newlsp=memcmp(&(lsp->seqno), &((*lspscan)->lsp->seqno), 4);
		//printf("freshfound %d \n",newlsp);
		/* found + old */
		if (newlsp < 0)
			return 0;
		/* found + current */
		if (newlsp == 0 &&
				memcmp(&(lsp->chksum), &((*lspscan)->lsp->chksum), 2) == 0) {
			/* renew! */
			(*lspscan)->expiretime = now+
				(lsp->remlifetime[0]<<8) + lsp->remlifetime[1];
			return 0;
		}
		/* found + new */
		if ((*lspscan)->len == len &&
				memcmp((*lspscan)->lsp + 1,
					lsp + 1, len - sizeof(struct lsp)) == 0) {
			/* new lsp may contain the same data as previous ones, just the seqno is new,
				 to renew the info. No minpath computation is required in this case */
			//printf ("==================== RENEW ONLY \n");
			memcpy((*lspscan)->lsp, lsp, sizeof(struct lsp));
		} else {
			/* something changed in connectivity */
			sendernode->flags |= VTRILLNODE_MODIFIED;
			request_minpath(now);
			//printf ("==================== MODIFIED! COMPUTE MINPATH! \n");
			(*lspscan)->len = len;
			memcpy((*lspscan)->lsp, lsp, len);
		}
		(*lspscan)->expiretime = now+
			(lsp->remlifetime[0]<<8) + lsp->remlifetime[1];
		return 1;
	}
	//printf("lspfresh6\n");
	/* new ID! this lspid has never been seen before */
	struct lsplist *newlsp = malloc(sizeof(struct lsplist));
	/* allocate 1542 bytes, so any future version of this lsp can be updated in place */
	newlsp->lsp = malloc(TRILL_PACKET_SIZE);
	newlsp->len = len;
	memcpy(newlsp->lsp, lsp, len);
	newlsp->expiretime = now+
		(lsp->remlifetime[0]<<8) + lsp->remlifetime[1];
	//newlsp->next=*lspscan;
	newlsp->next=NULL;
	*lspscan=newlsp;
	//printf ("==================== NEW! COMPUTE MINPATH! \n");
	/* this info is new, so schedule a minpath computation */
	sendernode->flags |= VTRILLNODE_MODIFIED;
	request_minpath(now);
#if 0
	printf("CONSISTENCY CHECK: %x%x ->", lsp->lspid[0],lsp->lspid[1]);
	struct lsplist *lspl;
	for(lspl=sendernode->lsps; lspl != NULL; lspl = lspl->next)
		printf("seq %x:%x",lspl->lsp->lspid[3],lspl->lsp->seqno[3]);
	printf("\n");
#endif
	return 1;
}

/* lsp incoming packet handler. local lsp get "received" from port -1.
	 if it is "fresh" flood it to the other nodes */

static void vtrill_in_lsp(int port, struct packet *p, int len)
{
	struct lsp *lsp=(struct lsp *)p;
	//printf("GOT LSP %x %x - %d\n", lsp->lspid[0],lsp->lspid[1], lsp->seqno[3]);
	if (lspfresh(lsp, len)) {
		memcpy(lsp->header.src,switchmac,ETH_ALEN);
		lsp_flood(port,p,len);
	}
}

/********************* Local LSP Database ***********************/

/* update local lsp database: a new node is reachable */

static void vtrill_neigh_reachable(unsigned char *nickname, int prio, 
		unsigned char *mac, int port, int metric)
{
	//printf("REACHABLE %x\n",(nickname[0]<<8)+nickname[1]);
	struct vtrillnode *sendernode=getvtrillnode(nickname);
	struct lsplist **lsps=&(mylsps);
	int fragment=0;
	struct tlvdata tlvdata;
	DBGOUT(DBGNEIGHPLUS,"%04x", ((nickname[0]<<8)|nickname[1]));
	EVENTOUT(DBGNEIGHPLUS, ((nickname[0]<<8)|nickname[1]));
	if (sendernode != NULL) {
		/* this nickname is already known */
		int mactest=tie_breaker(prio,mac,sendernode->prio,sendernode->mac);
		/* if the mac is not the same there is a clash */
		if (mactest) { 
			if (mactest < 0)
				return;
			else {
				/* HERE: collision on two different ports */
				vtrill_neigh_unreachable(nickname, sendernode->prio, sendernode->mac);
				deprecatevtrillnode(sendernode);
				sendernode=newvtrillnode(nickname,mac);
			}
		}
	} else {
		/* This is needed as we must set the port */
		sendernode=newvtrillnode(nickname,mac);
	}
	sendernode->prio=prio; 
	sendernode->port=port; /* XXX TBD: check loops on more ports */
	//printf("reachable2\n");
	/* this loop cycles if a lsp packet overflows and there is the need to create
		 a new lsp packet */
	while (1)
	{
		struct lsplist *this;
		if ((*lsps) == NULL) {
			struct lsplist *newlsp = malloc(sizeof(struct lsplist));
			newlsp->lsp = malloc(TRILL_PACKET_SIZE);
			newlsp->expiretime=0;
			memcpy(newlsp->lsp,isis_proto,sizeof(isis_proto));
			memcpy(newlsp->lsp->vlan,vtrillvlan,2);
			newlsp->lsp->hdrlen=LSP_HDRLEN;
			newlsp->lsp->pdutype=LSP_PDU;
			memcpy(newlsp->lsp->lspid,mynickname,2);
			newlsp->lsp->lspid[2]=0;
			newlsp->lsp->lspid[3]=fragment;
			memset(newlsp->lsp->seqno,0,4);
			newlsp->lsp->flags=0;
			tlv_start(newlsp->lsp, newlsp->lsp->tlvbuf, &tlvdata);
			tlv_add(&tlvdata,TLV_HOSTNAME,myprio,switchmac);
			newlsp->len=tlv_end(&tlvdata);
			newlsp->next=NULL;
			*lsps=newlsp;
		}
		this=*lsps;
		tlv_start(this->lsp, this->lsp->tlvbuf, &tlvdata);
		tlv_append(&tlvdata,this->len);
		if (tlv_add(&tlvdata,TLV_EXTREACH,nickname,0 /* ext */, metric) < 0) {
			/* overflow, move to the next "fragment" */
			tlv_end(&tlvdata);
			fragment++;
			lsps=&(this->next);
		} else {
			this->len=tlv_end(&tlvdata);
			setlen(this->len-VTRILL_MAC_HEADER_LEN, this->lsp->pdulen);
			/* force the renew/flood of this lsp */
			this->expiretime=0;
			/* and leave the "fragment" scan while loop */
			break;
		}
	}
}

/* update local lsp database: a node becomes (locally) unreachable */
/* note: TLV_EXTREACH entry for the unreachable node gets deleted from
	 the lsp packet where it is. tlv are never moved from a lsp packet to another
	 to minimize the request for packet flooding  */
static void vtrill_neigh_unreachable(unsigned char *nickname, int prio, unsigned char *mac)
{
	struct lsplist *lsps=mylsps;
	struct vtrillnode *sendernode=getvtrillnode(nickname);
	DBGOUT(DBGNEIGHMINUS,"%04x", ((nickname[0]<<8)|nickname[1]));
	EVENTOUT(DBGNEIGHMINUS, ((nickname[0]<<8)|nickname[1]));
	if (sendernode != NULL) {
		int mactest=tie_breaker(prio,mac,sendernode->prio,sendernode->mac);
		/* if the mac is not the same there is a clash */
		/* maybe this switch has the same nick on another port! */
		if (mactest) {
				return;
		}
	} 
	while(lsps != NULL) {
		int len=tlv_del_extreach(lsps->lsp, lsps->len, lsps->lsp->tlvbuf, nickname, /*ext*/0);
		if (len < lsps->len) {
			lsps->len=len;
			setlen(lsps->len-VTRILL_MAC_HEADER_LEN, lsps->lsp->pdulen);
			/* force the renew/flood of this lsp */
			lsps->expiretime=0;
			break;
		}
		lsps=lsps->next;
	}
}

/* renew lsp lsprenew second before they expire */
/* This function starts once per second */
static void vtrill_lspupdate(void *arg)
{
	struct lsplist *lsps=mylsps;
	time_t now=qtime();
	while(lsps != NULL) {
		if (now+lsprenew > lsps->expiretime) {
			/* increase the seqno */
			intinc4(lsps->lsp->seqno);
			//printf("vtrill_lspupdate seqno %02x %02x %02x %02x\n",lsps->lsp->seqno[0],lsps->lsp->seqno[1],lsps->lsp->seqno[2],lsps->lsp->seqno[3]);
			/* set the full lifetime for this packet */
			lsps->lsp->remlifetime[0]=lspexpire>>8;
			lsps->lsp->remlifetime[1]=lspexpire;
			/* take note of the expire time to renew it on time */
			lsps->expiretime = now + lspexpire;
			/* compute the OSI checksum */
			set_test_checksum(1, lsps->lsp->lspid, lsps->len - offsetof(struct lsp,lspid), 8);
			vtrill_in_lsp(-1, (struct packet *) lsps->lsp, lsps->len);
		}
		lsps=lsps->next;
	}
	/* once per second test if a minpath computation is needed */
	schedule_minpath(now);
}

/* constructor/descructor for the lsp layer */
static void lsp_init()
{
	struct vtrillnode *node;
	mylsps=NULL;
	node=newvtrillnode(mynickname,switchmac);
	node->prio=myprio;
	vtrill_timerlsp=qtimer_add(1,0,vtrill_lspupdate,NULL);
}

static void lsp_fini()
{
	int i;
	qtimer_del(vtrill_timerlsp);
	for (i=0; i<vtrilltablemax; i++) {
		if (ba_check(vtrilltable_ok,i)) {
			vtrilltable[i]->nadj=0;
			delvtrillnode(i);
		}
	}
	while (mylsps != NULL) {
		struct lsplist *this=mylsps;
		free(this->lsp);
		mylsps=this->next;
		free(this);
	}
}

/********************* Local reachability ***********************/

/* glue to the database layer */

static int check_isdesignated(struct neighlist *neigh)
{
	if (neigh == NULL) 
		return 0;
	while (neigh != NULL) {
		if (neigh->flags & NEIGH_UP &&
				memcmp(mynickname, neigh->nickname, 2) > 0)
			return 0;
		neigh=neigh->next;
	}
	return 1;
}

static void update_designated(struct portdata *portdata)
{
	if (portdata != NULL) {
		if (check_isdesignated(portdata->neighbors))
			portdata->flags |= PORTDATA_DESIGNATED;
		else
			portdata->flags &= ~PORTDATA_DESIGNATED;
		//printf("DESIGNATED %d\n",portdata->flags);
	}
}

/* send IIH/Hello packet */
/* This layer looks for "neighbors" port by port.
	 a neighbor is directly reachable on a port */
static void vtrill_hello(void *arg)
{
	register unsigned int port;
	struct iih *iih=alloca(TRILL_PACKET_SIZE);
	unsigned int holdingtime=3*helloperiod;
	struct tlvdata tlv;
	time_t now=qtime();
	memcpy(iih,isis_proto,sizeof(isis_proto));
	memcpy(iih->header.src,switchmac,ETH_ALEN);
	memcpy(iih->vlan,vtrillvlan,2);
	iih->hdrlen=IIH_HDRLEN;
	iih->pdutype=IIH_PDU;
	iih->circuit=1;
	memcpy(iih->nickname,mynickname,2);
	iih->holdingtime[0]=holdingtime>>8;
	iih->holdingtime[1]=holdingtime;
	iih->prio=myprio;
	iih->designlanid[0]=iih->designlanid[1]=iih->designlanid[2]=0;
	/* loop on all the vtrill ports and send "hello"/IIH */
	/* ISIS does not define a fragmentation strategy when too many
		 nodes are directly reachable on a port.
		 This limit is very high: more than 1000 nodes on a single link */
	ba_FORALL(portset,numports, ({
				int len;
				struct portdata *portdata = port_getvtrill(port);
				int modified=0;
				tlv_start(iih, iih->tlvbuf, &tlv);
				/* AREA is not needed */
				//tlv_add(&tlv, TLV_AREA);
				if (portdata != NULL) {
					struct neighlist **next=&(portdata->neighbors);
					while (*next != NULL) {
						if (now > (*next)->expiretime) {
							struct neighlist *delenda=*next;
							//printf("timeout %x\n",((*next)->nickname[0]<<8)+(*next)->nickname[1]);
							/* this neighbor becomes unreachable as its IIH packet expired */
							/* STATUS -> DOWN */
							if ((*next)->flags & NEIGH_UP) {
								modified=1;
								//// printf("UNREACHABLE %x\n",((*next)->nickname[0]<<8)+(*next)->nickname[1]);
								vtrill_neigh_unreachable((*next)->nickname,(*next)->prio,(*next)->mac);
								/* UPCALL! the neighbor is UNREACHABLE */
							}
							*next=(*next)->next;
							free(delenda);
						} else {
							tlv_add(&tlv,TLV_NEIGHBOR,(*next)->nickname);
							next=&((*next)->next);
						}
					}
				}
				len=tlv_end(&tlv)-VTRILL_MAC_HEADER_LEN;
				iih->pdulen[0]=len>>8;
				iih->pdulen[1]=len;
				port_send_packet(port,iih,len+VTRILL_MAC_HEADER_LEN);
				if (modified)
					update_designated(portdata);
				}), port);
}

/* test if an incoming IIH includes this node, i.e. test if the
	 communication is bidirectional */
int selfseentest(int type, unsigned char *tlvdata, void *arg)
{
	switch  (type) {
		case TLV_AREA:
			return 0;
		case TLV_NEIGHBOR:
			if (memcmp(tlvdata, mynickname,2) == 0)
				return 1;
			else
				return 0;
	}
	return 0;
}

/* incoming iih packet handler */
static void vtrill_in_iih(int port, struct packet *p, int len)
{
	struct iih *iih=(struct iih *)p;
	time_t expiretime=qtime()+((iih->holdingtime[0]<<8) + iih->holdingtime[1]);
	struct portdata *portdata = port_getvtrill(port);
	int modified=0;
	if (portdata == NULL) {
		printf("VTRILL NULL PORTDATA \n");
		return;
	}
	if (memcmp(iih->nickname,mynickname,2) == 0) {
		int diff=tie_breaker(iih->prio, iih->header.src, myprio, switchmac);
		if (diff==0) {
			/* we do not support non-vtrill shortcuts between ports */
			printf("duplicate MAC or circuit LOOP\n");
			return;
		} 
		if (diff > 0) {
			//printf("CHANGE NICKNAME!\n");
			mynickname[0]=mynickname[1]=0;
			vtrill_restart();
			return;
		}
	} 
	struct neighlist **next=&(portdata->neighbors);
	/* update neighbors' list */
	while (1) {
		if (*next == NULL) {
			/* STATUS -> NEW */
			*next=malloc(sizeof(struct neighlist));
			memcpy((*next)->nickname,iih->nickname,2);
			memcpy((*next)->mac,iih->header.src,ETH_ALEN);
			(*next)->prio=iih->prio;
			(*next)->expiretime=expiretime;
			(*next)->seenselftime=0;;
			//printf("fresh %x %ld\n",((*next)->nickname[0]<<8)+(*next)->nickname[1],expiretime);
			(*next)->flags=NEIGH_FRESH;
			(*next)->next=NULL;
			break;
		} else if (memcmp((*next)->nickname,iih->nickname,2)==0) {
			(*next)->expiretime=expiretime;
			//printf("update %x %ld\n",((*next)->nickname[0]<<8)+(*next)->nickname[1],expiretime);
			(*next)->flags&=~NEIGH_FRESH;
			break;
		} else
			next=&((*next)->next);
	}
	struct neighlist *this=*next;
	int selfseen=tlv_parse(iih,len,(iih->pdulen[0]<<8)+iih->pdulen[1]-VTRILL_MAC_HEADER_LEN,iih->tlvbuf,selfseentest,this);
	/* check selfseen */
	if (selfseen==1) {
		time_t now=qtime();
		if (this->seenselftime == 0)
			this->seenselftime = now;
		/* STATUS = INIT and goes to UP after holdperiod time */
		if(!(this->flags & NEIGH_UP) && now - this->seenselftime > holdperiod) {
			this->flags |= NEIGH_UP;
			modified=1;
			//// printf("REACHABLE %x\n",(this->nickname[0]<<8)+this->nickname[1]);
			vtrill_neigh_reachable(this->nickname, iih->prio, iih->header.src,port,portdata->metric);
			/* UPCALL! the neighbor is REACHABLE */
		}
	} else {
		/* this node received a IIH but it is not in the (local) reachability list of the
			 sender, so the sender becomes unreachable */
		/* -> STATUS=DOWN */
		if (this->flags & NEIGH_UP) {
			this->flags &= ~NEIGH_UP;
			modified=1;
			//// printf("UNREACHABLEa %x\n",(this->nickname[0]<<8)+this->nickname[1]);
			vtrill_neigh_unreachable(this->nickname,this->prio,this->mac);
			/* UPCALL! the neighbor is UNREACHABLE */
		}
		this->seenselftime = 0;
	}
	if (modified)
		update_designated(portdata);
	//printf("GOT IIH\n");
}

/*************************************************/
/* ISIS packet dispatcher */
void vtrill_in_isis(int port, struct packet *p, int len)
{
	struct isis *px=(struct isis *) p;
	if (len < sizeof(struct isis))
			return;
	switch (px->pdutype) {
		case IIH_PDU:
			vtrill_in_iih(port,p,len);
			break;
		case LSP_PDU:
			vtrill_in_lsp(port,p,len);
			break;
		case CSNP_PDU:
			vtrill_in_csnp(port,p,len);
			break;
		case PSNP_PDU:
			vtrill_in_psnp(port,p,len);
			break;
		default:
			printf("Unknown ISIS VTRILL PDU type\n");
			break;
	}
}

static void setmynickname()
{
	long val=INTNICK(mynickname);
	while (val==0 || val>=0xffc0 || nickmap[val] != 0xffff)
		val=lrand48() & 0xffff;
	mynickname[0]=val;
	mynickname[1]=val>>8;
}

/* add a port for vtrill */
void *vtrill_newport(int port)
{
	//printf("vtrill_newport %d\n",port);
	struct portdata *portdata=malloc(sizeof(struct portdata));
	portdata->flags=0;
	portdata->metric=0x100;
	portdata->neighbors=NULL;
	return portdata;
}

static void vtrill_delneighbors(struct portdata *portdata)
{
	if (portdata != NULL) {
		while (portdata->neighbors != NULL) {
			struct neighlist *delenda=portdata->neighbors;
			if (delenda->flags & NEIGH_UP) {
				//// printf("UNREACHABLEb %x\n",(delenda->nickname[0]<<8)+delenda->nickname[1]);
				vtrill_neigh_unreachable(delenda->nickname,delenda->prio,delenda->mac);
			}
			portdata->neighbors=delenda->next;
			free(delenda);
		}
		portdata->flags=0;
	}
}

/* delete a vtrill port */
void vtrill_delport(int port, void *vtrilldata)
{
	struct portdata *portdata=vtrilldata;
	vtrill_delneighbors(portdata);
	if (portdata)
		free(portdata);
	//printf("vtrill_delport %d\n",port);
}

/* enable/disable vtrill (it chains the constructor/descructors of the other layers */
void vtrill_start(void)
{
	register int i;
	/* LSP LAYER */
	if (nickmap==NULL) {
		nickmap=malloc(0xffc0 * sizeof(uint16_t));
		if (nickmap == NULL) {
			printlog(LOG_ERR,"vtrill: allocation of nickname mapping array failed %s",strerror(errno));
			exit(1);
		}
	}
	for (i=0;i<0xffc0;i++)
		nickmap[i]= 0xffff;
	setmynickname();
	lsp_init();
	snp_init();
	vtrill_timerhello=qtimer_add(helloperiod,0,vtrill_hello,NULL);
}

void vtrill_enable(bitarray ports,int vlan)
{
	portset=ports;
	vtrillvlan[0]=vlan>>8;
	vtrillvlan[1]=vlan;
	vtrill_start();
	printf("vtrill enabled\n");
}

static void vtrill_stop(void)
{
	register unsigned int port;
	qtimer_del(vtrill_timerhello);
	snp_fini();
	/* Local Reachability */
	ba_FORALL(portset,numports, 
			vtrill_delneighbors(port_getvtrill(port)),
			port);
	/* LSP */
	lsp_fini();
	if (nickmap != NULL) {
		free(nickmap);
		nickmap=NULL;
	}
}

void vtrill_disable(void)
{
	vtrill_stop();
	portset=NULL;
	vtrillvlan[0]=0xff;
	vtrillvlan[1]=0xff;
	printf("vtrill disabled\n");
}

static void vtrill_restart(void)
{
	setmynickname();
	vtrill_stop();
	vtrill_start();
}

/* CLI interface */

static int showinfo(FILE *fd)
{
	printoutc(fd,"nickname=%04x",INTNICK(mynickname));
	printoutc(fd,"vlan=%d",(vtrillvlan[0]<<8)+vtrillvlan[1]);
	printoutc(fd,"prio=%d",myprio);
	printoutc(fd,"helloperiod=%d",helloperiod);
	printoutc(fd,"holdperiod=%d",holdperiod);
	printoutc(fd,"lspexpire=%d",lspexpire);
	printoutc(fd,"lsprenew=%d",lsprenew);
	printoutc(fd,"csnpperiod=%d",csnpperiod);
	printoutc(fd,"minpathdelay=%d",minpathdelay);
	return 0;
}

static int setnick(char *arg)
{
	unsigned int val;
	sscanf(arg,"%x",&val);
	if (val==0 || val>=0xffc0 || nickmap[val] != 0xffff)
		return EINVAL;
	mynickname[0]=val>>8;
	mynickname[1]=val;
	vtrill_restart();
	return 0;
}

static int setprio(int arg)
{
	if (arg >= 0 && arg < 256)
		myprio=arg;
	else
		return EINVAL;
	return 0;
}

static int sethelloperiod(int arg)
{
	if (arg > 0)
		helloperiod=arg;
	else
		return EINVAL;
	holdperiod=3*helloperiod;
	return 0;
}

static int setholdtimer(int arg)
{
	if (arg > 0)
		holdperiod=arg;
	else
		return EINVAL;
	return 0;
}

static int setlspexpire(int arg)
{
	if (arg > 0)
		lspexpire=arg;
	else
		return EINVAL;
	return 0;
}

static int setlsprenew(int arg)
{
	if (arg > 0 && arg < lspexpire)
		lsprenew=arg;
	else
		return EINVAL; 
	return 0;
}

static int setcnspperiod(int arg)
{
	if (arg > 0)
		csnpperiod=arg;
	else
		return EINVAL; 
	return 0;
}

static int setminpathdel(int arg)
{
	if (arg > 0)
		minpathdelay=arg;
	else
		return EINVAL; 
	return 0;
}

static void oneportprint(FILE *fd, int port)
{
	struct portdata *portdata = port_getvtrill(port);
	time_t now=qtime();
	if (portdata) {
		struct neighlist *nb=portdata->neighbors;
		printoutc(fd,"Port: %04d metric: %5d %s",port,portdata->metric,
				(portdata->flags & PORTDATA_DESIGNATED)?"DESIGNATED":"");
		while(nb != NULL) {
			printoutc(fd,"  Neighbor: %04x  MAC: %02x:%02x:%02x:%02x:%02x:%02x Prio: %d Status: %s   Expiretime: %d (in %d secs)",
					(nb->nickname[0]<<8)+nb->nickname[1], 
					nb->mac[0], nb->mac[1], nb->mac[2], nb->mac[3], nb->mac[4], nb->mac[5], nb->prio,
					(nb->flags & NEIGH_UP)?"UP  ":
					((nb->seenselftime > 0)?"Init":"New "), nb->expiretime, nb->expiretime - now);
			nb=nb->next;
		}
	}
}

static int portprint(FILE *fd,char *arg)
{
	int port;
	if (*arg != 0) {
		port=atoi(arg);
		if (ba_check(portset,port))
			oneportprint(fd,port);
		else
			return EINVAL;
	} else {
		for (port=0;port<numports;port++) {
			if (ba_check(portset,port))
				oneportprint(fd,port);
		}
	}
	return 0;
}

static void onenodeprint(FILE *fd, struct vtrillnode *node)
{
	int i;
	time_t now=qtime();
	struct lsplist *lsp=node->lsps;
	printoutc(fd,"Node: %04x MAC: %02x:%02x:%02x:%02x:%02x:%02x  prio: %d  distance: %d  hops: %d",
			node->intnick,
			node->mac[0], node->mac[1], node->mac[2], node->mac[3], node->mac[4], node->mac[5],
			node->prio, node->distance, node->maxhop);
	for (i=0; i<node->nfirsthop; i++)
		printoutc(fd,"  minpath firsthop: %04x",vtrilltable[node->firsthop[i]]->intnick);
	for (i=0; i<node->nadj; i++)
		printoutc(fd,"  adjacent: %04x metric %d",vtrilltable[node->adjindex[i]]->intnick,node->adjmetric[i]);
	while (lsp) {
		printoutc(fd,"  lspid: %08x seqno: %08x expiretime: %d (in %d secs)",
				(lsp->lsp->lspid[0]<<24)+ (lsp->lsp->lspid[1]<<16)+ (lsp->lsp->lspid[2]<<8)+ (lsp->lsp->lspid[3]),
				(lsp->lsp->seqno[0]<<24)+ (lsp->lsp->seqno[1]<<16)+ (lsp->lsp->seqno[2]<<8)+ (lsp->lsp->seqno[3]),
				lsp->expiretime, lsp->expiretime - now);
		lsp=lsp->next;
	}
}

static int nodeprint(FILE *fd,char *arg)
{
	int intnick;
	int index;
	if (*arg != 0) {
		sscanf(arg,"%x",&intnick);
		if (intnick <= 0 || intnick>0xffc0)
			return EINVAL;
		index=nickmap[intnick];
		if (index == 0xffff)
			return EINVAL;
		onenodeprint(fd,vtrilltable[index]);
	} else {
		printoutc(fd,"Nickname: %04x",INTNICK(mynickname));
		for (intnick=1; intnick<0xffc0; intnick++) {
			if ((index=nickmap[intnick]) != 0xffff)
				onenodeprint(fd,vtrilltable[index]);
		}
	}
	return 0;
}

static int bctreeprint(FILE *fd,char *arg)
{
	int tree;
	printoutc(fd,"Nickname: %04x",INTNICK(mynickname));
	for (tree=0; tree<NTREE; tree++) {
		int n;
		printoutc(fd,"Tree: %2d ttlmax: %d Root: %04x MAC: %02x:%02x:%02x:%02x:%02x:%02x",
				tree,nexttree[tree].ttl,
				vtrilltable[rootindex[tree]]->intnick,
				vtrilltable[rootindex[tree]]->mac[0], vtrilltable[rootindex[tree]]->mac[1],
				vtrilltable[rootindex[tree]]->mac[2], vtrilltable[rootindex[tree]]->mac[3],
				vtrilltable[rootindex[tree]]->mac[4], vtrilltable[rootindex[tree]]->mac[5]);
		for (n=0; n< nexttree[tree].ndst; n++)
			printoutc(fd,"  tree adj: %04x MAC: %02x:%02x:%02x:%02x:%02x:%02x  port: %d",
				vtrilltable[nexttree[tree].dst[n].index]->intnick,
				nexttree[tree].dst[n].mac[0], nexttree[tree].dst[n].mac[1], nexttree[tree].dst[n].mac[2],
				nexttree[tree].dst[n].mac[3], nexttree[tree].dst[n].mac[4], nexttree[tree].dst[n].mac[5],
				nexttree[tree].dst[n].port);
	}
	return 0;
}

static struct comlist cl[]={
	{"vtrill","============","VTRILL MENU",NULL,NOARG},
	{"vtrill/showinfo","","show vtrill info",showinfo,NOARG|WITHFILE},
	{"vtrill/setnick","X","set the switch nickname (hex number)",setnick,STRARG},
	{"vtrill/setprio","N","set the switch priority",setprio,INTARG},
	{"vtrill/sethiperiod","N","set the hello timer info",sethelloperiod,INTARG},
	{"vtrill/sethold","N","set the hold period to define a reachable neighbor",setholdtimer,INTARG},
	{"vtrill/setlspxpire","N","set the lsp expire time",setlspexpire,INTARG},
	{"vtrill/setlsprenew","N","set the renew time (before a lsp expires)",setlsprenew,INTARG},
	{"vtrill/setcnsptime","N","set the period of cnsp packets",setcnspperiod,INTARG},
	{"vtrill/setmindel","N","set the delay to start a minpath computation",setminpathdel,INTARG},
	{"vtrill/portprint","[N]","print port vtrill info",portprint,STRARG|WITHFILE},
	{"vtrill/nodeprint","[X]","print vtrill node info",nodeprint,STRARG|WITHFILE},
	{"vtrill/bctreeprint","","print broadcast tree info",bctreeprint,STRARG|WITHFILE},
};

void vtrill_init(int initnumports)
{
	numports=initnumports;
	//printf("PORTS=%d\n",numports);
	ADDCL(cl);
#ifdef DEBUGOPT
	ADDDBGCL(dl);
#endif
}
#endif
