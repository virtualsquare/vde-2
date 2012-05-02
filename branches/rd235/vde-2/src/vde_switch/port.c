/* Copyright 2005 Renzo Davoli VDE-2
 * 2008 Luca Saiu (Marionnet project): a better hub implementation
 * Some minor remain from uml_switch Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPLv2 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> /*ntoh conversion*/
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>

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
#include "fstp.h"
#include "vtrill.h"

#include "packetq.h"

static int pflag=0;
static int numports;
#ifdef VDE_PQ2
static int stdqlen=128;
#endif
#ifdef VDE_VTRILL
static int vtrillvlan=4095;
#endif

static struct port **portv;

#ifdef DEBUGOPT
#define DBGPORTNEW (dl) 
#define DBGPORTDEL (dl+1) 
#define DBGPORTDESCR (dl+2) 
#define DBGEPNEW (dl+3) 
#define DBGEPDEL (dl+4) 
#define PKTFILTIN (dl+5)
#define PKTFILTOUT (dl+6)
static struct dbgcl dl[]= {
	  {"port/+","new port",D_PORT|D_PLUS},
		{"port/-","closed port",D_PORT|D_MINUS},
		{"port/descr","set port description",D_PORT|D_DESCR},
	  {"port/ep/+","new endpoint",D_EP|D_PLUS},
		{"port/ep/-","closed endpoint",D_EP|D_MINUS},
		{"packet/in",NULL,D_PACKET|D_IN},
		{"packet/out",NULL,D_PACKET|D_OUT},
};
#endif

// for dedugging if needed

#if 0
	 void packet_dump (struct packet *p)
	 {
	 register int i;
	 printf ("packet dump dst");
	 for (i=0;i<ETH_ALEN;i++)
	 printf(":%02x",p->header.dest[i]);
	 printf(" src");
	 for (i=0;i<ETH_ALEN;i++)
	 printf(":%02x",p->header.src[i]);
	 printf(" proto");
	 for (i=0;i<2;i++)
	 printf(":%02x",p->header.proto[i]);
	 printf("\n");
	 }
#endif

struct endpoint {
	int port;
	int fd_ctl;
	int fd_data;
	char *descr;
#ifdef VDE_PQ2
	struct vdepq *vdepq;
	int vdepq_count;
	int vdepq_max;
#endif
	struct endpoint *next;
};

#define NOTINPOOL 0x8000

struct port {
	struct endpoint *ep;
	int flag;
	/* sender is already inside ms, but it needs one more memaccess */
	int (*sender)(int fd_ctl, int fd_data, void *packet, int len, int port);
	struct mod_support *ms;
	int vlanuntag;
	uid_t user;
	gid_t group;
	uid_t curuser;
#ifdef FSTP
	int cost;
#endif
#ifdef VDE_VTRILL
	void *vtrilldata;
#endif
#ifdef PORTCOUNTERS
	long long pktsin,pktsout,bytesin,bytesout;
#endif
};

/* VLAN MANAGEMENT:
 * table the vlan table (also for inactive ports)
 * vlan bctag is the vlan table -- only tagged forwarding ports mapping
 * vlan bcuntag is the vlan table -- only untagged forwarding ports mapping
 * validvlan is the table of valid vlans
 */

struct {
	bitarray table;
	bitarray bctag;
	bitarray bcuntag;
	bitarray notlearning;
} vlant[NUMOFVLAN+1];
bitarray validvlan;

#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)


static int alloc_port(unsigned int portno)
{
	int i=portno;
	if (i==0) {
		/* take one */
		for (i=1;i<numports && portv[i] != NULL && 
				(portv[i]->ep != NULL || portv[i]->flag & NOTINPOOL) ;i++)
			;
	} else if (i<0) /* special case MGMT client port */
		i=0;
	if (i >= numports)
		return -1;
	else {
		if (portv[i] == NULL) {
			struct port *port;
			if ((port = malloc(sizeof(struct port))) == NULL){
				printlog(LOG_WARNING,"malloc port %s",strerror(errno));
				return -1;
			} else
			{
				DBGOUT(DBGPORTNEW,"%02d", i);
				EVENTOUT(DBGPORTNEW,i);

				portv[i]=port;
				port->ep=NULL;
				port->user=port->group=port->curuser=-1;
#ifdef FSTP
				port->cost=DEFAULT_COST;
#endif
#ifdef PORTCOUNTERS
				port->pktsin=0;
				port->pktsout=0;
				port->bytesin=0;
				port->bytesout=0;
#endif
				port->flag=0;
				port->sender=NULL;
				port->vlanuntag=0;
				ba_set(vlant[0].table,i);
#ifdef VDE_VTRILL
				port->vtrilldata=NULL;
#endif
			}
		}
		return i;
	}
}

static void free_port(unsigned int portno)
{
	if (portno < numports) {
		struct port *port=portv[portno];
		if (port != NULL && port->ep==NULL) {
			portv[portno]=NULL;
			register int i;
			/* delete completely the port. all vlan defs zapped */
			bac_FORALL(validvlan,NUMOFVLAN,ba_clr(vlant[i].table,portno),i);
			free(port);
		}
	}
}

/* 1 if user belongs to the group, 0 otherwise) */
static int user_belongs_to_group(uid_t uid, gid_t gid)
{
	struct passwd *pw=getpwuid(uid);
	if (pw == NULL) 
		return 0;
	else {
		if (gid==pw->pw_gid)
			return 1;
		else {
			struct group *grp;
			setgrent();
			while ((grp = getgrent())) {
				if (grp->gr_gid == gid) {
					int i;
					for (i = 0; grp->gr_mem[i]; i++) {
						if (strcmp(grp->gr_mem[i], pw->pw_name)==0) {
							endgrent();
							return 1;
						}
					}
				}
			}
			endgrent();
			return 0;
		}
	}
}


/* Access Control check:
	 returns 0->OK -1->Permission Denied */
static int checkport_ac(struct port *port, uid_t user)
{
	/*unrestricted*/
	if (port->user == -1 && port->group == -1)
		return 0;
	/*root or restricted to a specific user*/
	else if (user==0 || (port->user != -1 && port->user==user))
		return 0;
	/*restricted to a group*/
	else if (port->group != -1 && user_belongs_to_group(user,port->group))
		return 0;
	else {
		errno=EPERM;
		return -1;
	}
}

static int portsetup(int portno, char *setup);

/* initialize a new endpoint */
struct endpoint *setup_ep(int portno, int fd_ctl, int fd_data, uid_t user,
		struct mod_support *modfun, char *setup)
{
	struct port *port;
	struct endpoint *ep;

	if ((portno = alloc_port(portno)) >= 0) {
		port=portv[portno];	
		if (port->ep == NULL && checkport_ac(port,user)==0)
			port->curuser=user;
		if (port->curuser == user &&
				(ep=malloc(sizeof(struct endpoint))) != NULL) {
			DBGOUT(DBGEPNEW,"Port %02d FD %2d", portno,fd_ctl);
			EVENTOUT(DBGEPNEW,portno,fd_ctl);
			port->ms=modfun;
			port->sender=modfun->sender;
			if (setup) {
				portsetup(portno, setup);
			}
			ep->port=portno;
			ep->fd_ctl=fd_ctl;
			ep->fd_data=fd_data;
			ep->descr=NULL;
#ifdef VDE_PQ2
			ep->vdepq=NULL;
			ep->vdepq_count=0;
			ep->vdepq_max=stdqlen;
#endif
			if(port->ep == NULL) {/* WAS INACTIVE */
				register int i;
				/* copy all the vlan defs to the active vlan defs */
				ep->next=port->ep;
				port->ep=ep;
				bac_FORALL(validvlan,NUMOFVLAN,
						({if (ba_check(vlant[i].table,portno)) {
						 ba_set(vlant[i].bctag,portno);
#ifdef FSTP
						 fstaddport(i,portno,(i!=port->vlanuntag));
#endif
						 }
						 }),i);
				if (port->vlanuntag != NOVLAN) {
					ba_set(vlant[port->vlanuntag].bcuntag,portno);
					ba_clr(vlant[port->vlanuntag].bctag,portno);
				}
				if (port->vlanuntag != 4095)
					ba_clr(vlant[port->vlanuntag].notlearning,portno);
#ifdef VDE_VTRILL
				if (ba_check(vlant[vtrillvlan].bctag,portno))
					port->vtrilldata=vtrill_newport(portno);
#endif
			} else {
				ep->next=port->ep;
				port->ep=ep;
			}
			return ep;
		}
		else {
			if (port->curuser != user)
				errno=EADDRINUSE;
			else 
				errno=ENOMEM;
			return NULL;
		}
	}
	else {
		errno=ENOMEM;
		return NULL;
	}
}

int ep_get_port(struct endpoint *ep)
{
	return ep->port;
}

void setup_description(struct endpoint *ep, char *descr)
{
	DBGOUT(DBGPORTDESCR,"Port %02d FD %2d -> \"%s\"",ep->port,ep->fd_ctl,descr);
	EVENTOUT(DBGPORTDESCR,ep->port,ep->fd_ctl,descr);
	ep->descr=descr;
}

static int rec_close_ep(struct endpoint **pep, int fd_ctl)
{
	struct endpoint *this=*pep;
	if (this != NULL) {
		if (this->fd_ctl==fd_ctl) {
			DBGOUT(DBGEPDEL,"Port %02d FD %2d",this->port,fd_ctl);
			EVENTOUT(DBGEPDEL,this->port,fd_ctl);
			*pep=this->next;
#ifdef VDE_PQ2
			vdepq_del(&(this->vdepq));
#endif
			if (portv[this->port]->ms->delep)
				portv[this->port]->ms->delep(this->fd_ctl,this->fd_data,this->descr);
			free(this);
			return 0;
		} else
			return rec_close_ep(&(this->next),fd_ctl);
	} else
		return ENXIO;
}

static int close_ep_port_fd(int portno, int fd_ctl)
{
	if (portno >=0 && portno < numports) {
		struct port *port=portv[portno];
		if (port != NULL) {
			int rv=rec_close_ep(&(port->ep),fd_ctl);
			if (port->ep == NULL) {
				DBGOUT(DBGPORTDEL,"%02d",portno);
				EVENTOUT(DBGPORTDEL,portno);
				hash_delete_port(portno);
				port->ms=NULL;
				port->sender=NULL;
				port->curuser=-1;
#ifdef VDE_VTRILL
				if (ba_check(vlant[vtrillvlan].bctag,portno))
					vtrill_delport(portno,port->vtrilldata);
#endif
				register int i;
				/* inactivate port: all active vlan defs cleared */
				bac_FORALL(validvlan,NUMOFVLAN,({
							ba_clr(vlant[i].bctag,portno);
#ifdef FSTP
							fstdelport(i,portno);
#endif
							}),i);
				if (port->vlanuntag < NOVLAN) ba_clr(vlant[port->vlanuntag].bcuntag,portno);
				if (!(port->flag & NOTINPOOL))
					free_port(portno);
			}
			return rv;	
		} else
			return ENXIO;
	} else
		return EINVAL;
}

int close_ep(struct endpoint *ep)
{
	return close_ep_port_fd(ep->port, ep->fd_ctl);
}

#ifdef VDE_PQ2
static int rec_setqlen_ep(struct endpoint *ep, int fd_ctl, int len)
{
	struct endpoint *this=ep;
	if (this != NULL) {
		if (this->fd_ctl==fd_ctl) {
			ep->vdepq_max = len;
			return 0;
		} else
			return rec_setqlen_ep(this->next, fd_ctl, len);
	} else
		return ENXIO;
}

static int setqlen_ep_port_fd(int portno, int fd_ctl, int len)
{
	if (portno >=0 && portno < numports) {
		struct port *port=portv[portno];
		if (port != NULL) {
			return rec_setqlen_ep(port->ep, fd_ctl, len);
		}
		else
			return ENXIO;
	} else
		return EINVAL;
}
#endif

int portflag(int op,int f)
{
	int oldflag=pflag;
	switch(op)  {
		case P_GETFLAG: oldflag = pflag & f; break;
		case P_SETFLAG: pflag=f; break;
		case P_ADDFLAG: pflag |= f; break;
		case P_CLRFLAG: pflag &= ~f; break;
	}
	return oldflag;
}


/*********************** sending macro used by Core ******************/

/* VDBG counter: count[port].spacket++; count[port].sbytes+=len */
#ifdef PORTCOUNTERS
#define SEND_COUNTER_UPD(Port,LEN) ({Port->pktsout++; Port->bytesout +=len;})
#else
#define SEND_COUNTER_UPD(Port,LEN)
#endif

#ifndef VDE_PQ2
#define SEND_PACKET_PORT(PORT,PORTNO,PACKET,LEN) \
	({\
	 struct port *Port=(PORT); \
	 if (PACKETFILTER(PKTFILTOUT,(PORTNO),(PACKET), (LEN))) {\
	 struct endpoint *ep; \
	 SEND_COUNTER_UPD(Port,LEN); \
	 for (ep=Port->ep; ep != NULL; ep=ep->next) \
	 Port->ms->sender(ep->fd_ctl, ep->fd_data, (PACKET), (LEN), ep->port); \
	 } \
	 })
#else
#define SEND_PACKET_PORT(PORT,PORTNO,PACKET,LEN,TMPBUF) \
	({\
	 struct port *Port=(PORT); \
	 if (PACKETFILTER(PKTFILTOUT,(PORTNO),(PACKET), (LEN))) {\
	 struct endpoint *ep; \
	 SEND_COUNTER_UPD(Port,LEN); \
	 for (ep=Port->ep; ep != NULL; ep=ep->next) \
	 if (ep->vdepq_count || \
		 Port->ms->sender(ep->fd_ctl, ep->fd_data, (PACKET), (LEN), ep->port) == -EWOULDBLOCK) {\
	 if (ep->vdepq_count < ep->vdepq_max) \
	 ep->vdepq_count += vdepq_add(&(ep->vdepq), (PACKET), (LEN), TMPBUF); \
	 if (ep->vdepq_count == 1) mainloop_pollmask_add(ep->fd_data, POLLOUT);\
	 } \
	 } \
	 })
#endif

#if defined(FSTP) || defined(VDE_VTRILL)

/* functions for FSTP */
void port_send_packet(int portno, void *packet, int len)
{
#ifndef VDE_PQ2
	SEND_PACKET_PORT(portv[portno],portno,packet,len);
#else
	void *tmpbuf=NULL;
	SEND_PACKET_PORT(portv[portno],portno,packet,len,&tmpbuf);
#endif
}

void portset_send_packet(bitarray portset, void *packet, int len)
{
	register int i;
#ifndef VDE_PQ2
	ba_FORALL(portset,numports,
			SEND_PACKET_PORT(portv[i],i,packet,len), i);
#else
	void *tmpbuf=NULL;
	ba_FORALL(portset,numports,
			SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbuf), i);
#endif
}
#endif

#ifdef FSTP
void port_set_status(int portno, int vlan, int status)
{
	if (ba_check(vlant[vlan].table,portno)) {
		if (status==DISCARDING) {
			ba_set(vlant[vlan].notlearning,portno);
			ba_clr(vlant[vlan].bctag,portno);
			ba_clr(vlant[vlan].bcuntag,portno);
		} else if (status==LEARNING) {
			ba_clr(vlant[vlan].notlearning,portno);
			ba_clr(vlant[vlan].bctag,portno);
			ba_clr(vlant[vlan].bcuntag,portno);
		} else { /*forwarding*/
			ba_clr(vlant[vlan].notlearning,portno);
			if (portv[portno]->vlanuntag == vlan) 
				ba_set(vlant[vlan].bcuntag,portno);
			else 
				ba_set(vlant[vlan].bctag,portno);
		}
	}
}

int port_get_status(int portno, int vlan)
{
	if (ba_check(vlant[vlan].notlearning,portno)) 
		return DISCARDING;
	else {
		if (ba_check(vlant[vlan].bctag,portno) ||
				ba_check(vlant[vlan].bcuntag,portno))
			return FORWARDING;
		else
			return LEARNING;
	}
}

int port_getcost(int port)
{
	return portv[port]->cost;
}

void forallports(int vlan, void (*f)(int vlan, int port, int tagged))
{
	int port;
	if (bac_check(validvlan,vlan)) {
		ba_FORALL(vlant[vlan].bcuntag,numports, f(vlan,port,0),port);
		ba_FORALL(vlant[vlan].bctag,numports, f(vlan,port,1),port);
	}
}

#endif

#ifdef VDE_VTRILL
void *port_getvtrill(int portno)
{
	if (portno > 0 && portno < numports) {
		struct port *port=portv[portno];
		if (port != NULL)
			return port->vtrilldata;
		else
			return NULL;
	} else
		return NULL;
}
#endif

/************************************ CORE PACKET MGMT *****************************/

/* TAG2UNTAG packet:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *             | Destination     |    Source       |81 00|pvlan| L/T | data
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

/************************************ CORE PACKET MGMT *****************************/

/* TAG2UNTAG packet:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *             | Destination     |    Source       |81 00|pvlan| L/T | data
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *                         | Destination     |    Source       | L/T | data
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * Destination/Source: 4 byte right shift
 * Length -4 bytes
 * Pointer to the packet: +4 bytes
 * */

#define TAG2UNTAG(P,LEN) \
	({ memmove((char *)(P)+4,(P),2*ETH_ALEN); LEN -= 4 ; \
	 (struct packet *)((char *)(P)+4); })

/* TAG2UNTAG packet:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *             | Destination     |    Source       | L/T | data
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * | Destination     |    Source       |81 00|pvlan| L/T | data
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * Destination/Source: 4 byte left shift
 * Length -4 bytes
 * Pointer to the packet: +4 bytes
 * The space has been allocated in advance (just in case); all the modules
 * read data into a bipacket.
 */

#define UNTAG2TAG(P,VLAN,LEN) \
	({ memmove((char *)(P)-4,(P),2*ETH_ALEN); LEN += 4 ; \
	 (P)->header.src[2]=0x81; (P)->header.src[3]=0x00;\
	 (P)->header.src[4]=(VLAN >> 8); (P)->header.src[5]=(VLAN);\
	 (struct packet *)((char *)(P)-4); })

#ifdef VDE_PQ2
static int trysendfun(struct endpoint *ep, void *packet, int len)
{
	int port=ep->port;
	return portv[port]->ms->sender(ep->fd_ctl, ep->fd_data, packet, len, port);
}

void handle_out_packet(struct endpoint *ep)
{
	//printf("handle_out_packet %d\n",ep->vdepq_count);
	ep->vdepq_count -= vdepq_try(&(ep->vdepq),ep,trysendfun);
	if (ep->vdepq_count == 0)
		mainloop_pollmask_del(ep->fd_data, POLLOUT);
}
#endif

void handle_in_packet(struct endpoint *ep,  struct packet *packet, int len)
{
	int tarport;
	int vlan,tagged;
	int port=ep->port;
#ifdef VDE_VTRILL
	int fromvtrill;
#endif

	if(PACKETFILTER(PKTFILTIN,port,packet,len)) {

#ifdef PORTCOUNTERS
		portv[port]->pktsin++;
		portv[port]->bytesin+=len;
#endif
		if (pflag & HUB_TAG) { /* this is a HUB */
			register int i;
#ifndef VDE_PQ2
			for(i = 1; i < numports; i++)
				if((i != port) && (portv[i] != NULL))
					SEND_PACKET_PORT(portv[i],i,packet,len);
#else
			void *tmpbuf=NULL;
			for(i = 1; i < numports; i++)
				if((i != port) && (portv[i] != NULL))
					SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbuf);
#endif
		} else { /* This is a switch, not a HUB! */
			if (packet->header.proto[0] == 0x81 && packet->header.proto[1] == 0x00) {
				tagged=1;
				vlan=((packet->data[0] << 8) + packet->data[1]) & 0xfff;
				if (! ba_check(vlant[vlan].table,port))
					return; /*discard unwanted packets*/
			} else {
				tagged=0;
				if ((vlan=portv[port]->vlanuntag) == NOVLAN)
					return; /*discard unwanted packets*/
			}

#ifdef FSTP
			/* when FSTP is off, MST packet must be forwarded */
			if (ISBPDU(packet) && FSTVLAN(vlan)) {
				fst_in_bpdu(port,packet,len,vlan,tagged);
				return; /* BPDU packets are not forwarded */
			}
#endif
#ifdef VDE_VTRILL
			if (tagged && vlan==vtrillvlan) {
				if (ISISIS(packet)) {
					/* manage isis request */
					if (ISVISIS(packet))
						vtrill_in_isis(port, packet, len);
					return;
				}
				if (ISTRILL(packet)) {
					struct vtrillh *vt_packet = (struct vtrillh *)packet;
					if (VT_MULTI(vt_packet->vtrilldata)) {
						/* BROADCAST */
						/* forward the packets along all the tree branches but the receiving one */
						/* unpack the header (drop vtrill header) and continue */
						/* set port to ingress nickname | VTRILLNICKNAME! */
						/*
							printf("VTRILL Recv Broadcast \n");
							packet_dump(packet);
							*/
						int ttl;
						if ((ttl=VT_GETTTL(vt_packet->vtrilldata)) > 0) {
							unsigned char oldmac[6];
							ttl--;
							VT_SETTTL(vt_packet->vtrilldata, ttl);
							memcpy(oldmac, vt_packet->header.src, ETH_ALEN);
							memcpy(vt_packet->header.src, switchmac, ETH_ALEN);
							struct nextmultivtrill *nmvt=broadcast_vtrill(vt_packet->egress);
							if (nmvt) {
								int i;
								for (i=0; i<nmvt->ndst; i++) {
									if (memcmp(nmvt->dst[i].mac, oldmac, ETH_ALEN) != 0) {
										int port=nmvt->dst[i].port;
										if (port > 0) {
											memcpy(vt_packet->header.dest, nmvt->dst[i].mac, ETH_ALEN);
#ifndef VDE_PQ2
											SEND_PACKET_PORT(portv[port],port,packet,len);
#else
											void *tmpbuf=NULL;
											SEND_PACKET_PORT(portv[port],port,packet,len,&tmpbuf);
#endif
										}
									}
								}
							}
						}
						packet = VTRILL2UNVTRILL(packet,len);
						vlan=((packet->data[0] << 8) + packet->data[1]) & 0xfff;
						port = INTNICK(vt_packet->igress) | VTRILLNICKNAME;
					} else {
						/* UNICAST */
						/* if this switch is egress unpack the packet (drop vtrill header) and continue */
						/* set port to ingress nickname | VTRILLNICKNAME ! */
						if (memcmp(vt_packet->egress,mynickname,2) == 0) {
							packet = VTRILL2UNVTRILL(packet,len);
							port = INTNICK(vt_packet->igress) | VTRILLNICKNAME;
							vlan=((packet->data[0] << 8) + packet->data[1]) & 0xfff;
						} else {
							/* else this not egress forward the packet (delete if TTL is 0) */
							/* and return */
							int ttl;
							if ((ttl=VT_GETTTL(vt_packet->vtrilldata)) == 0)
								return;
							else {
								int myttl;
								int port = unicast_vtrill_port(INTNICK(vt_packet->egress), 
										vt_packet->header.dest, &myttl);
								if (port > 0) {
									ttl--;
									VT_SETTTL(vt_packet->vtrilldata, ttl);
									memcpy(vt_packet->header.src, switchmac, 6);
#ifndef VDE_PQ2
									SEND_PACKET_PORT(portv[port],port,packet,len);
#else
									void *tmpbuf=NULL;
									SEND_PACKET_PORT(portv[port],port,packet,len,&tmpbuf);
#endif
								}
								return;
							}
						}
					}
					fromvtrill=1;
				} else {
					fromvtrill=0;
					/* Mixed vtrill/nonvtrill traffic
						 has not been implemented yet */
					return;
				}
			} else {
				fromvtrill=0;
				/* The port is in blocked status, no packet received */
				if (ba_check(vlant[vlan].notlearning,port)) return; 
			}
#else
			/* The port is in blocked status, no packet received */
			if (ba_check(vlant[vlan].notlearning,port)) return; 
#endif

			/* We don't like broadcast source addresses */
			if(! (IS_BROADCAST(packet->header.src))) {
				int last = find_in_hash_update(packet->header.src,vlan,port);
				/* old value differs from actual input port */
				if(last >=0 && (port != last)){
					printlog(LOG_INFO,"MAC %02x:%02x:%02x:%02x:%02x:%02x moved from port %d to port %d",packet->header.src[0],packet->header.src[1],packet->header.src[2],packet->header.src[3],packet->header.src[4],packet->header.src[5],last,port);
				}
			}
			/* static void send_dst(int port,struct packet *packet, int len) */
			if(IS_BROADCAST(packet->header.dest) || 
					(tarport = find_in_hash(packet->header.dest,vlan)) < 0 ){
				/* no cache or broadcast/multicast == all ports *except* the source port! */
				/* BROADCAST: tag/untag. Broadcast the packet untouched on the ports
				 * of the same tag-ness, then transform it to the other tag-ness for the others*/
				/* TODO optimize if none is tagged or untagged */
				if (tagged) {
					register int i;
#ifndef VDE_PQ2
					ba_FORALL(vlant[vlan].bctag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len);}),i);
					packet=TAG2UNTAG(packet,len);
					ba_FORALL(vlant[vlan].bcuntag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len);}),i);
#else
					void *tmpbuft=NULL;
					void *tmpbufu=NULL;
					ba_FORALL(vlant[vlan].bctag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbuft);}),i);
					packet=TAG2UNTAG(packet,len);
					ba_FORALL(vlant[vlan].bcuntag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbufu);}),i);
#endif
				} else { /* untagged */
					register int i;
#ifndef VDE_PQ2
					ba_FORALL(vlant[vlan].bcuntag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len);}),i);
					packet=UNTAG2TAG(packet,vlan,len);
					ba_FORALL(vlant[vlan].bctag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len);}),i);
#else
					void *tmpbufu=NULL;
					void *tmpbuft=NULL;
					ba_FORALL(vlant[vlan].bcuntag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbufu);}),i);
					packet=UNTAG2TAG(packet,vlan,len);
					ba_FORALL(vlant[vlan].bctag,numports,
							({if (i != port) SEND_PACKET_PORT(portv[i],i,packet,len,&tmpbuft);}),i);
#endif
				}
#ifdef VDE_VTRILL
				/* if this broadcast does not come from vtrill */
				if (fromvtrill==0 && nreachable>1) {
					/* choose a tree and send the packet along the adjacent branches */
					struct vtrillh *vt_packet;
					/* if untag UNTAG->TAG */
					if (tagged) /* tagged reverse its logic for the broadcast above */
						packet = UNTAG2TAG(packet,vlan,len);
					packet=UNVTRILL2VTRILL(packet,len);
					vt_packet = (struct vtrillh *)packet;
					VTRILLH_SETEGRESS(vt_packet, 0xffffU);
					struct nextmultivtrill *nmvt=broadcast_vtrill(vt_packet->egress);
					if (nmvt) {
						int i;
						memcpy(vt_packet->header.src, switchmac, ETH_ALEN);
						SETUP_VTRILLH(vt_packet, vtrillvlan, 1, nmvt->ttl);
						for (i=0; i<nmvt->ndst; i++) {
							int port=nmvt->dst[i].port;
							if (port > 0) {
								memcpy(vt_packet->header.dest, nmvt->dst[i].mac, ETH_ALEN);
								//printf("VTRILL Send broadcast\n");
								//packet_dump(packet);
#ifndef VDE_PQ2
								SEND_PACKET_PORT(portv[port],port,packet,len);
#else
								void *tmpbuf=NULL;
								SEND_PACKET_PORT(portv[port],port,packet,len,&tmpbuf);
#endif
							}
						}
					}
				}
#endif
			} else {
				/* the hash table should not generate tarport not in vlan 
				 * any time a port is removed from a vlan, the port is flushed from the hash */
				if (tarport==port)
					return; /*do not loop!*/
#ifdef VDE_VTRILL
				if (tarport & VTRILLNICKNAME) {
					//printf("SEND UNICAST VTRILL %p %d\n", packet, len);
					/* do not reinsert packet from vtrill in vtrill again! */
					if (fromvtrill==0) {
						struct vtrillh *vt_packet;
						int port;
						int ttl;
						/* if untag UNTAG->TAG */
						if (!(tagged))
							packet = UNTAG2TAG(packet,vlan,len);
						/* wrap the packet by the vtrill header and send it to the first hop */
						packet=UNVTRILL2VTRILL(packet,len);
						vt_packet = (struct vtrillh *)packet;
						port = unicast_vtrill_port(get_vtrillnickname(tarport), 
								vt_packet->header.dest, &ttl);
						if (port > 0) {
							SETUP_VTRILLH(vt_packet, vtrillvlan, 0, ttl);
							VTRILLH_SETEGRESS(vt_packet, get_vtrillnickname(tarport));
#ifndef VDE_PQ2
							SEND_PACKET_PORT(portv[port],port,packet,len);
#else
							void *tmpbuf=NULL;
							SEND_PACKET_PORT(portv[port],port,packet,len,&tmpbuf);
						}
#endif
					}
					return;
				}
#endif
#ifndef VDE_PQ2
				if (tagged) {
					if (portv[tarport]->vlanuntag==vlan) { /* TAG->UNTAG */
						packet = TAG2UNTAG(packet,len);
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len);
					} else {                               /* TAG->TAG */
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len);
					}
				} else {
					if (portv[tarport]->vlanuntag==vlan) { /* UNTAG->UNTAG */
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len);
					} else {                              /* UNTAG->TAG */
						packet = UNTAG2TAG(packet,vlan,len);
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len);
					}
				}
#else
				if (tagged) {
					void *tmpbuf=NULL;
					if (portv[tarport]->vlanuntag==vlan) { /* TAG->UNTAG */
						packet = TAG2UNTAG(packet,len);
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len,&tmpbuf);
					} else {                               /* TAG->TAG */
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len,&tmpbuf);
					}
				} else {
					void *tmpbuf=NULL;
					if (portv[tarport]->vlanuntag==vlan) { /* UNTAG->UNTAG */
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len,&tmpbuf);
					} else {                              /* UNTAG->TAG */
						packet = UNTAG2TAG(packet,vlan,len);
						SEND_PACKET_PORT(portv[tarport],tarport,packet,len,&tmpbuf);
					}
				}
#endif
			} /* if(BROADCAST) */
		} /* if(HUB) */
	} /* if(PACKETFILTER) */
}

/**************************************** COMMAND MANAGEMENT ****************************************/

static int showinfo(FILE *fd)
{
	printoutc(fd,"Numports=%d",numports);
	printoutc(fd,"HUB=%s",(pflag & HUB_TAG)?"true":"false");
#ifdef PORTCOUNTERS
	printoutc(fd,"counters=true");
#else
	printoutc(fd,"counters=false");
#endif
#ifdef VDE_PQ2
	printoutc(fd,"default length of port packet queues: %d",stdqlen);
#endif
	return 0;
}

static int portsetnumports(int val)
{
	if(val > 0 && val < MAXPORT) {
		/*resize structs*/
		int i;
		for(i=val;i<numports;i++)
			if(portv[i] != NULL)
				return EADDRINUSE;
		portv=realloc(portv,val*sizeof(struct port *));
		if (portv == NULL) {
			printlog(LOG_ERR,"Numport resize failed portv %s",strerror(errno));
			exit(1);
		}
		for (i=0;i<NUMOFVLAN;i++) { 
			if (vlant[i].table) {
				vlant[i].table=ba_realloc(vlant[i].table,numports,val);
				if (vlant[i].table == NULL) {
					printlog(LOG_ERR,"Numport resize failed vlan tables vlan table %s",strerror(errno));
					exit(1);
				}
			}
			if (vlant[i].bctag) {
				vlant[i].bctag=ba_realloc(vlant[i].bctag,numports,val);
				if (vlant[i].bctag == NULL) {
					printlog(LOG_ERR,"Numport resize failed vlan tables vlan bctag %s",strerror(errno));
					exit(1);
				}
			}
			if (vlant[i].bcuntag) {
				vlant[i].bcuntag=ba_realloc(vlant[i].bcuntag,numports,val);
				if (vlant[i].bcuntag == NULL) {
					printlog(LOG_ERR,"Numport resize failed vlan tables vlan bctag %s",strerror(errno));
					exit(1);
				}
			}
			if (vlant[i].notlearning) {
				vlant[i].notlearning=ba_realloc(vlant[i].notlearning,numports,val);
				if (vlant[i].notlearning == NULL) {
					printlog(LOG_ERR,"Numport resize failed vlan tables vlan notlearning %s",strerror(errno));
					exit(1);
				}
			}
		}
		for (i=numports;i<val;i++)
			portv[i]=NULL;
#ifdef FSTP
		fstsetnumports(val);
#endif
#ifdef VDE_VTRILL
		vtrillsetnumports(val);
#endif
		numports=val;
		return 0;
	} else 
		return EINVAL;
}

static int portpreconfigure(char *arg)
{
	int port,value;
	if (sscanf(arg,"%i %i",&port,&value) != 2)
		return EINVAL;
	if (port < 0 || port >= numports)
		return EINVAL;
	if (portv[port] == NULL)
		return ENXIO;
	if (value)
		portv[port]->flag |= NOTINPOOL;
	else
		portv[port]->flag &= ~NOTINPOOL;
	return 0;
}

static int portsetuser(char *arg)
{
	int port;
	char *portuid=arg;
	struct passwd *pw;
	while (*portuid != 0 && *portuid == ' ') portuid++;
	while (*portuid != 0 && *portuid != ' ') portuid++;
	while (*portuid != 0 && *portuid == ' ') portuid++;
	if (sscanf(arg,"%i",&port) != 1 || *portuid==0)
		return EINVAL;
	if (port < 0 || port >= numports)
		return EINVAL;
	if (portv[port] == NULL)
		return ENXIO;
	if ((pw=getpwnam(portuid)) != NULL)
		portv[port]->user=pw->pw_uid;
	else if (isdigit(*portuid)) 
		portv[port]->user=atoi(portuid);
	else if (strcmp(portuid,"NONE")==0 || strcmp(portuid,"ANY")==0) 
		portv[port]->user= -1;
	else
		return EINVAL;
	return 0;
}

static int portsetgroup(char *arg)
{
	int port;
	char *portgid=arg;
	struct group *gr;
	while (*portgid != 0 && *portgid == ' ') portgid++;
	while (*portgid != 0 && *portgid != ' ') portgid++;
	while (*portgid != 0 && *portgid == ' ') portgid++;
	if (sscanf(arg,"%i",&port) != 1 || *portgid==0)
		return EINVAL;
	if (port < 0 || port >= numports)
		return EINVAL;
	if (portv[port] == NULL)
		return ENXIO;
	if ((gr=getgrnam(portgid)) != NULL)
		portv[port]->group=gr->gr_gid;
	else if (isdigit(*portgid)) 
		portv[port]->group=atoi(portgid);
	else if (strcmp(portgid,"NONE")==0 || strcmp(portgid,"ANY")==0) 
		portv[port]->group= -1;
	else
		return EINVAL;
	return 0;
}

static int portremove(int val)
{
	if (val <0 || val>=numports)
		return EINVAL;
	if (portv[val] == NULL)
		return ENXIO;
	if (portv[val]->ep != NULL)
		return EADDRINUSE;
	free_port(val);
	return 0;
}

static int portcreate(int val)
{
	int port;
	if (val <0 || val>=numports)
		return EINVAL;
	if (portv[val] != NULL)
		return EEXIST;
	port=alloc_port(val);
	if (port < 0)
		return ENOSPC;
	portv[port]->flag |= NOTINPOOL;
	return 0;
}

static int portcreateauto(FILE* fd)
{
	int port = alloc_port(0);

	if (port < 0)
		return ENOSPC;

	portv[port]->flag |= NOTINPOOL;
	printoutc(fd, "Port %04d", port);
	return 0;
}

static int epclose(char *arg)
{
	int port,id;
	if (sscanf(arg,"%i %i",&port,&id) != 2)
		return EINVAL;
	else
		return close_ep_port_fd(port,id);
}

#ifdef VDE_PQ2
static int defqlen(int len)
{
	if (len < 0)
		return EINVAL;
	else {
		stdqlen=len;
		return 0;
	}
}

static int epqlen(char *arg)
{
	int port,id,len;
	if (sscanf(arg,"%i %i %i",&port,&id,&len) != 3 || len < 0)
		return EINVAL;
	else
		return setqlen_ep_port_fd(port,id,len);
}
#endif

static char *port_getuser(uid_t uid)
{
	static char buf[6];
	struct passwd *pw;
	if (uid == -1) 
		return "NONE";
	else {
		pw=getpwuid(uid);
		if (pw != NULL)
			return pw->pw_name;
		else {
			sprintf(buf,"%d",uid);
			return buf;
		}
	}
}

static char *port_getgroup(gid_t gid)
{
	static char buf[6];
	struct group *gr;
	if (gid == -1) 
		return "NONE";
	else {
		gr=getgrgid(gid);
		if (gr != NULL)
			return gr->gr_name;
		else {
			sprintf(buf,"%d",gid);
			return buf;
		}
	}
}

static int print_port(FILE *fd,int i,int inclinactive)
{
	struct endpoint *ep;
	if (portv[i] != NULL && (inclinactive || portv[i]->ep!=NULL)) {
		printoutc(fd,"Port %04d untagged_vlan=%04d %sACTIVE - %s",
				i,portv[i]->vlanuntag,
				portv[i]->ep?"":"IN",
				(portv[i]->flag & NOTINPOOL)?"preconfigured":"");
		printoutc(fd," Current User: %s Access Control: (User: %s - Group: %s)", 
				port_getuser(portv[i]->curuser),
				port_getuser(portv[i]->user), 
				port_getgroup(portv[i]->group));
#ifdef PORTCOUNTERS
		printoutc(fd," IN:  pkts %10lld          bytes %20lld",portv[i]->pktsin,portv[i]->bytesin);
		printoutc(fd," OUT: pkts %10lld          bytes %20lld",portv[i]->pktsout,portv[i]->bytesout);
#endif
		for (ep=portv[i]->ep; ep != NULL; ep=ep->next) {
			printoutc(fd,"  -- endpoint ID %04d module %-12s: %s",ep->fd_ctl,
					portv[i]->ms->modname,(ep->descr)?ep->descr:"no endpoint description");
#ifdef VDE_PQ2
			printoutc(fd,"              unsent packets: %d max %d",ep->vdepq_count,ep->vdepq_max);
#endif
		}
		return 0;
	} else
		return ENXIO;
}

static int print_ptable(FILE *fd,char *arg)
{
	register int i;
	if (*arg != 0) {
		i=atoi(arg);
		if (i <0 || i>=numports)
			return EINVAL;
		else {
			return print_port(fd,i,0);
		}
	} else {
		for (i=0;i<numports;i++) 
			print_port(fd,i,0);
		return 0;
	}
}

static int print_ptableall(FILE *fd,char *arg)
{
	register int i;
	if (*arg != 0) {
		i=atoi(arg);
		if (i <0 || i>=numports)
			return EINVAL;
		else {
			return print_port(fd,i,1);
		}
	} else {
		for (i=0;i<numports;i++) 
			print_port(fd,i,1);
		return 0;
	}
}

#ifdef PORTCOUNTERS
static void portzerocounter(int i)
{
	if (portv[i] != NULL) {
		portv[i]->pktsin=0;
		portv[i]->pktsout=0;
		portv[i]->bytesin=0;
		portv[i]->bytesout=0;
	}
}

static int portresetcounters(char *arg)
{
	register int i;
	if (*arg != 0) {
		i=atoi(arg);
		if (i <0 || i>=numports)
			return EINVAL;
		else {
			portzerocounter(i);
			return 0;
		}
	} else {
		for (i=0;i<numports;i++)
			portzerocounter(i);
		return 0;
	}
}
#endif

static int portsethub(int val)
{
	if (val) {
#ifdef FSTP
		fstpshutdown();
#endif
		portflag(P_SETFLAG,HUB_TAG);
	} else
		portflag(P_CLRFLAG,HUB_TAG);
	return 0;
}

static int portsetvlan_nocheck(int port,int vlan)
{
	/* port NOVLAN is okay here, it means NO untagged traffic */
	if (vlan <0 || vlan > NUMOFVLAN || port < 0 || port >= numports) 
		return EINVAL;
	if ((vlan != NOVLAN && !bac_check(validvlan,vlan)) || portv[port] == NULL)
		return ENXIO;
	int oldvlan=portv[port]->vlanuntag;
	/* if the user redefines the same untagged vlan there is nothing to do. */
	if (oldvlan != vlan) {
		portv[port]->vlanuntag=NOVLAN;
		hash_delete_port(port);
		if (portv[port]->ep != NULL) {
			/*changing active port*/
			if (oldvlan != NOVLAN) 
				ba_clr(vlant[oldvlan].bcuntag,port);
			if (vlan != NOVLAN) {
				ba_set(vlant[vlan].bcuntag,port);
				ba_clr(vlant[vlan].bctag,port);
			}
#ifdef FSTP
			if (oldvlan != NOVLAN) fstdelport(oldvlan,port);
			if (vlan != NOVLAN) fstaddport(vlan,port,0);
#endif
		}
		if (oldvlan != NOVLAN) ba_clr(vlant[oldvlan].table,port);
		if (vlan != NOVLAN) ba_set(vlant[vlan].table,port);
		portv[port]->vlanuntag=vlan;
	}
	return 0;
}

static int portsetvlan(char *arg)
{
	int port,vlan;
	if (sscanf(arg,"%i %i",&port,&vlan) != 2)
		return EINVAL;
	return portsetvlan_nocheck(port,vlan);
}

static int vlancreate_nocheck(int vlan)
{
	int rv=0;
	vlant[vlan].table=ba_alloc(numports);
	vlant[vlan].bctag=ba_alloc(numports);
	vlant[vlan].bcuntag=ba_alloc(numports);
	vlant[vlan].notlearning=ba_alloc(numports);
	if (vlant[vlan].table == NULL || vlant[vlan].bctag == NULL || 
			vlant[vlan].bcuntag == NULL) 
		return ENOMEM;
	else {
#ifdef FSTP
		if (vlan == 0 && fstflag(P_GETFLAG,FSTP_TAG))
			rv=fstnewvlan(vlan);
#endif
		if (rv == 0) {
			bac_set(validvlan,NUMOFVLAN,vlan);
		}
		return rv;
	}
}

static int vlancreate(int vlan)
{
	if (vlan > 0 && vlan < NUMOFVLAN-1) { /*vlan NOVLAN (0xfff a.k.a. 4095) is reserved */
		if (bac_check(validvlan,vlan))
			return EEXIST;
		else 
			return vlancreate_nocheck(vlan);
	} else
		return EINVAL;
}

static int vlanremove(int vlan)
{
	if (vlan >= 0 && vlan < NUMOFVLAN) {
		if (bac_check(validvlan,vlan)) {
			register int i,used=0;
			ba_FORALL(vlant[vlan].table,numports,({used++;i;}),i);
			if (used)
				return EADDRINUSE;
			else {
				bac_clr(validvlan,NUMOFVLAN,vlan);
				free(vlant[vlan].table);
				free(vlant[vlan].bctag);
				free(vlant[vlan].bcuntag);
				free(vlant[vlan].notlearning);
				vlant[vlan].table=NULL;
				vlant[vlan].bctag=NULL;
				vlant[vlan].bcuntag=NULL;
				vlant[vlan].notlearning=NULL;
#ifdef FSTP
				fstremovevlan(vlan);
#endif
				return 0;
			}
		} else
			return ENXIO;
	} else
		return EINVAL;
}

static int vlanaddport_nocheck(int port, int vlan)
{
	if (vlan <0 || vlan >= NUMOFVLAN-1 || port < 0 || port >= numports)
		return EINVAL;
	if (!bac_check(validvlan,vlan) || portv[port] == NULL)
		return ENXIO;
	if (portv[port]->ep != NULL && portv[port]->vlanuntag != vlan) {
		/* if the port is already untagged for that vlan there is nothing to do */ 
		if (!bac_check(vlant[vlan].bctag,port)) {
			/* changing active port*/
			ba_set(vlant[vlan].bctag,port);
#ifdef FSTP
			fstaddport(vlan,port,1);
#endif
#ifdef VDE_VTRILL
			if (ba_check(vlant[vtrillvlan].bctag,port))
				portv[port]->vtrilldata=vtrill_newport(port);
#endif
		}
	}
	ba_set(vlant[vlan].table,port);
	return 0;
}

static int vlanaddport(char *arg)
{
	int port,vlan;
	if (sscanf(arg,"%i %i",&vlan,&port) != 2)
		return EINVAL;
	return vlanaddport_nocheck(port,vlan);
}

static int vlandelport(char *arg)
{
	int port,vlan;
	if (sscanf(arg,"%i %i",&vlan,&port) != 2)
		return EINVAL;
	if (vlan <0 || vlan >= NUMOFVLAN-1 || port < 0 || port >= numports)
		return EINVAL;
	if (!bac_check(validvlan,vlan) || portv[port] == NULL)
		return ENXIO;
	if (portv[port]->vlanuntag == vlan)
		return EADDRINUSE;
	if (portv[port]->ep != NULL) {
		/*changing active port*/
		ba_clr(vlant[vlan].bctag,port);
#ifdef FSTP
		fstdelport(vlan,port);
#endif
#ifdef VDE_VTRILL
		if (ba_check(vlant[vtrillvlan].bctag,port)) {
			vtrill_delport(port,portv[port]->vtrilldata);
			portv[port]->vtrilldata=NULL;
		}
#endif
	}
	ba_clr(vlant[vlan].table,port);
	hash_delete_port(port);
	return 0;
}

#ifdef VDE_VTRILL

static int vlanvtrill(int vlan)
{
	if (vlan > 0 && vlan < NUMOFVLAN) { /*vlan NOVLAN (0xfff a.k.a. 4095) means no vtrill */
		if (!bac_check(validvlan,vlan))
			return ENXIO;
		if (vlan != vtrillvlan) {
			if (vtrillvlan != 0xfff)
				vtrill_disable();
			vtrillvlan=vlan;
			vtrill_enable(vlant[vlan].bctag,vtrillvlan);
		}
		return 0;
	} else if (vlan == 0xfff) {
		vtrill_disable();
		vtrillvlan=vlan;
		return 0;
	} else
		return EINVAL;
}

static int showvtrill(FILE *fd)
{
	printoutc(fd,"vtrill is %sabled",(vtrillvlan==4095)?"dis":"en");
	printoutc(fd,"vtrill vlan=%d",vtrillvlan);
	return 0;
}

#endif

static int portsetup(int portno, char *setup)
{
	int rv=0;
	while (*setup) {
		if (*setup == ',') setup++;
		switch (*setup) {
			case 'u':
				rv=portsetvlan_nocheck(portno,atoi(++setup));
				break;
			case 't':
				rv=vlanaddport_nocheck(portno,atoi(++setup));
				break;
		}
		if (rv != 0) break;
		while (*setup && (*setup == ',' || isdigit(*setup)))
			setup++;
	}
	return rv;
}

static int portvlansetup(char *arg)
{
	char *setup;
	setup=strchr(arg,' ');
	if (setup == NULL)
		return EINVAL;
	setup++;
	return portsetup(atoi(arg),setup);
}

#define STRSTATUS(PN,V) \
	((ba_check(vlant[(V)].notlearning,(PN))) ? "Discarding" : \
	 (ba_check(vlant[(V)].bctag,(PN)) || ba_check(vlant[(V)].bcuntag,(PN))) ? \
	 "Forwarding" : "Learning")

static void vlanprintactive(int vlan,FILE *fd)
{
	register int i;
	printoutc(fd,"VLAN %04d",vlan);
	ba_FORALL(vlant[vlan].table,numports,
			({ int tagged=portv[i]->vlanuntag != vlan;
			 if (portv[i]->ep)
			 printoutc(fd," -- Port %04d tagged=%d active=1 status=%s", i, tagged, 
				 STRSTATUS(i,vlan));
			 }), i);
}

static int vlanprint(FILE *fd,char *arg)
{
	if (*arg != 0) {
		register int vlan;
		vlan=atoi(arg);
		if (vlan >= 0 && vlan < NUMOFVLAN-1) {
			if (bac_check(validvlan,vlan))
				vlanprintactive(vlan,fd);
			else
				return ENXIO;
		} else
			return EINVAL;
	} else 
		bac_FORALLFUN(validvlan,NUMOFVLAN,vlanprintactive,fd);
	return 0;
}

static void vlanprintelem(int vlan,FILE *fd)
{
	register int i;
	printoutc(fd,"VLAN %04d",vlan);
	ba_FORALL(vlant[vlan].table,numports,
			printoutc(fd," -- Port %04d tagged=%d active=%d status=%s",
				i, portv[i]->vlanuntag != vlan, portv[i]->ep != NULL, STRSTATUS(i,vlan)),i);
}

static int vlanprintall(FILE *fd,char *arg)
{
	if (*arg != 0) {
		register int vlan;
		vlan=atoi(arg);
		if (vlan > 0 && vlan < NUMOFVLAN-1) {
			if (bac_check(validvlan,vlan))
				vlanprintelem(vlan,fd);
			else
				return ENXIO;
		} else
			return EINVAL;
	} else 
		bac_FORALLFUN(validvlan,NUMOFVLAN,vlanprintelem,fd);
	return 0;
}

/* NOT sure about the effects of changing address on FSTP */

#if 0
static int setmacaddr(char *strmac)
{
	int maci[ETH_ALEN],rv;

	if (index(strmac,':') != NULL)
		rv=sscanf(strmac,"%x:%x:%x:%x:%x:%x", maci+0, maci+1, maci+2, maci+3, maci+4, maci+5);
	else
		rv=sscanf(strmac,"%x.%x.%x.%x.%x.%x", maci+0, maci+1, maci+2, maci+3, maci+4, maci+5);
	if (rv < 6)
		return EINVAL;
	else  {
		register int i;
		for (i=0;i<ETH_ALEN;i++)
			switchmac[i]=maci[i];
		return 0;
	}
}
#endif

uid_t port_user(int port)
{
	if (port<0 || port>=numports || portv[port]==NULL)
		return -1;
	else
		return portv[port]->curuser;
}

char *port_descr(int portno, int epn) {
	if (portno<0 || portno>=numports)
		return NULL;
	else {
		struct port *port=portv[portno];
		if (port == NULL)
			return NULL;
		else {
			struct endpoint *ep;
			for (ep=port->ep;ep!=NULL && epn>0;ep=ep->next,epn--)
				;
			if (ep)
				return ep->descr;
			else
				return NULL;
		}
	}
}

static struct comlist cl[]={
	{"port","============","PORT STATUS MENU",NULL,NOARG},
	{"port/showinfo","","show port info",showinfo,NOARG|WITHFILE},
	{"port/setnumports","N","set the number of ports",portsetnumports,INTARG},
	/*{"port/setmacaddr","MAC","set the switch MAC address",setmacaddr,STRARG},*/
	{"port/sethub","0/1","1=HUB 0=switch",portsethub,INTARG},
	{"port/setvlan","N VLAN","set port VLAN (untagged, 4095 for none)",portsetvlan,STRARG},
	{"port/createauto","","create a port with an automatically allocated id (inactive|notallocatable)",portcreateauto,NOARG|WITHFILE},
	{"port/create","N","create port N for preconfiguration",portcreate,INTARG},
	{"port/remove","N","remove the port N",portremove,INTARG},
	{"port/preconfigure","N 0/1","Is the port allocatable as unnamed? 1=Y 0=N",portpreconfigure,STRARG},
	{"port/setuser","N user","access control: set user",portsetuser,STRARG},
	{"port/setgroup","N user","access control: set group",portsetgroup,STRARG},
	{"port/epclose","N ID","remove the endpoint port N/id ID",epclose,STRARG},
#ifdef VDE_PQ2
	{"port/defqlen","LEN","set the default queue length for new ports",defqlen,INTARG},
	{"port/epqlen","N ID LEN","set the lenth of the queue for port N/id IP",epqlen,STRARG},
#endif
#ifdef PORTCOUNTERS
	{"port/resetcounter","[N]","reset the port (N) counters",portresetcounters,STRARG},
#endif
	{"port/vlansetup","N SETUPSTR","fast vlan def (see manual)",portvlansetup,STRARG},
	{"port/print","[N]","print the port/endpoint table",print_ptable,STRARG|WITHFILE},
	{"port/allprint","[N]","print the port/endpoint table (including inactive port)",print_ptableall,STRARG|WITHFILE},
	{"vlan","============","VLAN MANAGEMENT MENU",NULL,NOARG},
	{"vlan/create","N","create the VLAN with tag N",vlancreate,INTARG},
	{"vlan/remove","N","remove the VLAN with tag N",vlanremove,INTARG},
	{"vlan/addport","N PORT","add port to the vlan N (tagged)",vlanaddport,STRARG},
	{"vlan/delport","N PORT","add port to the vlan N (tagged)",vlandelport,STRARG},
#ifdef VDE_VTRILL
	{"vlan/vtrill","","show vtrill status/vlan",showvtrill,NOARG|WITHFILE},
	{"vlan/setvtrill","N","set the vtrill vlan (4095 for none)",vlanvtrill,INTARG},
#endif
	{"vlan/print","[N]","print the list of defined vlan",vlanprint,STRARG|WITHFILE},
	{"vlan/allprint","[N]","print the list of defined vlan (including inactive port)",vlanprintall,STRARG|WITHFILE},
};

void port_init(int initnumports)
{
	if((numports=initnumports) <= 0) {
		printlog(LOG_ERR,"The switch must have at least 1 port\n");
		exit(1);
	}
	if(numports > MAXPORT) {
		printlog(LOG_ERR,"Max # of ports (%d) exceeded\n",MAXPORT);
		exit(1);
	}
	portv=calloc(numports,sizeof(struct port *));
	/* vlan_init */
	validvlan=bac_alloc(NUMOFVLAN);
	if (portv==NULL || validvlan == NULL) {
		printlog(LOG_ERR,"ALLOC port data structures");
		exit(1);
	}
	ADDCL(cl);
#ifdef DEBUGOPT
	ADDDBGCL(dl);
#endif
	if (vlancreate_nocheck(0) != 0) {
		printlog(LOG_ERR,"ALLOC vlan port data structures");
		exit(1);
	}
}
