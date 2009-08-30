/* Copyright 2005 Renzo Davoli VDE-2
 * Licensed under the GPLv2 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
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

static int pflag=0;
static int numports;

#ifdef FSTP
#include <fstp.h>
/*********************** sending macro used by FSTP & Core ******************/
void inline ltonstring(unsigned long l,unsigned char *s) {
	s[3]=l; l>>=8;
	s[2]=l; l>>=8;
	s[1]=l; l>>=8;
	s[0]=l;
}

unsigned long inline nstringtol(unsigned char *s) {
	return (s[0]<<24)+(s[1]<<16)+(s[2]<<8)+s[3];
}

#define STP_TCA 0x80
#define STP_AGREEMENT 0x40
#define STP_FORWARDING 0x20
#define STP_LEARNING 0x10
#define STP_PORTROLEMASK 0x0c
#define STP_ROOT 0x04
#define STP_PROPOSAL 0x02
#define STP_TC 0x01

#ifdef DEBUGOPT
#define DBGFSTPSTATUS (dl) 
#define DBGFSTPROOT (dl+1) 
#define DBGFSTPPLUS (dl+2) 
#define DBGFSTPMINUS (dl+3) 
static struct dbgcl dl[]= {
	  {"fstp/status","fstp: status change",D_FSTP|D_STATUS},
	  {"fstp/root","fstp: rootswitch/port change",D_FSTP|D_ROOT},
	  {"fstp/+","fstp: port becomes active",D_FSTP|D_PLUS},
	  {"fstp/-","fstp: port becomes inactive",D_FSTP|D_MINUS},
};
static char *fstpdecodestatus[]={
	"discarding",
	"learning",
	"forwarding",
	"learning+forwarding"};
#define port_set_status(P,V,S) \
	({DBGOUT(DBGFSTPSTATUS,"Port %04d VLAN %02x:%02x %s",\
					       (P),(V)>>8,(V)&0xff,fstpdecodestatus[(S)]);\
	 EVENTOUT(DBGFSTPSTATUS,(P),(V),(S));\
	 port_set_status(P,V,S);})
#endif

#define SWITCHID_LEN (ETH_ALEN+2)
#define FSTP_ACTIVE(VLAN,PORT) (ba_check(fsttab[(VLAN)]->rcvhist[0],(PORT)) || \
			ba_check(fsttab[(VLAN)]->rcvhist[1],(PORT)))

static int rcvhistindex;
struct vlst {
	unsigned char root[SWITCHID_LEN];
	unsigned char rootcost[4];
	unsigned char dessw[SWITCHID_LEN];
	unsigned char port[2];
	int rootport;
	int bonusport;
	int bonuscost;
	int tctime;
	/* TC: topology change timers missing XXX */
	unsigned int roottimestamp;
	bitarray untag;
	bitarray tagged;
	bitarray backup;
	bitarray edge;
	bitarray rcvhist[2];
};

#define BPDUADDR {0x01,0x80,0xc2,0x00,0x00,0x00}
unsigned char bpduaddrp[]=BPDUADDR;
#define SETFSTID(ID,MAC,PRIO) ({ \
		char *id=(char *)(ID); \
		*(id++)=(PRIO)>>8; \
		*(id++)=(PRIO); \
		memcpy(id,(MAC),ETH_ALEN); 0; })
static unsigned char myid[SWITCHID_LEN];

#define STDHELLOPERIOD 4
static struct vlst *fsttab[NUMOFVLAN];
static int helloperiod = STDHELLOPERIOD;
static int maxage = STDHELLOPERIOD*10;
static int fst_timerno;

/* packet prototype for untagged ports */
struct fstbpdu {
	struct ethheader header;
	unsigned char llc[3];
	unsigned char stp_protocol[2];
	unsigned char stp_version;
	unsigned char stp_type;
	unsigned char stp_flags;
	unsigned char stp_root[SWITCHID_LEN];
	unsigned char stp_rootcost[4];
	unsigned char stp_bridge[SWITCHID_LEN];
	unsigned char stp_port[2];
	unsigned char stp_age[2];
	unsigned char stp_maxage[2];
	unsigned char stp_hello[2];
	unsigned char stp_fwddelay[2];
	unsigned char stp_v1len;
} __attribute__((packed));;

/* packet prototype for tagged ports */
struct fsttagbpdu {
	struct ethheader header;
  unsigned char tag_vlan[2];
  unsigned char tag_proto[2];
	unsigned char llc[3];
	unsigned char stp_protocol[2];
	unsigned char stp_version;
	unsigned char stp_type;
	unsigned char stp_flags;
	unsigned char stp_root[SWITCHID_LEN];
	unsigned char stp_rootcost[4];
	unsigned char stp_bridge[SWITCHID_LEN];
	unsigned char stp_port[2];
	unsigned char stp_age[2];
	unsigned char stp_maxage[2];
	unsigned char stp_hello[2];
	unsigned char stp_fwddelay[2];
	unsigned char stp_v1len;
} __attribute__((packed));;

static struct fstbpdu outpacket = {
	.header.dest=BPDUADDR,
	.header.proto={0x00,0x39}, /* 802.3 packet length */
	.llc={0x42,0x42,0x3},
	.stp_protocol={0,0},
	.stp_version=2,
	.stp_type=2,
};

static struct fsttagbpdu outtagpacket = {
	.header.dest=BPDUADDR,
	.header.proto={0x81,0x00},
	.tag_proto={0x00,0x39},
	.llc={0x42,0x42,0x3},
	.stp_protocol={0,0},
	.stp_version=2,
	.stp_type=2,
};

/* 
 * BIT:
 *  0 TOPOLOGY CHANGE
 *  1 PROPOSAL
 *  2/3 PORT ROLE: 00 UNKNOWN 01 ALT/BACKUP 10 ROOT 11 DESIGNATED
 *  4 LEARNING 5 FORWARDING
 *  6 AGREEMENT
 *  7 TOPOLOGY CHANGE ACK
 */

#define STP_FLAGS(VLAN,PORT,AGR,TC,TCACK) \
	(TC | \
	 (ba_check(fsttab[(VLAN)]->backup,port) != 0) << 1 | \
	 (ba_check(fsttab[(VLAN)]->backup,port) == 0) << 2 | \
	 (fsttab[vlan]->rootport != (PORT)) << 3 |\
	 port_get_status((PORT),(VLAN)) << 4 | \
	 (AGR) << 6 | \
	 (TCACK) << 7)

int fstnewvlan(int vlan)
{
	/*printf("F new vlan %d\n",vlan);*/
	register unsigned int port;
	int newvlan=(fsttab[vlan] == NULL);
	if (newvlan  &&
			((fsttab[vlan]=malloc(sizeof(struct vlst))) == NULL ||
			 (fsttab[vlan]->untag = ba_alloc(numports)) == NULL ||
			 (fsttab[vlan]->tagged = ba_alloc(numports)) == NULL ||
			 (fsttab[vlan]->edge = ba_alloc(numports)) == NULL ||
			 (fsttab[vlan]->rcvhist[0] = ba_alloc(numports)) == NULL ||
			 (fsttab[vlan]->rcvhist[1] = ba_alloc(numports)) == NULL ||
			 (fsttab[vlan]->backup = ba_alloc(numports)) == NULL))
		return ENOMEM;
	else {
		memcpy(fsttab[vlan]->root,myid,SWITCHID_LEN);
		memset(fsttab[vlan]->rootcost,0,4);
		memset(fsttab[vlan]->dessw,0xff,SWITCHID_LEN);
		memset(fsttab[vlan]->port,0,4);
		fsttab[vlan]->rootport=fsttab[vlan]->roottimestamp=0;
		if (newvlan) {
			fsttab[vlan]->bonusport=fsttab[vlan]->bonuscost=0;
			fsttab[vlan]->tctime=0;
		}
		DBGOUT(DBGFSTPROOT,"Port %04d VLAN %02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				0,vlan>>8,vlan&0xff,
				fsttab[vlan]->root[0], fsttab[vlan]->root[1], 
				fsttab[vlan]->root[2], fsttab[vlan]->root[3],
				fsttab[vlan]->root[4], fsttab[vlan]->root[5], 
				fsttab[vlan]->root[6], fsttab[vlan]->root[7]);
		EVENTOUT(DBGFSTPROOT,0,vlan,fsttab[vlan]->root);
		ba_FORALL(fsttab[vlan]->backup,numports, ({
				ba_clr(fsttab[vlan]->backup,port);
				port_set_status(port,vlan,FORWARDING);
				}), port);
		return 0;
	}
}

int fstremovevlan(int vlan)
{
	/*printf("F remove vlan %d\n",vlan);*/
	if (fsttab[vlan] == NULL) 
		return ENOENT;
	else {
		struct vlst *old=fsttab[vlan];
		fsttab[vlan]=NULL;
		free(old->untag);
		free(old->tagged);
		free(old->backup);
		free(old->edge);
		free(old->rcvhist[0]);
		free(old->rcvhist[1]);
		free(old);
		return 0;
	}
}

void fstsetnumports (int val)
{
	register int i;
	/*printf("F numports %d\n",val);*/
	for (i=0;i<NUMOFVLAN;i++) {
		if (fsttab[i]) {
			fsttab[i]->untag=ba_realloc(fsttab[i]->untag,numports,val);
			if (fsttab[i]->untag == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/untag %s",strerror(errno));
				exit(1);
			}
			fsttab[i]->tagged=ba_realloc(fsttab[i]->tagged,numports,val);
			if (fsttab[i]->tagged == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/tagged %s",strerror(errno));
				exit(1);
			}
			fsttab[i]->backup=ba_realloc(fsttab[i]->backup,numports,val);
			if (fsttab[i]->backup == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/backup %s",strerror(errno));
				exit(1);
			}
			fsttab[i]->edge=ba_realloc(fsttab[i]->edge,numports,val);
			if (fsttab[i]->edge == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/edge %s",strerror(errno));
				exit(1);
			}
			fsttab[i]->rcvhist[0]=ba_realloc(fsttab[i]->rcvhist[0],numports,val);
			if (fsttab[i]->rcvhist[0] == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/rcvhist0 %s",strerror(errno));
				exit(1);
			}
			fsttab[i]->rcvhist[1]=ba_realloc(fsttab[i]->rcvhist[1],numports,val);
			if (fsttab[i]->rcvhist[1] == NULL) {
				printlog(LOG_ERR,"Numport resize failed vlan tables fstab/rcvhist1 %s",strerror(errno));
				exit(1);
			}
		}
	}
	numports=val;
}

/* say hello! */
static void fst_hello_vlan(int vlan,int now)
{
	int age,nowvlan;
	register int port;
	/* timeout on the root port */
	if (fsttab[vlan]->rootport != 0 && (now - fsttab[vlan]->roottimestamp) > 3*helloperiod)
		fstnewvlan(vlan);
	nowvlan=(fsttab[vlan]->rootport==0)?0:now; /* This switch is the root */
	memcpy(outpacket.stp_root,fsttab[vlan]->root,SWITCHID_LEN);
	memcpy(outtagpacket.stp_root,fsttab[vlan]->root,SWITCHID_LEN);
	memcpy(outpacket.stp_rootcost,fsttab[vlan]->rootcost,4);
	memcpy(outtagpacket.stp_rootcost,fsttab[vlan]->rootcost,4);
	age=nowvlan-fsttab[vlan]->roottimestamp;
	if (age > 0xffff) age=0xffff;
	outpacket.stp_age[0] = outtagpacket.stp_age[0]=age;
	outpacket.stp_age[1] = outtagpacket.stp_age[1]=age>>8;
	outpacket.stp_fwddelay[0] = outtagpacket.stp_fwddelay[0]=0;
	outpacket.stp_fwddelay[1] = outtagpacket.stp_fwddelay[1]=0; /* XXX */
	ba_FORALL(fsttab[vlan]->untag,numports,
			({ if (!(ba_check(fsttab[vlan]->edge,port))) {
			 outpacket.stp_port[0]=0x80| (port>>4);
			 outpacket.stp_port[1]=port;
			 outpacket.stp_flags=STP_FLAGS(vlan,port,1,0,0);
			 port_send_packet(port,&outpacket,sizeof(outpacket));
			 }
			 }), port);
	ba_FORALL(fsttab[vlan]->tagged,numports,
			({ if (!(ba_check(fsttab[vlan]->edge,port))) {
			 outtagpacket.stp_port[0]=0x80| (port>>4);
			 outtagpacket.stp_port[1]=port;
			 outtagpacket.tag_vlan[0]=vlan>>8 & 0xf;
			 outtagpacket.tag_vlan[1]=vlan;
			 outtagpacket.stp_flags=STP_FLAGS(vlan,port,1,0,0);
			 port_send_packet(port,&outtagpacket,sizeof(outtagpacket));
			 }
			 }), port);
}

/* a port that is not handling control packets for a while cannot be
 * a backup port. It means that the other end is not speaking FSTP anymore.
 * It must be reverted to a designed forwarding port.
 */
static void fst_updatebackup(int vlan,int index)
{
	register int port;
	ba_FORALL(fsttab[vlan]->backup,numports, ({
				if (!FSTP_ACTIVE(vlan,port)) {
				ba_clr(fsttab[vlan]->backup,port);
				port_set_status(port,vlan,FORWARDING);
				}
				}), port);
#ifdef DEBUGOPT
	ba_FORALL(fsttab[vlan]->untag,numports,({
				if (ba_check(fsttab[(vlan)]->rcvhist[index],(port)) && !(ba_check(fsttab[(vlan)]->rcvhist[1-index],(port)))) {
				DBGOUT(DBGFSTPMINUS,"Port %04d VLAN %02x:%02x",port,vlan>>8,vlan&0xff);
				EVENTOUT(DBGFSTPMINUS,port,vlan); }
				}), port);
	ba_FORALL(fsttab[vlan]->tagged,numports,({
				if (ba_check(fsttab[(vlan)]->rcvhist[index],(port)) && !(ba_check(fsttab[(vlan)]->rcvhist[1-index],(port)))) {
				DBGOUT(DBGFSTPMINUS,"Port %04d VLAN %02x:%02x",port,vlan>>8,vlan&0xff);
				EVENTOUT(DBGFSTPMINUS,port,vlan); }
				}), port);
#endif
	ba_zap(fsttab[vlan]->rcvhist[index],numports);
}

static void fst_hello(void *arg)
{
	int now=qtime();
	static int hellocounter;
	hellocounter++;
	//printf("HELLO\n");
	bac_FORALLFUN(validvlan,NUMOFVLAN,fst_hello_vlan,now);
	if ((hellocounter & 0x3) == 0) {
		rcvhistindex=1-rcvhistindex;
		bac_FORALLFUN(validvlan,NUMOFVLAN, fst_updatebackup,rcvhistindex);
	}
}

static void fst_sendbpdu(int vlan,int port,int agr,int tc,int tcack)
{
	int now=qtime();
	int age,nowvlan;
	if (!(pflag & FSTP_TAG)) return;
	nowvlan=(fsttab[vlan]->rootport==0)?0:now; /* This switch is the root */
	if (ba_check(fsttab[vlan]->untag,port)) {
		memcpy(outpacket.stp_root,fsttab[vlan]->root,SWITCHID_LEN);
		memcpy(outpacket.stp_rootcost,fsttab[vlan]->rootcost,4);
		age=nowvlan-fsttab[vlan]->roottimestamp;
		if (age > 0xffff) age=0xffff;
		outpacket.stp_age[0] = age;
		outpacket.stp_age[1] = age>>8;
		outpacket.stp_fwddelay[0] = 0;
		outpacket.stp_fwddelay[1] = 0; /* XXX */
		outpacket.stp_port[0]=0x80| (port>>4);
		outpacket.stp_port[1]=port;
		outpacket.stp_flags=STP_FLAGS(vlan,port,agr,tc,tcack);
		port_send_packet(port,&outpacket,sizeof(outpacket));
	} 
	if (ba_check(fsttab[vlan]->tagged,port)) {
		memcpy(outtagpacket.stp_root,fsttab[vlan]->root,SWITCHID_LEN);
		memcpy(outtagpacket.stp_rootcost,fsttab[vlan]->rootcost,4);
		age=nowvlan-fsttab[vlan]->roottimestamp;
		if (age > 0xffff) age=0xffff;
		outtagpacket.stp_age[0]=age;
		outtagpacket.stp_age[1]=age>>8;
		outtagpacket.stp_fwddelay[0]=0;
		outtagpacket.stp_fwddelay[1]=0; /* XXX */
		outtagpacket.stp_port[0]=0x80| (port>>4);
		outtagpacket.stp_port[1]=port;
		outtagpacket.tag_vlan[0]=vlan>>8 & 0xf;
		outtagpacket.tag_vlan[1]=vlan;
		outtagpacket.stp_flags=STP_FLAGS(vlan,port,agr,tc,tcack);
		port_send_packet(port,&outtagpacket,sizeof(outtagpacket));
	}
}

/* Topology change flood 
 * two main difference between this and 802.1d/w:
 * - it flushes all the hash table for this vlan (including the "calling" port
 * - do not send all the packet with TC but just this
 */
static void topology_change(int vlan, int genport)
{
	register int port;
	int now=qtime();
	//if (now - fsttab[vlan]->tctime > 2*helloperiod) { /*limit age?*/
	/*printf("TOPOLOGY CHANGE %d\n",vlan);*/
	fsttab[vlan]->tctime=now;
	hash_delete_vlan(vlan);
	ba_FORALL(fsttab[vlan]->untag,numports,
			({ if(port != genport && !(ba_check(fsttab[vlan]->backup,port)) &&
						!(ba_check(fsttab[vlan]->edge,port)) && FSTP_ACTIVE(vlan,port)) {
			 fst_sendbpdu(vlan,port,0,1,0); }
			 }),port);
	ba_FORALL(fsttab[vlan]->tagged,numports,
			({ if(port != genport && !(ba_check(fsttab[vlan]->backup,port)) &&
						!(ba_check(fsttab[vlan]->edge,port)) && FSTP_ACTIVE(vlan,port)) {
			 fst_sendbpdu(vlan,port,0,1,0); }
			 }),port);
	//}
}

/* heart of the fast protocol:
 * 1- receive a proposal
 * 2- stop all the designed ports
 * 3- give back the acknowledge and put the new root in fwd*/
static void fastprotocol(int vlan, int newrootport)
{
  register int port;
	ba_FORALL(fsttab[vlan]->untag,numports,
			({ if(port != newrootport && !(ba_check(fsttab[vlan]->backup,port)) &&
						!(ba_check(fsttab[vlan]->edge,port)) && FSTP_ACTIVE(vlan,port)) {
			 port_set_status(port,vlan,DISCARDING);
			 ba_set(fsttab[vlan]->backup,port);
			 fst_sendbpdu(vlan,port,0,0,0); }
			 }),port);
	ba_FORALL(fsttab[vlan]->tagged,numports,
			({ if(port != newrootport && !(ba_check(fsttab[vlan]->backup,port)) &&
						!(ba_check(fsttab[vlan]->edge,port)) && FSTP_ACTIVE(vlan,port)) {
			 port_set_status(port,vlan,DISCARDING);
			 ba_set(fsttab[vlan]->backup,port);
			 fst_sendbpdu(vlan,port,0,0,0); }
			 }),port);
	ba_clr(fsttab[vlan]->backup,newrootport); /* forward ON */
	port_set_status(newrootport,vlan,FORWARDING);
	fst_sendbpdu(vlan,newrootport,1,0,0);
}

/* handling of bpdu incoming packets */
void fst_in_bpdu(int port, struct packet *inpacket, int len, int vlan, int tagged)
{
	struct fstbpdu *p;
	/* XXX check the header for fake info? */
	struct vlst *v=fsttab[vlan];
	int val,valroot;  
	if (ba_check(fsttab[vlan]->edge,port))
		return;
#ifdef DEBUGOPT
	if (!FSTP_ACTIVE(vlan,port)) {
		 DBGOUT(DBGFSTPPLUS,"Port %04d VLAN %02x:%02x",port,vlan>>8,vlan&0xff);
		 EVENTOUT(DBGFSTPPLUS,port,vlan); 
	}
#endif
	ba_set(fsttab[vlan]->rcvhist[rcvhistindex],port);

	if (tagged) {
		p=(struct fstbpdu *)(((unsigned char *)inpacket)+4);
		len-=4;
	} else 
		p=(struct fstbpdu *)(inpacket);
	if (len < 51 || v==NULL || p->stp_version != 2 || p->stp_type != 2)
		return; /* faulty packet */
	/* this is a topology change packet */
	if (p->stp_flags & STP_TC) 
		topology_change(vlan,port);	
	ltonstring(nstringtol(p->stp_rootcost)+
			          (port_getcost(port)-((port==v->bonusport)?v->bonuscost:0)),
								p->stp_rootcost);
/* compare BPDU */
/* >0 means new root, == 0 root unchanged, <0 sender must change topology */
	if ((val=valroot=memcmp(v->root,p->stp_root,SWITCHID_LEN)) == 0)
		if ((val=memcmp(v->rootcost,p->stp_rootcost,4)) == 0) 
			if ((val=memcmp(v->dessw,p->stp_bridge,SWITCHID_LEN)) == 0)
				val=memcmp(v->port,p->stp_port,2);
	/*printf("VAL = %d root=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
			" recv=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x \n",val,
	fsttab[vlan]->root[0], fsttab[vlan]->root[1], fsttab[vlan]->root[2], fsttab[vlan]->root[3],
	fsttab[vlan]->root[4], fsttab[vlan]->root[5], fsttab[vlan]->root[6], fsttab[vlan]->root[7],
	p->stp_root[0], p->stp_root[1], p->stp_root[2], p->stp_root[3],
	p->stp_root[4], p->stp_root[5], p->stp_root[6], p->stp_root[7]);
	printf("++ stp_bridge=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
			" cost=%02x:%02x:%02x:%02x: port %02x:%02x \n",
	p->stp_bridge[0], p->stp_bridge[1], p->stp_bridge[2], p->stp_bridge[3],
	p->stp_bridge[4], p->stp_bridge[5], p->stp_bridge[6], p->stp_bridge[7],
	p->stp_rootcost[0], p->stp_rootcost[1], p->stp_rootcost[2], p->stp_rootcost[3],
	p->stp_port[0], p->stp_port[1]); */
	if (val == 0) {  /* root unchanged / new root announce*/
		v->roottimestamp=qtime();
	} else { /* new root or new root info*/
		if (val > 0 || (port == fsttab[vlan]->rootport && val<0)) {
			if (memcmp(v->root,outpacket.header.src,8) <= 0) 
				fstnewvlan(vlan);
			/* printf("NEW ROOT\n");*/
			memcpy(v->root,p->stp_root,SWITCHID_LEN);
			memcpy(v->rootcost,p->stp_rootcost,4);
			memcpy(v->dessw,p->stp_bridge,SWITCHID_LEN);
			memcpy(v->port,p->stp_port,2);
			v->rootport=port;
			v->roottimestamp=qtime();
			DBGOUT(DBGFSTPROOT,"Port %04d VLAN %02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
					port,vlan>>8,vlan&0xff,
					v->root[0], v->root[1], v->root[2], v->root[3],
					v->root[4], v->root[5], v->root[6], v->root[7]);
			EVENTOUT(DBGFSTPROOT,port,vlan,v->root);
			fastprotocol(vlan,port);
			topology_change(vlan,port);
		}
		else {
			if (memcmp(v->root,p->stp_root,SWITCHID_LEN) == 0) {
				/* critical point: longer path to root */
				/* root -> designated */
				/* non-root -> blocking */
				if ((p->stp_flags & STP_PORTROLEMASK) == STP_ROOT) {
					if (ba_check(v->backup,port)) {
						/* backup -> designated transition */
						//printf("backup -> designated port %d\n",port);
						ba_clr(v->backup,port); /* forward ON */
						port_set_status(port,vlan,FORWARDING);
						topology_change(vlan,port);
					}
				} else {
					if (!ba_check(v->backup,port)) {
						/* designated -> backup transition */
						//printf("designated ->backup port %d\n",port);
						ba_set(v->backup,port); /* forward OFF */
						port_set_status(port,vlan,DISCARDING);
						topology_change(vlan,port);
					}
				}
			} else {
				/*printf("THIS?\n");*/
				fst_sendbpdu(vlan,port,0,0,0);
			}
		}
	}
}

void fstaddport(int vlan,int port,int tagged)
{
	/*printf("F addport V %d  - P %d  - T%d\n",vlan,port,tagged);*/

	if (tagged) {
		ba_set(fsttab[vlan]->tagged,port);
	  ba_clr(fsttab[vlan]->untag,port);
	} else {
	  ba_set(fsttab[vlan]->untag,port);
		ba_clr(fsttab[vlan]->tagged,port);
	}
	ba_clr(fsttab[vlan]->backup,port);
	ba_clr(fsttab[vlan]->edge,port);
	ba_clr(fsttab[vlan]->rcvhist[0],port);
	ba_clr(fsttab[vlan]->rcvhist[1],port);
	fst_sendbpdu(vlan,port,0,0,0);
	topology_change(vlan,port);
}

void fstdelport(int vlan,int port)
{
	/*printf("F delport V %d  - P %d\n",vlan,port);*/
	if (FSTP_ACTIVE(vlan,port)) {
		 DBGOUT(DBGFSTPMINUS,"Port %04d VLAN %02x:%02x",port,vlan>>8,vlan&0xff);
		 EVENTOUT(DBGFSTPMINUS,port,vlan);
	}
	ba_clr(fsttab[vlan]->untag,port);
	ba_clr(fsttab[vlan]->tagged,port);
	ba_clr(fsttab[vlan]->backup,port);
	ba_clr(fsttab[vlan]->edge,port);
	if (port == fsttab[vlan]->rootport) {
		fstnewvlan(vlan);
	}
	topology_change(vlan,port);
}

static void fstinitpkt(void)
{
	memcpy(outpacket.stp_bridge,myid,SWITCHID_LEN);
	memcpy(outtagpacket.stp_bridge,myid,SWITCHID_LEN);
	memcpy(outpacket.header.src,switchmac,ETH_ALEN);
	memcpy(outtagpacket.header.src,switchmac,ETH_ALEN);
	outpacket.stp_hello[0]=outtagpacket.stp_hello[0]=helloperiod,
	outpacket.stp_hello[1]=outtagpacket.stp_hello[1]=helloperiod>>8,
	outpacket.stp_maxage[0]=outtagpacket.stp_maxage[0]=maxage,
	outpacket.stp_maxage[1]=outtagpacket.stp_maxage[1]=maxage>>8,
	fst_timerno=qtimer_add(helloperiod,0,fst_hello,NULL);
}

static int fstpshowinfo(FILE *fd)
{
	printoutc(fd,"MAC %02x:%02x:%02x:%02x:%02x:%02x Priority %d (0x%x)",
			switchmac[0], switchmac[1], switchmac[2], switchmac[3], switchmac[4], switchmac[5],
			priority,priority);
	printoutc(fd,"FSTP=%s",(pflag & FSTP_TAG)?"true":"false");
	return 0;
}

static void fstnewvlan2(int vlan, void *arg)
{
	fstnewvlan(vlan);
}

void fstpshutdown(void)
{
	if (pflag & FSTP_TAG)
	{
		qtimer_del(fst_timerno);
		fstflag(P_CLRFLAG,FSTP_TAG);
		bac_FORALLFUN(validvlan,NUMOFVLAN,fstnewvlan2,NULL);
	}
}

static int fstpsetonoff(FILE *fd, int val)
{
	int oldval=((pflag & FSTP_TAG) != 0);
	if (portflag(P_GETFLAG, HUB_TAG)){
		printoutc(fd, "Can't use fstp in hub mode");
		return 0;
	}
	val=(val != 0);
	if (oldval != val)
	{
		if (val) { /* START FST */
			fstinitpkt();
			fstflag(P_SETFLAG,FSTP_TAG);
		} else { /* STOP FST */
			qtimer_del(fst_timerno);
			fstflag(P_CLRFLAG,FSTP_TAG);
			bac_FORALLFUN(validvlan,NUMOFVLAN,fstnewvlan2,NULL);
		}
	}
	return 0;
}

static char *decoderole(int vlan, int port)
{
	if (!(ba_check(fsttab[vlan]->untag,port) || ba_check(fsttab[vlan]->untag,port)))
		return "Unknown";
	if (ba_check(fsttab[vlan]->edge,port))
		return "Edge";
	if (fsttab[vlan]->rootport == port)
		return "Root";
	if (ba_check(fsttab[vlan]->backup,port))
		return "Alternate/Backup";
	return "Designated";
}

static void fstprintactive(int vlan,FILE *fd)
{
	register int i;
	printoutc(fd,"FST DATA VLAN %04d %s %s",vlan,
			memcmp(myid,fsttab[vlan]->root,SWITCHID_LEN)==0?"ROOTSWITCH":"",
			((pflag & FSTP_TAG)==0)?"FSTP IS DISABLED":"");
	printoutc(fd, " ++ root %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			fsttab[vlan]->root[0], fsttab[vlan]->root[1], fsttab[vlan]->root[2], fsttab[vlan]->root[3],
			fsttab[vlan]->root[4], fsttab[vlan]->root[5], fsttab[vlan]->root[6], fsttab[vlan]->root[7]);
	printoutc(fd, " ++ designated %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			fsttab[vlan]->dessw[0], fsttab[vlan]->dessw[1], fsttab[vlan]->dessw[2], fsttab[vlan]->dessw[3],
			fsttab[vlan]->dessw[4], fsttab[vlan]->dessw[5], fsttab[vlan]->dessw[6], fsttab[vlan]->dessw[7]);
	printoutc(fd, " ++ rootport %04d cost %d age %d bonusport %04d bonuscost %d",
			fsttab[vlan]->rootport, 
			nstringtol(fsttab[vlan]->rootcost),
			qtime()-fsttab[vlan]->roottimestamp,fsttab[vlan]->bonusport,fsttab[vlan]->bonuscost);
	ba_FORALL(fsttab[vlan]->untag,numports,
			printoutc(fd," -- Port %04d tagged=%d portcost=%d role=%s",i,0,port_getcost(i),decoderole(vlan,i)),i);
	ba_FORALL(fsttab[vlan]->tagged,numports,
			printoutc(fd," -- Port %04d tagged=%d portcost=%d role=%s",i,1,port_getcost(i),decoderole(vlan,i)),i);
}	

static int fstprint(FILE *fd,char *arg)
{
	if (*arg != 0) {
		register int vlan;
		vlan=atoi(arg);
		if (vlan >= 0 && vlan < NUMOFVLAN-1) {
			if (bac_check(validvlan,vlan))
				fstprintactive(vlan,fd);
			else
				return ENXIO;
		} else
			return EINVAL;
	} else
		bac_FORALLFUN(validvlan,NUMOFVLAN,fstprintactive,fd);
	return 0;
}

static int fstsetbonus(char *arg)
{
	int vlan, port, cost;
	if (sscanf(arg,"%i %i %i",&vlan,&port,&cost) != 3)
		return EINVAL;
	if (vlan <0 || vlan >= NUMOFVLAN || port < 0 || port >= numports)
		return EINVAL;
	if (!bac_check(validvlan,vlan)) 
		return ENXIO;
	fsttab[vlan]->bonusport=port;
	fsttab[vlan]->bonuscost=cost;
	return 0;
}

static int fstsetedge(char *arg)
{
	int vlan, port, val;
	if (sscanf(arg,"%i %i %i",&vlan,&port,&val) != 3)
		return EINVAL;
	if (vlan <0 || vlan >= NUMOFVLAN || port < 0 || port >= numports)
		return EINVAL;
	if (!bac_check(validvlan,vlan))
		return ENXIO;
	if (val) {
		ba_set(fsttab[vlan]->edge,port);
		if (ba_check(fsttab[vlan]->untag,port) || ba_check(fsttab[vlan]->untag,port))
			port_set_status(port,vlan,FORWARDING);
	} else {
		ba_clr(fsttab[vlan]->edge,port);
		ba_clr(fsttab[vlan]->backup,port);
	}
	return 0;
}

static struct comlist cl[]={
	{"fstp","============","FAST SPANNING TREE MENU",NULL,NOARG},
	{"fstp/showinfo","","show fstp info",fstpshowinfo,NOARG|WITHFILE},
	{"fstp/setfstp","0/1","Fast spanning tree protocol 1=ON 0=OFF",fstpsetonoff,INTARG|WITHFILE},
	{"fstp/setedge","VLAN PORT 1/0","Define an edge port for a vlan 1=Y 0=N",fstsetedge,STRARG},
	{"fstp/bonus","VLAN PORT COST","set the port bonus for a vlan",fstsetbonus,STRARG},
	{"fstp/print","[N]","print fst data for the defined vlan",fstprint,STRARG|WITHFILE},
};

int fstflag(int op,int f)
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

void fst_init(int initnumports)
{
	numports=initnumports;
	SETFSTID(myid,switchmac,priority);
	if (pflag & FSTP_TAG)
		fstinitpkt();
	ADDCL(cl);
#ifdef DEBUGOPT
	ADDDBGCL(dl);
#endif
}
#endif
