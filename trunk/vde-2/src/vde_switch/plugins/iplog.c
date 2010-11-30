/*   This is part of VDE Virtual Distributed Internet
 *
 *   iplog: ip logging plugin for vde_switch
 *   
 *   Copyright 2010 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
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
 */

/* XXX missing:
	 search ip
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>

#include <config.h>
#include <vde.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <pwd.h>
#include <ctype.h>

#include <vdecommon.h>

#include <vdeplugin.h>

static char *logfile;
static int logfilefd=-1;

#define D_LOGIP 0300 
static struct dbgcl dl[]= {
	{"iplog/newip","show new ip addresses",D_LOGIP|D_PLUS},
};
#define D_LOGIP_NEWIP (dl)

/* lists of ip ranges to log */
struct ip4logaddr {
	struct ip4logaddr *next;
	uint32_t addr;
	uint32_t mask;
};

struct ip6logaddr {
	struct ip6logaddr *next;
	uint32_t addr[4];
	uint32_t mask[4];
};

struct ip4logaddr *ip4loghead;
struct ip6logaddr *ip6loghead;

/* packet header structure layer 2 and 3*/
#define ETH_ALEN 6
struct header {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

union body {
	struct {
		unsigned char version;
		unsigned char filler[11];
		unsigned char ip4src[4];
		unsigned char ip4dst[4];
	} v4;
	struct {
		unsigned char version;
		unsigned char filler[7];
		unsigned char ip6src[16];
		unsigned char ip6dst[16];
	} v6;
	struct {
		unsigned char priovlan[2];
	} vlan;
};

/* vde plugin data */
struct plugin vde_plugin_data={
	.name="iplog",
	.help="log ip/port/user assignment",
};

/* translate ipv4 ipv6 addresses into strings for logging */
static inline int ip42string(uint32_t *addr, char *hostname, unsigned int len)
{
	struct sockaddr_in ip4addr;
	ip4addr.sin_family=AF_INET;
	ip4addr.sin_port=0;
	ip4addr.sin_addr.s_addr = *addr;
	return getnameinfo((struct sockaddr *)&ip4addr,sizeof(ip4addr),
			hostname,len,NULL,0,NI_NUMERICHOST);
}

static inline int ip62string(uint32_t *addr, char *hostname, unsigned int len)
{
	struct sockaddr_in6 ip6addr;
	ip6addr.sin6_family=AF_INET6;
	ip6addr.sin6_port=0;
	ip6addr.sin6_flowinfo=0;
	ip6addr.sin6_scope_id=0;
	memcpy(&ip6addr.sin6_addr.s6_addr,addr,16);
	return getnameinfo((struct sockaddr *)&ip6addr,sizeof(ip6addr),
			hostname,len,NULL,0,NI_NUMERICHOST);
}

/* hash table of recently seen ip addresses, collision lists are double linked */
#define IP_HASH_SIZE 1024

struct ip_hash_entry {
	struct ip_hash_entry *next;
	struct ip_hash_entry **prev;
	time_t last_seen;
	int port;
	short vlan;
	short len;
	unsigned char ipaddr[4];
};

static struct ip_hash_entry **iph;

static inline int ip_hash(int len,unsigned char *addr)
{
	if (len == 4)
		return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]) % IP_HASH_SIZE);
	else
		return((addr[0]+2*addr[1]+3*addr[2]+5*addr[3]+
				7*addr[4]+11*addr[5]+13*addr[6]+17*addr[7]+
				19*addr[8]+23*addr[9]+29*addr[10]+31*addr[11]+
				37*addr[12]+41*addr[13]+43*addr[14]+47*addr[15]) % IP_HASH_SIZE);
}

/* search ip address into the hash tacle and add it if it does not exist.
	 log each new item added */
static void ip_find_in_hash_update(int len,unsigned char *addr,int vlan,int port)
{
	struct ip_hash_entry *e;
	int k = ip_hash(len, addr);
	time_t now;
	for(e = iph[k]; e && memcmp(e->ipaddr, addr, len) && e->len == len && 
			e->vlan == vlan; e = e->next)
		;
	if(e == NULL) {
		e = (struct ip_hash_entry *) malloc(sizeof(*e)+(len-4));
		if(e == NULL){
			printlog(LOG_WARNING,"Failed to malloc ip_hash entry %s",strerror(errno));
			return;
		}
		memcpy(e->ipaddr, addr, len);
		if(iph[k] != NULL) iph[k]->prev = &(e->next);
		e->next = iph[k];
		e->prev = &(iph[k]);
		e->vlan = vlan;
		e->len = len;
		e->port = -1;
		iph[k] = e;
	} 
	now=qtime();
	e->last_seen = now;
	if(e->port != port) {
		e->port=port;
		char hostname[100];
		char msg[256];
		char lf[]="\n";
		struct iovec iov[]={{msg,0},{lf,1}};

		if ((len==4 && ip42string((uint32_t *)addr,hostname,sizeof(hostname))==0) ||
				(len==16 && ip62string((uint32_t *)addr,hostname,sizeof(hostname))==0)) {
			struct passwd *pwd;
			char *username;
			if ((pwd=getpwuid(port_user(port))) == NULL)
				username="(none)";
			else
				username=pwd->pw_name;
			iov[0].iov_len=snprintf(msg,sizeof(msg),"ipv%d %s port=%d user=%s",
					(len==4)?4:6, hostname, port, username);
			if (logfilefd >= 0)
				writev(logfilefd,iov,2);
			else if (logfilefd != -1) 
				syslog(LOG_INFO, msg);
			DBGOUT(D_LOGIP_NEWIP,"%s",msg);
		}
	}
}

/* pass through the hash table and execute function f for each element */
static void ip_for_all_hash(void (*f)(struct ip_hash_entry *, void *), void *arg)
{
	int i;
	struct ip_hash_entry *e, *next;

	for(i = 0; i < IP_HASH_SIZE; i++){
		for(e = iph[i]; e; e = next){
			next = e->next;
			(*f)(e, arg);
		}
	}
}

/* delete a hash table entry */
static inline void delete_hash_entry(struct ip_hash_entry *old) 
{
	*((old)->prev)=(old)->next; 
	if((old)->next != NULL) (old)->next->prev = (old)->prev;
		free((old)); 
}


#define IP_GC_INTERVAL 10
#define IP_GC_EXPIRE 360
static int ip_gc_interval=IP_GC_INTERVAL;
static int ip_gc_expire=IP_GC_EXPIRE;
static unsigned int ip_gc_timerno;

/* clean from the hash table entries older than IP_GC_EXPIRE seconds, given that
 * 'now' points to a time_t structure describing the current time */
static void ip_gc(struct ip_hash_entry *e, void *expiretime)
{
	if(e->last_seen <= *((time_t *)expiretime))
		delete_hash_entry(e);
}

/* clean old entries in the hash table 'h', and prepare the timer to be called
	  * again between GC_INTERVAL seconds */
static void ip_hash_gc(void *arg)
{
	time_t t = qtime() - ip_gc_expire;
	ip_for_all_hash(ip_gc, &t);
}

/* delete all ip address on a specific port (when the port is closed) */
static void port_gc(struct ip_hash_entry *e, void *arg)
{
	int *port=arg;
	if(*port == e->port)
		delete_hash_entry(e);
}

/* upcall from vde: new incomping packet */
#define UINT32(X) (((uint32_t *)&(X)))
static int iplog_pktin(struct dbgcl *event,void *arg,va_list v)
{
	int vlan=0;
	int port=va_arg(v,int);
	unsigned char *buf=va_arg(v,unsigned char *);
	//int len=va_arg(v,int);
	struct header *ph=(struct header *) buf;
	union body *pb=(union body *)(ph+1);
	//fprintf(stderr,"packet from port %d len %d\n",port,len);
	if (ph->proto[0]==0x81 && ph->proto[1]==0x00) { /*VLAN*/
		vlan=((pb->vlan.priovlan[0] << 8) + pb->vlan.priovlan[1]) & 0xfff;
		ph=(struct header *)(((char *)ph)+4);
		pb=(union body *)(((char *)pb)+4);
	}
	if (ph->proto[0]==0x08 && ph->proto[1]==0x00 &&
			pb->v4.version == 0x45) {
		/*v4 */
		struct ip4logaddr *ip4scan;
		/* is the packet in one of the logged ranges? */
		for (ip4scan=ip4loghead; ip4scan!=NULL; ip4scan=ip4scan->next) {
			/*printf("%x %x %x\n",UINT32(pb->v4.ip4src[0]) , ip4scan->mask ,
				ip4scan->addr);*/
			uint32_t *addr=UINT32(pb->v4.ip4src[0]);
			if ((addr[0] & ip4scan->mask) ==
					ip4scan->addr) {
				ip_find_in_hash_update(4,pb->v4.ip4src,vlan,port);
				break;
			}
		}
	}
	else if (ph->proto[0]==0x86 && ph->proto[1]==0xdd &&
			pb->v4.version == 0x60) {
		/*v6 */
		struct ip6logaddr *ip6scan;
		/* is the packet in one of the logged ranges? */
		for (ip6scan=ip6loghead; ip6scan!=NULL; ip6scan=ip6scan->next) {
			/*printf("%x %x %x:",UINT32(pb->v6.ip6src[0]) , ip6scan->mask[0] , ip6scan->addr[0]);
				printf("%x %x %x:",UINT32(pb->v6.ip6src[4]) , ip6scan->mask[1] , ip6scan->addr[1]);
				printf("%x %x %x:",UINT32(pb->v6.ip6src[8]) , ip6scan->mask[2] , ip6scan->addr[2]);
				printf("%x %x %x:",UINT32(pb->v6.ip6src[12]) , ip6scan->mask[3] , ip6scan->addr[3]);
				printf("\n");*/
			uint32_t *addr=UINT32(pb->v6.ip6src[0]);
			if (
					((addr[0] & ip6scan->mask[0]) == ip6scan->addr[0]) &&
					((addr[1] & ip6scan->mask[1]) == ip6scan->addr[1]) &&
					((addr[2] & ip6scan->mask[2]) == ip6scan->addr[2]) &&
					((addr[3] & ip6scan->mask[3]) == ip6scan->addr[3])
				 )
			{
				ip_find_in_hash_update(16,pb->v6.ip6src,vlan,port);
				break;
			}
		}
	}
	return 0;
}

/* upcall from vde: a port has been closed */
static int iplog_port_minus(struct dbgcl *event,void *arg,va_list v)
{
	int port=va_arg(v,int);
	ip_for_all_hash(&port_gc, &port);
	return 0;
}

/*user interface: chowinfo */
static int ipshowinfo(FILE *fd)
{
	printoutc(fd,"iplog: ip/port/user loggin plugin");
	if (logfilefd<0) {
		if (logfilefd == -1) 
			printoutc(fd,"log disabled");
		else
			printoutc(fd,"log on syslog");
	} else
		printoutc(fd,"log on file %s",logfile);
	printoutc(fd,"GC interval %d secs",ip_gc_interval);
	printoutc(fd,"GC expire %d secs",ip_gc_expire);
	return 0;
}

/* close the old log file */
static void closelogfile(void)
{
	if (logfilefd >= 0)
		close(logfilefd);
	if (logfile != NULL)
		free(logfile);
}

/* change the log file */
static int iplogfile(char *arg)
{
	if (*arg) {
		if (strcmp(arg,"-")==0) {
			closelogfile();
			logfilefd=-2;
			return 0;
		} else {
			int fd;
			fd=open(arg,O_CREAT|O_WRONLY|O_APPEND,0600);
			if (fd>=0) {
				char abspath[PATH_MAX];
				closelogfile();
				logfilefd=fd;
				vde_realpath(arg,abspath);
				logfile=strdup(abspath);
				return 0;
			} else 
				return ENOENT;
		}
	} else
		return EINVAL;
}

/* add a v4 range (recursive) */
static int iplog4radd(struct ip4logaddr **ph, uint32_t addr, uint32_t mask)
{
	if (*ph == NULL) {
		*ph=malloc(sizeof(struct ip4logaddr));
		if (*ph==NULL)
			return ENOMEM;
		else {
			(*ph)->next=NULL;
			(*ph)->addr=addr;
			(*ph)->mask=mask;
			return 0;
		}
	} else {
		if ((*ph)->addr==addr && (*ph)->mask==mask)
			return EEXIST;
		else
			return iplog4radd(&((*ph)->next),addr,mask);
	}
}

/* add a v6 range (recursive) */
static int iplog6radd(struct ip6logaddr **ph, uint32_t addr[4], uint32_t mask[4])
{
	if (*ph == NULL) {
		*ph=malloc(sizeof(struct ip6logaddr));
		if (*ph==NULL)
			return ENOMEM;
		else {
			(*ph)->next=NULL;
			memcpy((void *)((*ph)->addr),addr,16);
			memcpy((void *)((*ph)->mask),mask,16);
			return 0;
		}
	} else {
		if (memcmp(&((*ph)->addr),addr,16) == 0 &&
			memcmp(&((*ph)->mask),mask,16) == 0)
			return EEXIST;
		else
			return iplog6radd(&((*ph)->next),addr,mask);
	}
}

/* delete a v4 range (recursive) */
static int iplog4rdel(struct ip4logaddr **ph, uint32_t addr, uint32_t mask)
{
	if (*ph == NULL) {
		return ENOENT;
	} else {
		if ((*ph)->addr==addr && (*ph)->mask==mask) {
			struct ip4logaddr *this=*ph;
			*ph=(*ph)->next;
			free(this);
			return 0;
		} else
			return iplog4rdel(&((*ph)->next),addr,mask);
	}
}

/* delete a v6 range (recursive) */
static int iplog6rdel(struct ip6logaddr **ph, uint32_t addr[4], uint32_t mask[4])
{
	if (*ph == NULL) {
		return ENOENT;
	} else {
		if (memcmp(&((*ph)->addr),addr,16) == 0 &&
			memcmp(&((*ph)->mask),mask,16) == 0) {
			struct ip6logaddr *this=*ph;
			*ph=(*ph)->next;
			free(this);
			return 0;
		} else
			return iplog6rdel(&((*ph)->next),addr,mask);
	}
}

/* create a mask from the number of bits */
static void n2mask(int len,int n, uint32_t *out)
{
	char m[len];
	int i;
	for (i=0;i<len;i++,n-=8) {
		if (n>=8)
			m[i]=0xff;
		else if (n>0)
			m[i]=~((1<<(8-n))-1);
		else
			m[i]=0;
	}
	len=(len+sizeof(uint32_t)-1)/sizeof(uint32_t);
	for (i=0;i<len;i++)
		out[i]=*(((uint32_t *)m)+i);
}

/* cumpute the number of bits from a mask */
static int mask2n(int len, void *addr)
{
	char *m=addr;
	int n=0;
	int i,sm;
	for (i=0;i<len;i++) {
		for (sm=0x80;sm!=0;sm>>=1) {
			if (m[i] & sm)
				n++;
			else
				return n;
		}
	}
	return n;
}

/* convert an ipv4 or ipv6 address into addr/mask */
static int char2addr_mask(char *arg, uint32_t *addr, uint32_t *mask)
{
	struct addrinfo *ai;
	char *smask=strrchr(arg,'/');
	int len;
	if (smask != NULL) {
		*smask=0;
		smask++;
	}
	if (getaddrinfo(arg,NULL,NULL,&ai) != 0)
		return -1;
	else {
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *ip4addr=(struct sockaddr_in *) ai->ai_addr;
			len=4;
			if (smask != NULL)
				n2mask(len,atoi(smask),mask);
			else
				n2mask(len,32,mask);
			addr[0]=ip4addr->sin_addr.s_addr & mask[0];
		} else if (ai->ai_family == AF_INET6) {
			int i;
			struct sockaddr_in6 *ip6addr=(struct sockaddr_in6 *) ai->ai_addr;
			len=16;
			if (smask != NULL)
				n2mask(len,atoi(smask),mask);
			else
				n2mask(len,128,mask);
			for (i=0;i<4;i++)
				addr[i]=*(((uint32_t *)ip6addr->sin6_addr.s6_addr)+i) & mask[i];
		} else
			len=-1;
		freeaddrinfo(ai);
		return len;
	}
}

/* user interface: add an ipv4 or ipv6 range */
static int iplogadd(char *arg)
{
	uint32_t addr[4],mask[4];
	int len=char2addr_mask(arg,addr,mask);
	if (len == 4)
		return iplog4radd(&ip4loghead,addr[0],mask[0]);
	else if (len == 16)
		return iplog6radd(&ip6loghead,addr,mask);
	else 
		return EINVAL;
}

/* user interface: delete an ipv4 or ipv6 range */
static int iplogdel(char *arg)
{
	uint32_t addr[4],mask[4];
	int len=char2addr_mask(arg,addr,mask);
	if (len == 4)
		return iplog4rdel(&ip4loghead,addr[0],mask[0]);
	else if (len == 16)
		return iplog6rdel(&ip6loghead,addr,mask);
	else
		return EINVAL;
}

/* list the ipv4 ranges */
static void iplog4rlist(struct ip4logaddr *ph, FILE *fd)
{
	if (ph != NULL) {
		char hostname[20];
		if (ip42string(&ph->addr,hostname,sizeof(hostname)) == 0) 
			printoutc(fd,"  ipv4: %s/%d",hostname,mask2n(4,&ph->mask));
		iplog4rlist(ph->next,fd);
	}
}

/* list the ipv6 ranges */
static void iplog6rlist(struct ip6logaddr *ph, FILE *fd)
{
	if (ph != NULL) {
		char hostname[100];
		if (ip62string(ph->addr,hostname,sizeof(hostname)) == 0) 
			printoutc(fd,"  ipv6: %s/%d",hostname,mask2n(16,&ph->mask));
		iplog6rlist(ph->next,fd);
	}
}

/* user interfaces list the ip ranges (v4 and v6)*/
static int iploglist(FILE *fd)
{
	iplog4rlist(ip4loghead,fd);
	iplog6rlist(ip6loghead,fd);
	return 0;
}

/* user interfaces set the garbage collection interval*/
int iplog_set_gc_interval(int p)
{
	qtimer_del(ip_gc_timerno);
	ip_gc_interval=p;
	ip_gc_timerno=qtimer_add(ip_gc_interval,0,ip_hash_gc,NULL);
	return 0;
}

/* user interfaces set the expire interval*/
int iplog_set_gc_expire(int e)
{
	ip_gc_expire=e;
	return 0;
}

/* print an item of the recent ip hash table */
static void iplog_iplist_item(struct ip_hash_entry *e, void *arg)
{
	FILE *fd=arg;
	char hostname[100];
	if ((e->len==4 && ip42string((uint32_t *)e->ipaddr,hostname,sizeof(hostname))==0) ||
			(e->len==16 && ip62string((uint32_t *)e->ipaddr,hostname,sizeof(hostname))==0)) {
		struct passwd *pwd;
		char *username;
		if ((pwd=getpwuid(port_user(e->port))) == NULL)
			username="(none)";
		else
			username=pwd->pw_name;
		printoutc(fd,"ipv%d %s port=%d user=%s", (e->len==4)?4:6, hostname, e->port, username);
	}
}

/* user interface: list all the ip addresses in the hash table */
static int iplog_iplist(FILE *fd)
{
	ip_for_all_hash(iplog_iplist_item, fd);
	return 0;
}

/* user interface: list the ip addresses on a specific port */
struct ipport_data {
	FILE *fd;
	int port;
};

static void iplog_ipport_item(struct ip_hash_entry *e, void *arg)
{
	struct ipport_data *pipd=arg;
	if (e->port == pipd->port)
		iplog_iplist_item(e,pipd->fd);
}

static int iplog_ipport(FILE *fd,int port)
{
	struct ipport_data ipd={fd, port};
	ip_for_all_hash(iplog_ipport_item, &ipd);
	return 0;
}

/* user interface: list the ip addresses of a specific user */
struct ipuser_data {
	FILE *fd;
	uid_t user;
};

static void iplog_ipuser_item(struct ip_hash_entry *e, void *arg)
{
	struct ipuser_data *piud=arg;
	if (port_user(e->port) == piud->user)
		iplog_iplist_item(e,piud->fd);
}

static int iplog_ipuser(FILE *fd,char *user)
{
	struct passwd *pwd;
	struct ipuser_data iud={.fd=fd};
	if (user==NULL || *user==0)
		return EINVAL;
	if (isdigit(*user))
		pwd=getpwuid(atoi(user));
	else
		pwd=getpwnam(user);
	if (pwd == NULL)
		return EINVAL;
	iud.user=pwd->pw_uid;
	ip_for_all_hash(iplog_ipuser_item, &iud);
	return 0;
}

/* user interface: search an ip address in the hash table */
static void iplog_ipsearch_item(int len,unsigned char *addr, FILE *fd)
{
	struct ip_hash_entry *e;
	int k = ip_hash(len, addr);
	for(e = iph[k]; e && memcmp(e->ipaddr, addr, len) && e->len == len; e = e->next)
		;
	if(e != NULL) 
		iplog_iplist_item(e,fd);
}

static int iplog_ipsearch(FILE *fd,char *addr)
{
	struct addrinfo *ai;
	int rv=0;
	if (addr==NULL || *addr==0)
		    return EINVAL;
	if (getaddrinfo(addr,NULL,NULL,&ai) != 0)
		return EINVAL;
	if (ai->ai_family == AF_INET) {
		struct sockaddr_in *ip4addr=(struct sockaddr_in *) ai->ai_addr;
		iplog_ipsearch_item(4, (unsigned char *) &ip4addr->sin_addr.s_addr, fd);
	} else if (ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *ip6addr=(struct sockaddr_in6 *) ai->ai_addr;
		iplog_ipsearch_item(16, ip6addr->sin6_addr.s6_addr , fd);
	} else 
		return rv=EINVAL;
	freeaddrinfo(ai);
	return rv;
}

/* command list */
static struct comlist cl[]={
	{"iplog","============","IP/Mac/User Logging",NULL,NOARG},
	{"iplog/showinfo","","Show info on logging",ipshowinfo,NOARG|WITHFILE},
	{"iplog/logfile","pathname","Set the logfile",iplogfile,STRARG},
	{"iplog/ipadd","ipaddr/mask","add an ipv4/v6 range",iplogadd,STRARG},
	{"iplog/ipdel","ipaddr/mask","del an ipv6/v6 range",iplogdel,STRARG},
	{"iplog/list","","list ip ranges",iploglist,NOARG|WITHFILE},
	{"iplog/setgcint","N","change garbage collector interval",iplog_set_gc_interval,INTARG},
	{"iplog/setexpire","N","change iplog entries expire time",iplog_set_gc_expire,INTARG},
	{"iplog/iplist","","list active IP",iplog_iplist,NOARG|WITHFILE},
	{"iplog/ipport","port","list active IP on a port",iplog_ipport,INTARG|WITHFILE},
	{"iplog/ipuser","user","list active IP of a user",iplog_ipuser,STRARG|WITHFILE},
	{"iplog/ipsearch","ipaddr","search an IP address",iplog_ipsearch,STRARG|WITHFILE},
};

	static void
	__attribute__ ((constructor))
init (void)
{
	iph=calloc(IP_HASH_SIZE,sizeof(struct ip_hash_entry *));
	ADDCL(cl);
	ADDDBGCL(dl);
	ip_gc_timerno=qtimer_add(ip_gc_interval,0,ip_hash_gc,NULL);
	eventadd(iplog_pktin, "packet/in", NULL);
	eventadd(iplog_port_minus, "port/-", NULL);
	/* XXX add event port/minux  */
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	time_t t = qtime();
	eventdel(iplog_port_minus, "port/-", NULL);
	eventdel(iplog_pktin, "packet/in", NULL);
	qtimer_del(ip_gc_timerno);
	DELCL(cl);
	DELDBGCL(dl);
	ip_for_all_hash(ip_gc, &t);
	free(iph);
}
