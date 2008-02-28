/*
 * Copyright (C) 2007 - Filippo Giunchedi
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include "compat/poll.h"
#include <sys/time.h>
#include <time.h>

#include <libvdesnmp.h>
#include <libvdemgmt.h>
#include <vdeplugin.h>

#ifdef STANDALONE
#define EXIT(i) exit(i)
#else
#define EXIT(i) return(i)
#endif

vde_stats_t *_stats = NULL;

struct vdemgmt *mgmt_conn;
struct vdemgmt_out *mgmt_outbuf;

struct timeval *init_tv;
struct timeval *cur_tv;

int (*events[EVENTS_NUM])(int);

int stats_init(){
    assert( _stats == NULL );
    
    // init struttura
    _stats = malloc(sizeof(vde_stats_t));
    if( _stats == NULL )
        return 0;
    
    // init campi
    _stats->numports = 0;
 
    return 1;
}

#define PORTPRINT(pl)  debug(" port: %d", pl->index); \
        debug("  desc: %s", pl->desc); \
        debug("  mtu: %d", pl->mtu); \
        debug("  speed: %d", pl->speed); \
        debug("  phyaddr: %s", pl->phyaddress); \
        debug("  adminstatus: %d", pl->adminstatus); \
        debug("  operstatus: %d", pl->operstatus); \
		debug("  lastchange: %ld", pl->time_lastchange); \
		debug("   in->ucastpkts: %ld", pl->in->ucastpkts); \
		debug("   in->octects: %ld", pl->in->octects); \
		debug("   out->ucastpkts: %ld", pl->out->ucastpkts); \
		debug("   out->octects: %ld", pl->out->octects); 

/* ths of second between a and b (both struct timeval*) assuming a > b */
#define CSECDIFF(a, b) (   (((a)->tv_sec - (b)->tv_sec) * 100) + (( (a)->tv_usec > (b)->tv_usec ? (a)->tv_usec - (b)->tv_usec : 1000000 - (b)->tv_usec + (a)->tv_usec ) / 10000 )    )

/* return ths of a second from init_tv */
#define CSECINIT() ( CSECDIFF(cur_tv, init_tv) )

#define PORTUP(num) if( _stats->ports[num].operstatus != OPERSTATUS_UP ) { \
				          _stats->ports[num].time_lastchange = CSECINIT(); } \
					debug("portup: %d", num); \
					_stats->ports[num].adminstatus = ADMINSTATUS_UP; \
					_stats->ports[num].operstatus = OPERSTATUS_UP; \
					_stats->ports[num].active = 1;

#define PORTDOWN(num) if( _stats->ports[num].operstatus != OPERSTATUS_DOWN ) { \
				          _stats->ports[num].time_lastchange = CSECINIT(); } \
					  debug("portdown: %d", num); \
					  _stats->ports[num].adminstatus = ADMINSTATUS_DOWN; \
					  _stats->ports[num].operstatus = OPERSTATUS_DOWN; \
					  _stats->ports[num].active = 0;



#define SENDCMD(cmd) memset(mgmt_outbuf, 0, sizeof(struct vdemgmt_out)); if(!mgmt_conn) { errno = ECONNREFUSED; return 0; } vdemgmt_sendcmd(mgmt_conn, cmd, mgmt_outbuf);

int mgmt_init(char *sockpath){
	char *p,*q;
	short countersok=0, numportsok=0;

	mgmt_conn = vdemgmt_open(sockpath);

	if(!mgmt_conn){
		errno = ECONNREFUSED;
		return 0;
	}
	
	mgmt_outbuf=(struct vdemgmt_out *)malloc(sizeof(struct vdemgmt_out));
	if(!mgmt_outbuf){
		errno = ENOMEM;
		return 0;
	}
	
	SENDCMD("port/showinfo");
	
	// FIXME this could be factored into a macro
	q=p=mgmt_outbuf->buf;
	while(p < mgmt_outbuf->buf+mgmt_outbuf->sz){
		if(*p == '\0'){
			if( strcmp(q, "counters=true\n") == 0 )
				countersok=1;

			if( sscanf(q, "Numports=%d\n", &(_stats->numports)) == 1 )
				numportsok=1;

			q=p+1;
		}
		p++;
	}
	
	if( countersok && numportsok )
		return 1;
	
	printf("couldn't parse counters or numports\n");
	return 0;
}

int ports_init(void){
	int i;
	struct vde_port_stats *ps;

	cur_tv = malloc(sizeof(struct timeval));
	init_tv = malloc(sizeof(struct timeval));

	assert(_stats != NULL);
	assert(_stats->numports > 0);

	_stats->ports = (struct vde_port_stats *) malloc(sizeof(struct vde_port_stats) * _stats->numports);

	assert(_stats->ports != NULL);
	
	// ASSUMPTION: this is the same as sysUpTime time 
	gettimeofday(init_tv, NULL);

	for(i=0; i<_stats->numports; i++){
		ps = &(_stats->ports[i]);
		ps->out = malloc(sizeof(traffic_t));
		ps->in = malloc(sizeof(traffic_t));
		assert( ps->in != NULL && ps->out != NULL );
		
		ps->index = 0;
		ps->active = 0;
		// FIXME what sensible values might be for mtu/speed?
		ps->mtu = 0;
		ps->speed = 0;

		ps->adminstatus = ADMINSTATUS_DOWN;
		ps->operstatus = OPERSTATUS_NOTPRESENT;
		// TimeTicks == hundredths of a second
		ps->time_lastchange = init_tv->tv_usec;

		ps->desc[0] = '\0';
		ps->phyaddress[0] = '\0';

		ps->in->octects = 0;
		ps->in->ucastpkts = 0;
		ps->in->discards = 0;
		ps->in->errors = 0;
		ps->in->unknownprotos = 0;
		
		ps->out->octects = 0;
		ps->out->ucastpkts = 0;
		ps->out->discards = 0;
		ps->out->errors = 0;
		ps->out->unknownprotos = 0;
	}
	return 1;
}

// FIXME mac address info from hash/print is missing
// Hash: 0105 Addr: ae:4a:3c:e1:6e:c9 VLAN 0000 to port: 001  age 3 secs
int counters_parse(void){
	char *p,*q;

	char portstatus[10];
	int i, curport=0;
	char portdesc[DESC_MAXLEN];

	short inport=0, outok=0, inok=0;
	
	struct vde_port_stats *pl;

	// FIXME are these types large enough?
	long inbytes, inpkts;
	long outbytes, outpkts;

	memset(portdesc, '\0', DESC_MAXLEN);

	if(!mgmt_conn){
		printf("error initializing connection, is vde running?\n");
		return 0;
	}

	assert(_stats->ports != NULL);

	for(i=0; i < _stats->numports; i++){
		_stats->ports[i].active = 0;
	}

	SENDCMD("port/allprint");
	
	q=p=mgmt_outbuf->buf;
	while(p < mgmt_outbuf->buf+mgmt_outbuf->sz){
		if(*p == '\0'){

			/* Port 0001 untagged_vlan=0000 INACTIVE - Unnamed Allocatable */
			if( sscanf(q, "Port %4d %*s %s - %*s\n", &curport, portstatus) == 2 )
				inport=1;
			
			if( inport ){
				if( sscanf(q, " IN: pkts %ld bytes %ld\n", &inpkts, &inbytes) == 2 )
					inok = 1;

				if( sscanf(q, " OUT: pkts %ld bytes %ld\n", &outpkts, &outbytes) == 2 )
					outok = 1;

				/*   -- endpoint ID 0005 module unix prog   : vde_plug: user=godog PID=22006  SOCK=/tmp/vde.ctl.22006-00000 */
				/* format from port.c:print_port() however there's room for DESC_MAXLEN bytes in portdesc */
				if( (sscanf(q, "  -- endpoint ID %*04d module %*12c: %255c\n", portdesc) == 1) ||
						( (strncmp(portstatus, "INACTIVE", 8) == 0) && inok && outok ) ){

					gettimeofday(cur_tv, NULL);
					
					pl = &(_stats->ports[curport-1]);

					pl->active = 1;
					pl->index = curport;
					pl->in->octects = inbytes;
					pl->in->ucastpkts = inpkts;
					pl->out->octects = outbytes;
					pl->out->ucastpkts = outpkts;

					// FIXME we do not (yet) know the admin status since it is the
					// "preferred status", i.e. the one wanted by user
					if( strncmp(portstatus, "INACTIVE", 8) == 0 ){
						PORTDOWN(curport-1);
					} else if( strncmp(portstatus, "ACTIVE", 6) == 0 ){
						PORTUP(curport-1);
						strncpy(pl->desc, portdesc, strlen(portdesc)-1);
					}

					inpkts = inbytes = outpkts = outbytes = 0;
					inok = outok = 0;
					inport=0;

					PORTPRINT(pl);
				}
			} /* if( inport ) */			
			
			q=p+1;
		} /* if(*p == '\0') */
		p++;
	} /* while(p < mgmt_outbuf->buf+mgmt_outbuf->sz){ */

	return 0;
}

void port_debug_handler(const char *event, const int tag, const char *data){
	int portnum=0;
	char *i, *j;
	char tmpstr[DESC_MAXLEN];
	
	memset(tmpstr, '\0', DESC_MAXLEN);
	
	gettimeofday(cur_tv, NULL);

	//printf("received: %s -- %d -- %s\n", event, tag, data);

	switch(tag){
		case D_PORT|D_DESCR:
			if( sscanf(data, "/descr Port %02d", &portnum) == 1 ){
				debug("parsed port %d\n", portnum);
			}

			i = index(data, '"');
			j = rindex(data, '"');
			if( i && j && j > i && portnum ){
				strncpy(tmpstr, i+1, j - i );
				strncpy(_stats->ports[portnum-1].desc, tmpstr, DESC_MAXLEN);
			}
			debug("parsed descr[%p %p]: %s", i, j, tmpstr);
		break;

		case D_EP|D_MINUS:
			debug("ENDPOINT MINUS\n");
			if( sscanf(data, "ep/- Port %02d", &portnum) == 1 ){
				PORTDOWN(portnum-1);
				if(events[EVENT_PORT_DOWN])
					events[EVENT_PORT_DOWN](portnum-1);
			}
		break;

		case D_EP|D_PLUS:
			debug("ENDPOINT PLUS\n");
			if( sscanf(data, "ep/+ Port %02d", &portnum) == 1 ){
				PORTUP(portnum-1);
				if(events[EVENT_PORT_UP])
					events[EVENT_PORT_UP](portnum-1);
			}
		break;
		
		case D_PORT|D_MINUS:
			debug("PORT MINUS\n");
			if( sscanf(data, "/- %02d", &portnum) == 1 ){
				PORTDOWN(portnum-1);
			}
		break;

		case D_PORT|D_PLUS:
			debug("PORT PLUS\n");
			if( sscanf(data, "/+ %02d", &portnum) == 1 ){
				PORTUP(portnum-1);
			}
		break;
	}
}

int vde_snmp_reset_lastchange(){
	return gettimeofday(init_tv, NULL);
}

int vde_snmp_update(){
	return counters_parse();
}

int vde_snmp_init(char *sockpath){

	if( !stats_init() ){
		debug("couldn't stats_init\n");
		return -1;
	}

	if( !mgmt_init(sockpath) ){
		debug("couldn't mgmt_init\n");
		return -1;
	}

	if( vdemgmt_asyncreg(mgmt_conn, "port", port_debug_handler) != 0 ){
		return -1;
	}
	
	events[EVENT_PORT_UP] = NULL;
	events[EVENT_PORT_DOWN] = NULL;

	if( !ports_init() ){
		debug("couldn't ports_init\n");
		return -1;
	}

//	vde_snmp_dumpstats(_stats);

#ifdef STANDALONE
	counters_parse();
#else
	return counters_parse();
#endif

	/*vdemgmt_rstout(mgmt_outbuf);*/
	/*vdemgmt_sendcmd(mgmt_conn, "debug/list", mgmt_outbuf);*/
	/*write(1, mgmt_outbuf->buf, mgmt_outbuf->sz);*/

	/* standalone mode, only print port events */
	while(1){
		struct pollfd pfd={vdemgmt_getfd(mgmt_conn), POLLIN, 0};
		poll(&pfd,1,-1);
		vdemgmt_asyncrecv(mgmt_conn);
		PORTPRINT((&(_stats->ports[0])));
	}
}

// FIXME vde_snmp_close() is missing

vde_stats_t* vde_snmp_get_stats(){
    return _stats;
}

void vde_snmp_dumpstats(vde_stats_t *stats){
    int i;
	struct vde_port_stats *pl;

    assert( stats != NULL );
    
    debug("numports: %d", stats->numports);
   
    assert( stats->ports != NULL);
	
	for(i=0; i < stats->numports; i++){
		pl = &(stats->ports[i]);
		PORTPRINT(pl);
    }
}

int vde_snmp_getfd(){
	assert(mgmt_conn != NULL );
	return vdemgmt_getfd(mgmt_conn);
}

void vde_snmp_event(){
	assert(mgmt_conn != NULL );
	vdemgmt_asyncrecv(mgmt_conn);
}

// TODO support more than one callback per event type
int vde_snmp_register_callback(int event, int (*callback)(int portindex)){
	if( event < 0 || event >= EVENTS_NUM ){
		errno = ENOENT;
		return -1;
	}

	events[event] = callback;

	return 0;
}
