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

/** 
 * @file libvdesnmp.h
 * @brief vde_snmp library documentation
 * @author Filippo Giunchedi
 * @date 2007-11-01
 */

#ifndef _VDE_SNMP_H_
#define _VDE_SNMP_H_

#define debug(...) fprintf(stderr, "%s: ", __FUNCTION__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(NULL)

#define DESC_MAXLEN 255
#define PHYADDR_MAXLEN 17 

#define MAX_MGMT_READ 1024

#define ADMINSTATUS_UP  1
#define ADMINSTATUS_DOWN  2
#define ADMINSTATUS_TESTING  3

#define OPERSTATUS_UP  1
#define OPERSTATUS_DOWN  2
#define OPERSTATUS_TESTING  3
#define OPERSTATUS_UNKNOWN  4
#define OPERSTATUS_DORMANT  5
#define OPERSTATUS_NOTPRESENT  6
#define OPERSTATUS_LOWERLAYERDOWN  7

/* events array, init done in vde_snmp_init() */
#define EVENTS_NUM 2

#define EVENT_PORT_UP 0
#define EVENT_PORT_DOWN 1

/** 
 * @brief Collection of port status 
 */
typedef struct vde_stats {
    int numports;
	struct vde_port_stats *ports;
} vde_stats_t;
 
/** 
 * @brief Enumeration of possible administrative status
 */
typedef enum adminstatus {
    A_UP = ADMINSTATUS_UP,
    A_DOWN = ADMINSTATUS_DOWN,
    A_TESTING = ADMINSTATUS_TESTING
} adminstatus;

/** 
 * @brief Enumeration of possible operational status
 */
typedef enum operstatus {
   O_UP = OPERSTATUS_UP,
   O_DOWN = OPERSTATUS_DOWN,
   O_TESTING = OPERSTATUS_TESTING,
   O_UNKNOWN = OPERSTATUS_UNKNOWN,
   O_DORMANT = OPERSTATUS_DORMANT,
   O_NOTPRESENT = OPERSTATUS_NOTPRESENT,
   O_LOWERLAYERDOWN = OPERSTATUS_LOWERLAYERDOWN
} operstatus;

/** 
 * @brief Representation of traffic going thru a port 
 */
typedef struct traffic {
    long octects;
    long ucastpkts;
    long discards;
    long errors;
    long unknownprotos;
} traffic_t;

/** 
 * @brief Status of a single port 
 */
typedef struct vde_port_stats {
  short active; /* port is active, i.e. shown on port/allprint */
  int index;
  char desc[DESC_MAXLEN];
  int mtu;
  int speed;
  char phyaddress[PHYADDR_MAXLEN];
  adminstatus adminstatus;
  operstatus  operstatus;
  long time_lastchange;
  traffic_t *in;
  traffic_t *out;
} vde_port_stats; 

/** 
 * @brief Initialize vde_snmp structures.
 * 
 * @param standalone if 1 listen for port events and print them on stdout, for testing purposes only 
 * @param sockpath path to VDE management socket
 *
 * @return 0 on success, -1 on error
 */
int vde_snmp_init(char *sockpath);

/** 
 * @brief Get port statistics.
 * 
 * @return pointer to actual port statistics 
 */
vde_stats_t* vde_snmp_get_stats(void);

/** 
 * @brief Collect and update statistics.
 * 
 * @return 0 on success, -1 otherwise 
 */
int vde_snmp_update(void);

/** 
 * @brief Invoke registered event handlers. 
 */
void vde_snmp_event(void);

/** 
 * @brief Get console management file descriptor
 * 
 * @return the file descriptor, -1 on error
 */
int vde_snmp_getfd(void);

/** 
 * @brief Register an event handler for event
 * 
 * @param event the event type, either EVENT_PORT_UP or EVENT_PORT_DOWN 
 * @param (*callback)(int portindex) the pointer to function to be called when the event is received 
 * 
 * @return 0 on success, -1 otherwise 
 */
int vde_snmp_register_callback(int event, int (*callback)(int portindex));

/** 
 * @brief Reset time of last update for port structures
 * 
 * @return 0 on success, -1 otherwise 
 */
int vde_snmp_reset_lastchange(void);

/** 
 * @brief Dump port statistics on stdout
 * 
 * @param stats the port list to be printed 
 */
void vde_snmp_dumpstats(vde_stats_t *stats);

#endif
