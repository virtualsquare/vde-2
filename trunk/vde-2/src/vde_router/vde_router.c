#include "vder_datalink.h"
#include "vde_router.h"
#include "vder_queue.h"
#include "vder_packet.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <libgen.h>


static char *mgmt;
static int mgmtmode=0700;
static char *progname;
#define MAXCMD 128

#define match_input(c, i) ((strncmp(c, i, strlen(c)) == 0) && (strlen(c) == strlen(i)))

extern struct vde_router Router;

static char header[]="\nVDE Router  \n(C) D.Lacamera 2011 - GPLv2\n";
static char prompt[]="\nVDE-Router$ ";

static void printoutc(int fd, const char *format, ...)
{
	va_list arg;
	char outbuf[MAXCMD+1];

	va_start (arg, format);
	vsnprintf(outbuf,MAXCMD,format,arg);
	strcat(outbuf,"\n");
	write(fd,outbuf,strlen(outbuf));
}
static int help(int fd,char *s)
{
	char *nextargs = NULL, *arg;
	arg = strtok_r(s, " ", &nextargs);
	if(!arg) {
		/* No arguments */
		printoutc(fd, "COMMAND      HELP");
		printoutc(fd, "------------ ------------");
		printoutc(fd, "help         print a summary of mgmt commands. Use \"help <command>\" for details.");
		printoutc(fd, "connect      create a new interface connect it to vde socket");
		printoutc(fd, "ifconfig     show/change interface addresses configuration");
		printoutc(fd, "route        show/change routing table");
		printoutc(fd, "queue        show/change outgoing frames queues");
		printoutc(fd, "ipfilter     show/change ip filtering configuration");
		printoutc(fd, "stats        print interface statistics");
		printoutc(fd, "logout       close current management session");
		printoutc(fd, "shutdown     disconnect the vde_router and exit");
		printoutc(fd, "quit         alias for \"shutdown\"");
		return 0;
	} else if (match_input("help",arg)) {
		printoutc(fd, "help         print a summary of mgmt commands.");
		printoutc(fd, "Use \"help <command>\" for details.");
		return 0;
	} else if (match_input("connect",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\tconnect <vde_sock_path> [<macaddress>]");
		printoutc(fd, "Connects to a vde socket at path <vde_sock_path> by creating a new virtual ethernet device.");
		printoutc(fd, "If no <macaddress> is provided, it will be assigned automatically.");
		printoutc(fd, "");
		printoutc(fd, "Examples:");
		printoutc(fd, "connect /var/run/vde.ctl");
		printoutc(fd, "connect /var/run/my_sock.ctl 00:11:22:33:44:55");
		return 0;
	} else if (match_input("ifconfig",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\tifconfig [<devname> [<action> <address> <netmask>]]");
		printoutc(fd, "Show/store IP address configuration. If no <devname> is provided, the default action");
		printoutc(fd, "will be to display the current configuration for all the existing ethernet devices.");
		printoutc(fd, "<action> can be \"add\" or \"del\". If \"add\" is specified, all other arguments are mandatory.");
		printoutc(fd, "If \"del\" is specified, only <address> will be used to search for an existing entry.");
		printoutc(fd, "Each virtual ethernet can be associated to more than one IP addresses. A static route for");
		printoutc(fd, "the resulting neighborhood will be added.");
		printoutc(fd, "");
		printoutc(fd, "Examples:");
		printoutc(fd, "ifconfig");
		printoutc(fd, "ifconfig eth0");
		printoutc(fd, "ifconfig eth1 add 10.0.0.1 255.0.0.0");
		printoutc(fd, "ifconfig eth1 del 10.0.0.1");
		return 0;
	} else if (match_input("route",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\troute [<action> <address> <netmask> [gw <gateway>] [via <interface>] [metric <metric>]]");
		printoutc(fd, "--or--");
		printoutc(fd, "\troute <action> default [address]");
		printoutc(fd, "Show/store routing table information. If no <action> is given, the default behavior is to");
		printoutc(fd, "show the current (full) routing table.");
		printoutc(fd, "<action> can be \"add\" or \"del\". If \"add\" or \"del\" is specified, address and netmask are");
		printoutc(fd, "mandatory, unless the \"default\" keyword is present. \"default\" is used to manage default ");
		printoutc(fd, "gateway entry.");
		printoutc(fd, "");
		printoutc(fd, "Examples:");
		printoutc(fd, "route");
		printoutc(fd, "route add default 10.0.0.254");
		printoutc(fd, "route del default");
		printoutc(fd, "route add 192.168.0.0 255.255.0.0 gw 10.0.0.253 metric 2");
		printoutc(fd, "route add 192.168.1.0 255.255.255.0 via eth2");
		return 0;
	} else if (match_input("queue",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\tqueue [<devname>:<queuename> <policy> <policy_options>]");
		printoutc(fd, "");
		printoutc(fd, "Show/store queuing policy information. If no <action> is specified,");
		printoutc(fd, "the current queue policy and information are displayed, otherwise you need");
		printoutc(fd, "to specify the options for the selected queue.");
		printoutc(fd, "");
		printoutc(fd, "Selecting the queue consists in naming the interface and the associated queue.");
		printoutc(fd, "Every interface has one \":output\" queue and 32 priority queues named from");
		printoutc(fd, "\":prio0\" to \":prio31\".");
		printoutc(fd, "");
		printoutc(fd, "The following policies are available:");
		printoutc(fd, "");
		printoutc(fd, "- 'unlimited' (default).");
		printoutc(fd, "\tthis policy requires no options. It is the default policy, and it will allow");
		printoutc(fd, "\tto enqueue virtually an unlimited amount of data before it is dequeued.");
		printoutc(fd, "");
		printoutc(fd, "- 'fifo' (usage: fifo limit <limit>)");
		printoutc(fd, "\tthis policy will allow at most <limit> bytes to be enqueued, and a tail-drop");
		printoutc(fd, "\twill be adopted to all the exceeding frames when the queue is full.");
		printoutc(fd, "");
		printoutc(fd, "");
		printoutc(fd, "- 'red' (usage: red min <min> max <max> probability <P> limit <limit>)");
		printoutc(fd, "\tthis is the \"Random Early Detection\" queuing policy. It consists of setting");
		printoutc(fd, "\ta dynamic limit to the queue during the enqueue operation. The probability");
		printoutc(fd, "\tof dropping packets during enqueue will be 0 under <min> bytes, then it will ");
		printoutc(fd, "\tincrease linearly to reach <P> between <min> and <max>. Between <max> and <limit>");
		printoutc(fd, "\tit will be <P>. Over the physical limit <limit>, all packets will be dropped (P=1).");
		printoutc(fd, "");
		printoutc(fd, "- 'token' (usage: tbf limit <limit> bitrate <bitrate>");
		printoutc(fd, "\tThis is the \"Token Bucket\" queuing policy, allowing traffic to be dequeued at");
		printoutc(fd, "\tthe specified <bitrate>. Enqueuing will be limited to <limit> bytes, so if the");
		printoutc(fd, "\tqueue is full all the exceeding frames will be dropped.");
		printoutc(fd, "Examples:");
		printoutc(fd, "queue");
		printoutc(fd, "queue eth0:output fifo limit 40000");
		printoutc(fd, "queue eth0:prio3 red min 80000 max 160000 probability 0.1 limit 300000");
		printoutc(fd, "queue eth0:prio15 unlimited");
		return 0;
	} else if (match_input("ipfilter",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\tipfilter [<action> [src <interface>] [from <address> <netmask>]");
		printoutc(fd, "		 [to <address> <netmask>] [proto <proto>] [tos <tos>]");
		printoutc(fd, "		 [sport <sport>] [dport <dport>] <filter_action> [<priority>]]");
		printoutc(fd, "Show/store IP filtering information. If no <action> is specified, ");
		printoutc(fd, "the current ip filtering table is shown, else <action> can be \"add\" or \"del\"");
		printoutc(fd, "If \"add\" is specified, no other argument is mandatory but the <filter_action>.");
		printoutc(fd, "<filter_action> can be one of \"accept\" \"drop\" \"reject\" or \"prio\". Accept is the");
		printoutc(fd, "default behavior. \"reject\" is like \"drop\" except that it will send a icmp packet filtered ");
		printoutc(fd, "towards the source every time the rule is hit. \"prio\" changes the priority of the ");
		printoutc(fd, "packet when it gets inserted to the output queue system, allowing IP-based QoS.");
		printoutc(fd, "When \"prio\" is selected as <filter_action>, the argument <priority> is mandatory.");
		printoutc(fd, "If <del> is specified as <action>, all the arguments must match the previously ");
		printoutc(fd, "inserted rule, except the <filter_action> and the <priority> that get discarded.");
		printoutc(fd, "");
		printoutc(fd, "Please note that the rules will be processed on the inverse order as they were ");
		printoutc(fd, "inserted, so to drop all packets from eth0 except those coming from 10.0.0.3, insert");
		printoutc(fd, "the rules in the followinf order (generic to specific):");
		printoutc(fd, "");
		printoutc(fd, "ipfilter add src eth0 drop");
		printoutc(fd, "ipfilter add src eth0 from 10.0.0.3 255.255.255.255 accept");
		printoutc(fd, "");
		printoutc(fd, "other Examples:");
		printoutc(fd, "");
		printoutc(fd, "ipfilter");
		printoutc(fd, "ipfilter add src eth1 tos 2 to 172.16.0.0 255.255.0.0 prio 7");
		printoutc(fd, "ipfilter del src eth1 tos 2 to 172.16.0.0 255.255.0.0");
		return 0;
	} else if (match_input("stats",arg)) {
		printoutc(fd, "Syntax:");
		printoutc(fd, "\tstats");
		return 0;
	} else if (match_input("logout",arg)) {
		printoutc(fd, "Syntax:");
		return 0;
	} else if (match_input("shutdown",arg)) {
		printoutc(fd, "Syntax:");
		return 0;
	} else if (match_input("quit",arg)) {
		printoutc(fd, "Syntax:");
		return 0;
	} else {
		printoutc(fd, "No help available for %s", arg);
	}
	return ENOENT;
}

static int logout(int fd,char *s)
{
	return EPIPE;
}

static int doshutdown(int fd,char *s)
{
	exit(0);
}

static char *vder_ntoa(uint32_t addr)
{
	struct in_addr a;
	char *res;
	a.s_addr = addr;
	res = inet_ntoa(a);
	return res;
}

static int not_understood(int fd, char *s)
{
	printoutc(fd, "parameter \"%s\" not understood. Try \"help\"", s);
	return EINVAL;
}

static void show_ifconfig(int fd, struct vder_iface *iface)
{
	struct vder_ip4address *addr;
	printoutc(fd, "Interface: eth%d mac:%02x:%02x:%02x:%02x:%02x:%02x sock:%s",
					iface->interface_id, iface->macaddr[0],iface->macaddr[1],iface->macaddr[2],
					iface->macaddr[3],iface->macaddr[4],iface->macaddr[5],
					iface->vde_sock
			 );
	addr = iface->address_list;
	while(addr) {
			char *txt_address, *txt_netmask;
			txt_address = strdup(vder_ntoa(addr->address));
			txt_netmask= strdup(vder_ntoa(addr->netmask));
			printoutc(fd, "\taddress: %s netmask: %s", txt_address, txt_netmask);
			free(txt_address);
			free(txt_netmask);
			addr = addr->next;
	}
}

enum command_action_enum {
	ACTION_DELETE = 0,
	ACTION_ADD,
	ACTION_ADD_DEFAULT,
	ACTION_DEL_DEFAULT
};

static inline int is_unicast(uint32_t addr)
{
	uint32_t h_addr = ntohl(addr);
	if ( (h_addr == 0) ||(h_addr >= 0xe0000000) )
		return 0;
	return 1;
}

static inline int is_netmask(uint32_t addr)
{
	int i;
	uint32_t h_netmask = ntohl(addr), valid_value = 0;
	for (i = 31; i >= 0; i--) {
		valid_value += (1 << i);
		if (h_netmask == valid_value)
			return 1;
	}
	return 0;
}

static inline int not_a_number(char *p)
{
	if (!p)
		return 1; 
	if ((p[0] < '0') || (p[0] > '9'))
		return 1; 
	return 0;
}

static struct vder_iface *select_interface(char *arg)
{
	struct vder_iface *iface, *selected = NULL;;
	int iface_id;


	if (strncmp(arg,"eth",3)) {
		return NULL;
	}

	if (not_a_number(arg + 3))
		return NULL;

	iface_id = strtol(arg + 3, NULL, 10);
	iface = Router.iflist;
	while(iface) {
		if (iface_id == iface->interface_id) {
			selected = iface;
			break;
		}
		iface = iface->next;
	}
	return selected;
}


static int ifconfig(int fd,char *s)
{
	char *nextargs = NULL, *arg;
	struct vder_iface *iface;
	arg = strtok_r(s, " ", &nextargs);
	if(!arg) {
		/* No arguments */
		iface = Router.iflist;
		while(iface) {
			show_ifconfig(fd, iface);
			printoutc(fd, "");
			iface = iface->next;
		}
		return 0;
	} else {
		struct vder_iface *selected;
		struct in_addr temp_address, temp_netmask;
		enum command_action_enum action = -1;
		selected = select_interface(arg);
		if (!selected) {
			printoutc(fd, "Interface %s not found.", arg);
			return ENOENT;
		}
		arg = strtok_r(NULL, " ", &nextargs);
		if (!arg) {
			show_ifconfig(fd, selected);
			return 0;
		}
		if ((!arg) || (strlen(arg) != 3) || ((strncmp(arg, "add", 3) != 0) && (strncmp(arg, "del", 3) != 0))) {
			printoutc(fd, "Invalid action \"%s\".", arg);
			return EINVAL;
		}
		if (strncmp(arg, "del", 3) == 0)
			action = ACTION_DELETE;
		else
			action = ACTION_ADD;

		arg = strtok_r(NULL, " ", &nextargs);
		if (!arg) {
			not_understood(fd, "");
			return EINVAL;
		}
		if (!inet_aton(arg, &temp_address) || !is_unicast(temp_address.s_addr)) {
			printoutc(fd, "Invalid address \"%s\"", arg);
			return EINVAL;
		}
		arg = strtok_r(NULL, " ", &nextargs);
		if (!arg && (action == ACTION_ADD)) {
			printoutc(fd, "Error: parameter 'netmask' required.");
			return EINVAL;
		}
		if ((action == ACTION_ADD) && (!inet_aton(arg, &temp_netmask) || !is_netmask(temp_netmask.s_addr))) {
			printoutc(fd, "Invalid netmask \"%s\"", arg);
			return EINVAL;
		}
		if (action == ACTION_ADD) {
			if (vder_iface_address_add(selected, temp_address.s_addr, temp_netmask.s_addr) != 0)
				return errno;
		} else {
			if (vder_iface_address_del(selected, temp_address.s_addr) != 0)
				return errno;
		}

	}
	return 0;

}

static void show_route(int fd, struct vder_route *ro)
{
	char *dest = strdup(vder_ntoa(ro->dest_addr));
	char *netmask = strdup(vder_ntoa(ro->netmask));
	char *gateway = strdup(vder_ntoa(ro->gateway));
	if (ro->iface)
		printoutc(fd, "destination %s netmask %s gw %s via eth%d metric %d %s", dest, netmask, gateway,
			 ro->iface->interface_id, ro->metric,
			 ro->netmask==0?"default":"");
	else
		printoutc(fd, "destination %s netmask %s gw %s metric %d %s", dest, netmask, gateway,
			 ro->metric,
			 ro->netmask==0?"default":"");


	free(dest);
	free(netmask);
	free(gateway);
}

static int confirmquitplease(int fd,char *s) {
	printoutc(fd, "(did you mean 'quit'?)");
	return EBADRQC;
};

static int route(int fd,char *s)
{
	char *nextargs = NULL, *arg;
	struct vder_route *ro;
	struct vder_iface *selected = NULL;
	struct in_addr temp_address, temp_netmask, temp_gateway;
	int metric = 1;
	enum command_action_enum action = -1;

	arg = strtok_r(s, " ", &nextargs);
	if(!arg) {
		/* No arguments */
		ro = Router.routing_table;
		while(ro) {
			show_route(fd, ro);
			ro = ro->next;
		}
		return 0;
	}

	if ((!arg) || (strlen(arg) != 3) || ((strncmp(arg, "add", 3) != 0) && (strncmp(arg, "del", 3) != 0))) {
		printoutc(fd, "Invalid action \"%s\".", arg);
		return EINVAL;
	}
	if (strncmp(arg, "del", 3) == 0)
		action = ACTION_DELETE;
	else
		action = ACTION_ADD;

	arg = strtok_r(NULL, " ", &nextargs);
	if (!arg) {
		not_understood(fd, "");
		return EINVAL;
	}
	if (match_input("default", arg)) {
		if (action == ACTION_ADD)
			action = ACTION_ADD_DEFAULT;
		if (action == ACTION_DELETE) {
			if (vder_route_del(0, 0, 1))
				return errno;
			else
				return 0;
		}
		arg = strtok_r(NULL, " ", &nextargs);
	}

	if (!inet_aton(arg, &temp_address) || !is_unicast(temp_address.s_addr)) {
		printoutc(fd, "Invalid address \"%s\"", arg);
		return EINVAL;
	}

	if (action == ACTION_ADD_DEFAULT) {
		if (vder_route_add(0, 0, temp_address.s_addr, 1, NULL))
			return errno;
		else
			return 0;
	}

	arg = strtok_r(NULL, " ", &nextargs);
	if (!arg) {
		printoutc(fd, "Error: parameter 'netmask' required.");
		return EINVAL;
	}

	if (!inet_aton(arg, &temp_netmask) || !is_netmask(temp_netmask.s_addr)) {
		printoutc(fd, "Invalid netmask \"%s\"", arg);
		return EINVAL;
	}

	arg = strtok_r(NULL, " ", &nextargs);
	while(arg) {
		if (match_input("via", arg)) {
			arg = strtok_r(NULL, " ", &nextargs);
			selected = select_interface(arg);
			if (!selected)
				return EINVAL;
		} else if (match_input("gw", arg)) {
			arg = strtok_r(NULL, " ", &nextargs);
			if (!inet_aton(arg, &temp_gateway) || !is_unicast(temp_gateway.s_addr)) {
				printoutc(fd, "Invalid gateway \"%s\"", arg);
				return EINVAL;
			}
		} else if (match_input("metric", arg)) {
			arg = strtok_r(NULL, " ", &nextargs);
			metric = atoi(arg);
			if (metric < 1) {
				printoutc(fd, "Invalid metric \"%s\"", arg);
				return EINVAL;
			}
		} else {
			return EINVAL;
		}
		arg = strtok_r(NULL, " ", &nextargs);
	}

	if ((action == ACTION_DELETE) &&
		   (vder_route_del(temp_address.s_addr, temp_netmask.s_addr, metric))) {
			return errno;
	} else if ((action == ACTION_ADD) &&
		   (vder_route_add(temp_address.s_addr, temp_netmask.s_addr, temp_gateway.s_addr, metric, selected))) {
		return errno;
	}
	return 0;
}

const char action_name[4][30] = {"accept", "prio", "reject", "drop" };

static void proto_name(uint8_t proto, char *name)
{
	switch(proto) {
		case IPPROTO_ICMP:
			sprintf(name, "icmp");
			break;
		case IPPROTO_IGMP:
			sprintf(name, "igmp");
			break;
		case IPPROTO_TCP:
			sprintf(name, "tcp");
			break;
		case IPPROTO_UDP:
			sprintf(name, "udp");
			break;
		default:
			sprintf(name, "unknown(%d)", ntohs(proto));
	}
}


static void show_filter(int fd, struct vder_filter *filter)
{
	char *saddr_address = strdup(vder_ntoa(filter->saddr.address));
	char *daddr_address = strdup(vder_ntoa(filter->daddr.address));
	char *saddr_netmask = strdup(vder_ntoa(filter->saddr.netmask));
	char *daddr_netmask = strdup(vder_ntoa(filter->daddr.netmask));
	char source[10] = "any";
	char tos[10] = "any";
	char proto[30] = "any";


	if (filter->src_iface){
		snprintf(source, 10, "eth%d", filter->src_iface->interface_id);
	}
	if (filter->tos >= 0) {
		snprintf(tos, 10, "tos %d", filter->tos);
	}
	if (filter->proto > 0) {
		proto_name(filter->proto, proto);
	}
	printoutc(fd, "[iface: %s] %s:%d/%s -> %s:%d/%s proto %s tos %s verdict: %s Stats: %d packets, %d bytes",
			 source, saddr_address, ntohs(filter->sport), saddr_netmask, daddr_address, ntohs(filter->dport), daddr_netmask, proto, tos,
			 action_name[filter->action], filter->stats_packets, filter->stats_bytes);

	free(saddr_address);
	free(saddr_netmask);
	free(daddr_address);
	free(daddr_netmask);
}


static int filter(int fd,char *s)
{
	struct vder_filter *cur = Router.filtering_table;
	int action;
	struct vder_iface *vif = NULL;
	uint8_t proto = 0;
	struct in_addr s_addr = {0}, s_nm = {0}, d_addr = {0}, d_nm = {0};
	uint16_t sport = 0, dport = 0;
	int tos = -1;
	uint8_t priority = PRIO_BESTEFFORT;
	enum filter_action filter_action = filter_invalid;
	char *nextargs = NULL, *arg;

	arg = strtok_r(s, " ", &nextargs);
	if(!arg) {
		/* No arguments */
		while(cur) {
			show_filter(fd, cur);
			cur = cur->next;
		}
		return 0;
	}

	if ((!arg) || (strlen(arg) != 3) || ((strncmp(arg, "add", 3) != 0) && (strncmp(arg, "del", 3) != 0))) {
		printoutc(fd, "Invalid action \"%s\".", arg);
		return EINVAL;
	}
	if (strncmp(arg, "del", 3) == 0)
		action = ACTION_DELETE;
	else
		action = ACTION_ADD;

	arg = strtok_r(NULL, " ", &nextargs);
	if (!arg) {
		not_understood(fd, "");
		return EINVAL;
	}

	while(arg) {
		if (match_input("src", arg)) {
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			vif = select_interface(arg);
		} else if(match_input("proto", arg)) {
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			if (not_a_number(arg)) {
				if (match_input("tcp", arg))
					proto = IPPROTO_TCP;
				else if (match_input("udp", arg)) 
					proto = IPPROTO_UDP;
				else if (match_input("igmp", arg))
					proto = IPPROTO_IGMP;
				else if (match_input("icmp", arg))
					proto = IPPROTO_ICMP;
				else {
					printoutc(fd, "Invalid protocol \"%s\"", arg);
					return EINVAL;
				}
			} else {
				proto = atoi(arg);
				if (proto <= 0) {
					printoutc(fd, "Invalid protocol \"%s\"", arg);
					return EINVAL;
				}
			}
		} else if (match_input("from",arg)){
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			if (!inet_aton(arg, &s_addr) || !is_unicast(s_addr.s_addr)) {
				printoutc(fd, "Invalid from address \"%s\"", arg);
				return EINVAL;
			}
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg) {
				printoutc(fd, "from address: netmask is required");
				return EINVAL;
			}
			if (!inet_aton(arg, &s_nm) || !is_netmask(s_nm.s_addr)) {
				printoutc(fd, "Invalid netmask \"%s\"", arg);
				return EINVAL;
			}
		} else if (match_input("to",arg)){
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			if (!inet_aton(arg, &d_addr) || !is_unicast(d_addr.s_addr)) {
				printoutc(fd, "Invalid from address \"%s\"", arg);
				return EINVAL;
			}
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg) {
				printoutc(fd, "from address: netmask is required");
				return EINVAL;
			}
			if (!inet_aton(arg, &d_nm) || !is_netmask(d_nm.s_addr)) {
				printoutc(fd, "Invalid netmask \"%s\"", arg);
				return EINVAL;
			}
		} else if (match_input("tos",arg)){
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			tos = atoi(arg);
			if ((tos < 0) || not_a_number(arg)) {
				printoutc(fd, "Invalid tos %s", arg);
				return EINVAL;
			}
		} else if (match_input("sport",arg)){
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			if ((sport < 0) || not_a_number(arg)) {
				printoutc(fd, "Invalid sport %s", arg);
				return EINVAL;
			}
			sport = htons(atoi(arg));
		} else if (match_input("dport",arg)){
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			if (not_a_number(arg)) {
				printoutc(fd, "Invalid dport %s", arg);
				return EINVAL;
			}
			dport = htons(atoi(arg));
		} else if (match_input("prio",arg)){
			if (filter_action != filter_invalid) {
				printoutc(fd, "Invalid double action for filter");
			}
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg)
				return EINVAL;
			priority = atoi(arg);
			if ((priority < 0) || (priority >= PRIO_NUM) || not_a_number(arg)) {
				printoutc(fd, "Invalid priority %s", arg);
				return EINVAL;
			}
			filter_action = filter_priority;
		} else if (match_input("accept",arg)) {
			if (filter_action != filter_invalid) {
				printoutc(fd, "Invalid double action for filter");
			}
			filter_action = filter_accept;
		} else if (match_input("reject",arg)) {
			if (filter_action != filter_invalid) {
				printoutc(fd, "Invalid double action for filter");
			}
			filter_action = filter_reject;
		} else if (match_input("drop",arg)) {
			if (filter_action != filter_invalid) {
				printoutc(fd, "Invalid double action for filter");
			}
			filter_action = filter_drop;
		}
		arg = strtok_r(NULL, " ", &nextargs);
	}
	if ((filter_action == filter_invalid) && (action == ACTION_ADD)) {
		printoutc(fd, "Error: an action is required for filter");
		return EINVAL;
	}
	if (action == ACTION_ADD) {
		if (vder_filter_add(vif, proto, s_addr.s_addr, s_nm.s_addr, d_addr.s_addr, d_nm.s_addr, tos, sport, dport, filter_action, priority))
			return errno;
	} else {
		if (vder_filter_del(vif, proto, s_addr.s_addr, s_nm.s_addr, d_addr.s_addr, d_nm.s_addr, tos, sport, dport))
			return errno;
	}
	return 0;
}


static void fill_queue_info(struct vder_queue *q, char *info)
{
	if(!q)
		return;
	switch(q->policy) {
		case QPOLICY_UNLIMITED:
			snprintf(info, MAXCMD, "unlimited");
			break;
		case QPOLICY_FIFO:
			snprintf(info, MAXCMD, "pfifo limit: %u (%d packets dropped)", 
				q->policy_opt.fifo.limit,
				q->policy_opt.fifo.stats_drop);
			break;
		case QPOLICY_RED:
			snprintf(info, MAXCMD, "red min: %u, max: %u, probability: %lf limit: %u (%d packets dropped, %d packets fired)", 
				q->policy_opt.red.min,
				q->policy_opt.red.max,
				q->policy_opt.red.P,
				q->policy_opt.red.limit,
				q->policy_opt.red.stats_drop,
				q->policy_opt.red.stats_probability_drop
				);
			break;
		case QPOLICY_TOKEN:
			snprintf(info, MAXCMD, "token interval: %llu usec, limit: %u (%u packets dropped)",
				q->policy_opt.token.interval,
				q->policy_opt.token.limit,
				q->policy_opt.token.stats_drop);
			break;
	}
}


static void show_queues(int fd, struct vder_iface *vif)
{
	char ifname[10];
	char queue_info[MAXCMD];
	int i;
	if (!vif)
		return;

	snprintf(ifname, 10, "eth%d", vif->interface_id);

	fill_queue_info(&vif->out_q, queue_info);
	printoutc(fd, "%s:output %s size: %lu", ifname, queue_info, vif->out_q.size);
	for (i = 0; i < 32; i++) {
		fill_queue_info(&vif->prio_q[i], queue_info);
		printoutc(fd, "%s:prio%d %s size: %lu", ifname, i, queue_info, vif->prio_q[i].size);
	}
}


/*!!  Warning  !!*/
/* 0 == ERROR here! */
double get_labeled_arg(int fd, char *label, char **nextargs) {
	char *arg = strtok_r(NULL, " ", nextargs);
	if (!arg) {
		printoutc(fd, "missing parameter '%s'", label);
		return 0.0; //error
	}
	if (!match_input(label, arg)) {
		printoutc(fd, "invalid parameter \"%s\", expecting \"%s\"", arg, label);
		return 0.0; //error
	}
	arg = strtok_r(NULL, " ", nextargs);
	if (not_a_number(arg) && arg[0] != '.') {
		printoutc(fd, "invalid value \"%s\"", arg);
		return 0.0; //error
	}
	return strtod(arg, NULL);
}

static int queue(int fd, char *s)
{
	struct vder_iface *cur = Router.iflist, *selected = NULL;
	struct vder_queue *q;
	char *nextargs, *arg;
	int if_id;
	int prio_id = -1;
	char output_word[MAXCMD] = "";
	enum queue_policy_e newpolicy;

	arg = strtok_r(s, " ", &nextargs);
	if(!arg) {
		/* No arguments */
		while(cur) {
			show_queues(fd, cur);
			cur = cur->next;
		}
		return 0;
	}
	if ((sscanf(arg, "eth%d:prio%d", &if_id, &prio_id) != 2) && (sscanf(arg, "eth%d:%s", &if_id, output_word) != 2))
		return EINVAL;
	else {
		if (prio_id < 0 && !match_input("output", output_word)) {
			return EINVAL;
		}
		cur = Router.iflist;
		while(cur) {
			if (cur->interface_id == if_id) {
				selected = cur;
				break;
			}
			cur = cur->next;
		}

		if (!selected) {
			printoutc(fd, "Cannot find interface eth%d", if_id);
			return ENOENT;
		}

		/* Match policy */
		arg = strtok_r(NULL, " ", &nextargs);
		if (!arg) {
			printoutc(fd, "queue: queue policy required");
			return EINVAL;
		}
		if (match_input("unlimited", arg)) {
			newpolicy = QPOLICY_UNLIMITED;
		} else if (match_input("fifo", arg)) {
			newpolicy = QPOLICY_FIFO;
		} else if (match_input("red", arg)) {
			newpolicy = QPOLICY_RED;
		} else if (match_input("token", arg)) {
			newpolicy = QPOLICY_TOKEN;
		} else {
			printoutc(fd, "queue: invalid queue policy \"%s\"", arg);
			return EINVAL;
		}
		if (prio_id >= 0) {
			if (prio_id > 31) {
				printoutc(fd, "Invalid priority queue %s", arg);
				return EINVAL;
			}
			q = &selected->prio_q[prio_id];
		} else {
			printoutc(fd, "selected if=%d, outq", if_id);
			q = &selected->out_q;
		}

		/* Match arguments */
		if (newpolicy == QPOLICY_UNLIMITED) {
			qunlimited_setup(q);
		} else if (newpolicy == QPOLICY_FIFO) {
			uint32_t limit;
			arg = strtok_r(NULL, " ", &nextargs);
			if (!arg) {
				printoutc(fd, "fifo: missing parameter 'limit'");
				return EINVAL;
			}
			if (!match_input("limit", arg)) {
				printoutc(fd, "fifo: invalid parameter \"%s\"", arg);
				return EINVAL;
			}
			arg = strtok_r(NULL, " ", &nextargs);
			if (not_a_number(arg)) {
				printoutc(fd, "fifo: invalid limit");
				return EINVAL;
			}
			limit = strtol(arg, NULL, 10);
			qfifo_setup(q,limit);

		} else if (newpolicy == QPOLICY_RED) {
			uint32_t min, max, limit;
			double P;
			min = (uint32_t) get_labeled_arg(fd,"min", &nextargs);
			max = (uint32_t) get_labeled_arg(fd,"max", &nextargs);
			P = get_labeled_arg(fd,"probability", &nextargs);
			limit = (uint32_t) get_labeled_arg(fd,"limit", &nextargs);
			if (!min || !max || !limit)
				return EINVAL;
			qred_setup(q, min, max, P, limit);
		} else if (newpolicy == QPOLICY_TOKEN) {
			uint32_t limit, bitrate;
			limit = (uint32_t) get_labeled_arg(fd, "limit", &nextargs);
			bitrate = (uint32_t) get_labeled_arg(fd, "bitrate", &nextargs);
			if (!limit || !bitrate)
				return EINVAL;
			qtoken_setup(q, bitrate, limit);
		}
		return 0;
	}
}

static int doconnect(int fd,char *s)
{
	char *nextargs = NULL, *arg;
	struct vder_iface *created = NULL;
	int mac[6];
	uint8_t outmac[6], *newmac = NULL;
	char sock[1024];

	arg = strtok_r(s, " ", &nextargs);
	if (!arg) {
		printoutc(fd, "sock argument is required.");
		return EINVAL;
	} else {
		strncpy(sock, arg, 1023);
	}
	arg = strtok_r(NULL, " ", &nextargs);
	if (arg) {
		if ((sscanf(arg,"%02x:%02x:%02x:%02x:%02x:%02x",&mac[0],
			&mac[1], &mac[2], &mac[3], &mac[4], &mac[5] )) != ETHERNET_ADDRESS_SIZE) {

			printoutc(fd, "invalid mac address \"%s\"", arg);
			return EINVAL;
		} else {
			outmac[0] = (uint8_t)mac[0];
			outmac[1] = (uint8_t)mac[1];
			outmac[2] = (uint8_t)mac[2];
			outmac[3] = (uint8_t)mac[3];
			outmac[4] = (uint8_t)mac[4];
			outmac[5] = (uint8_t)mac[5];
			newmac = outmac;
		}
	}
	created = vder_iface_new(sock, newmac);
	if (created == NULL)
		return errno;
	pthread_create(&created->sender, 0, vder_core_send_loop, created);
	pthread_create(&created->receiver, 0, vder_core_recv_loop, created);
	pthread_create(&created->queue_manager, 0, vder_core_queuer_loop, created);

	printoutc(fd, "Created interface eth%d", created->interface_id);
	return 0;
}

static int stats(int fd, char *args)
{
	struct vder_iface *iface;
	if (strlen(args) > 0)
		return EINVAL;
	iface = Router.iflist;
	while(iface) {
		printoutc(fd, "eth%d frame sent:%d, frame received:%d",
			iface->interface_id, iface->stats.sent, iface->stats.recvd);
		printoutc(fd, "");
		iface = iface->next;
	}
	return 0;
}

#define WITHFILE 0x80
static struct comlist {
	char *tag;
	int (*fun)(int fd,char *arg);
	unsigned char type;
} commandlist [] = {
	{"help", help, WITHFILE},
	{"ifconfig", ifconfig, WITHFILE},
	{"route", route, WITHFILE},
	{"connect", doconnect, 0},
	{"stats", stats, WITHFILE},
	{"ipfilter", filter, WITHFILE},
	{"queue", queue, WITHFILE},
	{"logout",logout, 0},
	{"shutdown",doshutdown, 0},
	{"quit",doshutdown, 0},
	{"q",confirmquitplease, 0}
};

#define NCL sizeof(commandlist)/sizeof(struct comlist)

static inline void delnl(char *buf)
{
	int len=strlen(buf)-1;
	while (len>0 && 
				(buf[len]=='\n' || buf[len]==' ' || buf[len]=='\t')) {
		buf[len]=0;
		len--;
	}
}

static int handle_cmd(int fd,char *inbuf)
{
	int rv=ENOSYS;
	int i;
	char *cmd=inbuf;
	while (*inbuf == ' ' || *inbuf == '\t' || *inbuf == '\n') inbuf++;
	delnl(inbuf);
	if (*inbuf != '\0' && *inbuf != '#') {
		for (i=0; i<NCL 
				&& strncmp(commandlist[i].tag,inbuf,strlen(commandlist[i].tag))!=0;
				i++)
			;
		if (i<NCL)
		{
			inbuf += strlen(commandlist[i].tag);
			while (*inbuf == ' ' || *inbuf == '\t') inbuf++;
			if (fd>=0 && commandlist[i].type & WITHFILE)
				printoutc(fd,"0000 DATA END WITH '.'");
			rv=commandlist[i].fun(fd,inbuf);
			if (fd>=0 && commandlist[i].type & WITHFILE)
				printoutc(fd,".");
		}
		if (fd >= 0) {
			if (rv == 0) {
				printoutc(fd,"1000 Success");
			} else {
				printoutc(fd,"1%03d %s",rv,strerror(rv));
			}
		} else if (rv != 0) {
			fprintf(stderr,"rc command error: %s %s",cmd,strerror(rv));
		}
		return rv;
	}
	return rv;
}


static int mgmtcommand(int fd)
{
	char buf[MAXCMD+1];
	int n,rv;
	int outfd=fd;
	if (fd==STDIN_FILENO)
		outfd=STDOUT_FILENO;

	n = read(fd, buf, MAXCMD);
	if (n<0) {
		fprintf(stderr,"%s: read from mgmt %s",progname,strerror(errno));
		return -1;
	}
	else if (n==0){ 
		return -1;
		/* Remote end has closed connection. */
	}
	else {
		buf[n]=0;
		rv=handle_cmd(outfd,buf);
		if (rv>=0)
			write(outfd,prompt,strlen(prompt));
		return rv;
	}
}

static int delmgmtconn(int i,struct pollfd *pfd,int nfds)
{
	if (i<nfds) {
		close(pfd[i].fd);
		if (pfd[i].fd == STDIN_FILENO) /* close stdin implies exit */
			exit(0);
		memmove(pfd+i,pfd+i+1,sizeof (struct pollfd) * (nfds-i-1));
		nfds--;
	}
	return nfds;
}

static int openmgmt(char *mgmt)
{
	int mgmtconnfd;
	struct sockaddr_un sun;
	int one = 1;

	if((mgmtconnfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		fprintf(stderr,"%s: mgmt socket: %s",progname,strerror(errno));
		exit(1);
	}
	if(setsockopt(mgmtconnfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		fprintf(stderr,"%s: mgmt setsockopt: %s",progname,strerror(errno));
		exit(1);
	}
	if(fcntl(mgmtconnfd, F_SETFL, O_NONBLOCK) < 0){
		fprintf(stderr,"%s: Setting O_NONBLOCK on mgmt fd: %s",progname,strerror(errno));
		exit(1);
	}
	sun.sun_family = PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",mgmt);
	if(bind(mgmtconnfd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
		fprintf(stderr,"%s: mgmt bind %s",progname,strerror(errno));
		exit(1);
	}
	chmod(sun.sun_path,mgmtmode);
	if(listen(mgmtconnfd, 15) < 0){
		fprintf(stderr,"%s: mgmt listen: %s",progname,strerror(errno));
		exit(1);
	}
	return mgmtconnfd;
}

int config_readline (int fd, char *l)
{
	int len = 0;
	while(read(fd, &l[len], 1) > 0) {

		/* Skip leading spaces and empty lines */
		if ((len == 0) && (l[len]=='\n' || l[len]==' ' || l[len]=='\t'))
			continue;

		if (l[len] == '\n') {
			l[len] = (char)0;
			break;
		} else {
			if (++len == MAXCMD) {
				l[MAXCMD-1] = 0;
				break;
			}
		}
	}
	return len;
}

#define MAXCONN 6
static int newmgmtconn(int fd,struct pollfd *pfd,int nfds)
{
	int new;
	unsigned int len;
	char buf[MAXCMD];
	struct sockaddr addr;
	new = accept(fd, &addr, &len);
	if(new < 0) {
		fprintf(stderr, "mgmt accept %s",strerror(errno));
		return nfds;
	}
	if (nfds < MAXCONN) {
		snprintf(buf,MAXCMD,header);
		write(new,buf,strlen(buf));
		write(new,prompt,strlen(prompt));
		pfd[nfds].fd=new;
		pfd[nfds].events=POLLIN | POLLHUP;
		return ++nfds;
	} else {
		fprintf(stderr,"too many mgmt connections\n");
		close (new);
		return nfds;
	}
}

void cleanup(void)
{
	if(mgmt)
		unlink(mgmt);
}

void usage(void)
{
	fprintf(stderr, "Usage: %s [-c configfile] [-M mgmt_socket] [-m mgmt_mode] [-p pidfile] [-d]\n", progname);
	exit(1);
}

int main(int argc, char *argv[])
{
	char cmd[MAXCMD];
	int npfd = 0;
	struct pollfd pfd[MAXCONN];
	int consoleindex = -1, mgmtindex = -1;
	int i, n, daemon = 0;
	char *pidfile = NULL, *configfile = NULL;
	int option_index;
	static struct option long_options[] = {
		{"help",0 , 0, 'h'},
		{"config",1 , 0, 'c'},
		{"mgmt", 1, 0, 'M'},
		{"mgmtmode", 1, 0, 'm'},
		{"daemon",0 , 0, 'd'},
		{"pidfile", 1, 0, 'p'},
		{0,0,0,0}
	};
	progname=basename(argv[0]);
	vderouter_init();
	atexit(cleanup);

	while(1) {
		int c;
		c = getopt_long (argc, argv, "hM:c:dmp:", long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'c':
				configfile = strdup(optarg);
				break;
			case 'M':
				mgmt=strdup(optarg);
				break;
			case 'm':
				sscanf(optarg,"%o",&mgmtmode);
				break;
			case 'd':
				daemon=1;
				break;
			case 'p':
				pidfile=strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}
	if (optind < argc)
		usage();

	if (configfile) {
		int fd = open(configfile, O_RDONLY);
		if (fd < 0) {
			perror("Opening configuration file");
			exit(1);
		}
		while (config_readline(fd,cmd) > 0) {
			handle_cmd(STDOUT_FILENO, cmd);
		}
		close(fd);
	}

	if (daemon) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		if (fork() > 0) {
			exit (0);
		}
		if (fork() > 0) {
			exit (0);
		}
		setsid();
	} else {
		consoleindex = npfd;
		pfd[npfd].fd = STDIN_FILENO;
		pfd[npfd].events = POLLIN | POLLHUP;
		write(STDOUT_FILENO,header,strlen(header));
		write(STDOUT_FILENO,prompt,strlen(prompt));
		npfd++;
	}

	if (pidfile) {
		int pid_fd = open(pidfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		char pidstr[7] = "";
		if (pid_fd >= 0) {
			snprintf(pidstr, 6, "%d", getpid());
			write(pid_fd, pidstr, strlen(pidstr));
			close(pid_fd);
		} else {
			fprintf(stderr, "Cannot open pidfile: %s", strerror(errno));
		}
	}

	if(mgmt != NULL) {
		int mgmtfd = openmgmt(mgmt);
		mgmtindex = npfd;
		pfd[npfd].fd = mgmtfd;
		pfd[npfd].events = POLLIN | POLLHUP;
		npfd++;
	}

	while(1) {
		n = poll(pfd, npfd, -1);
		if (n>0) {
			for (i = 0; i < npfd; i++) {
				if ((pfd[i].revents == POLLIN) && (i == mgmtindex)) {
					npfd = newmgmtconn(pfd[i].fd, pfd, npfd);
					break;
				} else if (i != mgmtindex) {
					if (pfd[i].revents == POLLIN) {
						mgmtcommand(pfd[i].fd);
					} else if (pfd[i].revents&POLLHUP) {
						npfd = delmgmtconn(i, pfd, npfd);
						break;
					}
				}
			}
		}
	}
	exit(0);
}
