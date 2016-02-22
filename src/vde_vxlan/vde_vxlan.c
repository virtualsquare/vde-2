/*
 * VDE - vde_vxlan Network emulator for vde
 * Copyright (C) 2014 Renzo Davoli, Alessandro Ghedini VirtualSquare
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>

#include "vxlan_hash.h"
#include "log.h"
#include "vxlan.h"
#include "plug.h"

/* from vde_switch/switch.h */

#define INIT_HASH_SIZE 128

void cleanup();
void help();

int main(int argc, char *argv[]) {
	int opts;
	struct pollfd pfd[3];

	char *plug_addr  = NULL;
	int   plug_port  = 0;

	int daemonize = 0;

	const char   *short_opts  = "I:A:P:T:s:p:dvh";
	struct option long_opts[] = {
		{ "vxlan-id",   required_argument, 0, 'I' },
		{ "vxlan-addr", required_argument, 0, 'A' },
		{ "vxlan-port", required_argument, 0, 'P' },
		{ "vxlan-mttl", required_argument, 0, 'T' },

		{ "sock",       required_argument, 0, 's' },
		{ "port",       required_argument, 0, 'p' },

		{ "daemon",     no_argument,       0, 'd' },
		{ "verbose",    no_argument,       0, 'v' },

		{ "help",       no_argument,       0, 'h' },
		{0, 0, 0, 0}
	};

	while ((opts = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (opts) {
			/* VXLAN opts */
			case 'I': { vxlan_id   = atoi(optarg);      break; }
			/* TODO: IPv6 support */
			case 'A': { vxlan_addr = inet_addr(optarg); break; }
			case 'P': { vxlan_port = atoi(optarg);      break; }
			case 'T': { vxlan_mttl = atoi(optarg);      break; }

			/* VDE opts */
			case 's': { plug_addr = strdup(optarg);     break; }
			case 'p': { plug_port = atoi(optarg);       break; }

			case 'd': { daemonize = 1;                  break; }
			case 'v': { debug = 1;                      break; }

			default :
			case 'h': { help(); exit(1);                       }
		}
	}

	if (vxlan_id == -1) {
		printlog(LOG_ERR, "Invalid VXLAN ID");
		exit(1);
	}

	if (vxlan_addr == INADDR_NONE) {
		printlog(LOG_ERR, "Invalid VXLAN multicast address");
		exit(1);
	}

	atexit(cleanup);

	plug_open(plug_addr, plug_port, pfd);

	vxlan_open(pfd);

	hash_init(INIT_HASH_SIZE);

	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR, "daemon(): %s", strerror(errno));
		return 1;
	} else if (daemonize) {
		logok = 1;
		openlog("vde_vxlan", LOG_PID, 0);
		printlog(LOG_INFO, "VDE_VXLAN started");
	}

	while (1) {
		int n = poll(pfd, 3, 1000);

		if ((n < 0) && (errno != EINTR)) {
			printlog(LOG_ERR, "poll(): %s", strerror(errno));
			return 1;
		}

		if (pfd[0].revents & POLLHUP) {
			printlog(LOG_INFO, "VDE connection closed");
			return 0;
		}

		if (pfd[1].revents & POLLHUP) {
			printlog(LOG_ERR, "VDE connection error");
		}

		if (pfd[1].revents & POLLIN) {
			plug_process();
		}

		if (pfd[2].revents & POLLIN) {
			vxlan_process();
		}

		hash_gc();
	}

	return 0;
}

void cleanup() {
	vxlan_close();
	plug_close();
}

void help() {
	#define CMD_HELP(CMDL, CMDS, MSG) printf("  %s, %s\t%s.\n", CMDS, CMDL, MSG);

	puts("Usage: vde_vxlan [OPTIONS]\n");
	puts(" VXLAN Options:");

	CMD_HELP("--vxlan-id",   "-I", "ID of the VXLAN");
	CMD_HELP("--vxlan-addr", "-A", "Multicast address of the VXLAN");
	CMD_HELP("--vxlan-port", "-P", "Port of the VXLAN (default 4879)");
	CMD_HELP("--vxlan-mttl", "-T", "Multicast TTL (default 1)");

	puts("\n VDE Options:");

	CMD_HELP("--sock", "-s", "Socket directory of the VDE switch");
	CMD_HELP("--port", "-p", "Port of the VDE switch");

	CMD_HELP("--daemon",  "-d", "Run in background");
	CMD_HELP("--verbose", "-v", "Show debug output");

	CMD_HELP("--help",    "-h", "Show this help");

	puts("");
}
