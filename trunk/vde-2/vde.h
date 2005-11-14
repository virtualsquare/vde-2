#ifndef VDE_H_
#define VDE_H_

#ifdef HAVE_GETOPT_LONG_ONLY
#define GETOPT_LONG getopt_long_only
#else
#define GETOPT_LONG getopt_long
#endif

#ifndef VDESTDSOCK
#define VDESTDSOCK	"/var/run/vde.ctl"
#define VDETMPSOCK	"/tmp/vde.ctl"
#endif

#define DO_SYSLOG
#define VDE_IP_LOG
//#define VDE_PQ

#endif
