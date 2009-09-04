#ifndef VDE_H_
#define VDE_H_

#ifdef HAVE_GETOPT_LONG_ONLY
#define GETOPT_LONG getopt_long_only
#else
#define GETOPT_LONG getopt_long
#endif

#define VDE_SOCK_DIR LOCALSTATEDIR"/run"
#define VDE_RC_DIR SYSCONFDIR"/vde2"

#ifndef VDESTDSOCK
#define VDESTDSOCK	VDE_SOCK_DIR"/vde.ctl"
#define VDETMPSOCK	"/tmp/vde.ctl"
#endif

#define DO_SYSLOG
#define VDE_IP_LOG

/*
 * Enable the new packet queueing. Experimental but recommended
 * (expecially with Darwin and other BSDs)
 */
#define VDE_PQ

#endif
