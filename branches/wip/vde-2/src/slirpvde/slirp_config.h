#ifndef SLIRP_CONFIG_H_
#define SLIRP_CONFIG_H_

/*
 * User definable configuration options
 */

/* Undefine if you don't want talk emulation */
#undef EMULATE_TALK

/* Define if you want the connection to be probed */
/* XXX Not working yet, so ignore this for now */
#undef PROBE_CONN

/* Define to 1 if you want KEEPALIVE timers */
#define DO_KEEPALIVE 0

/* Define to MAX interfaces you expect to use at once */
/* MAX_INTERFACES determines the max. TOTAL number of interfaces (SLIP and PPP) */
/* MAX_PPP_INTERFACES determines max. number of PPP interfaces */
#define MAX_INTERFACES 1
#define MAX_PPP_INTERFACES 1

/* Define if you want slirp's socket in /tmp */
/* XXXXXX Do this in ./configure */
#undef USE_TMPSOCKET

/* Define if you want slirp to use cfsetXspeed() on the terminal */
#undef DO_CFSETSPEED

/* Define this if you want slirp to write to the tty as fast as it can */
/* This should only be set if you are using load-balancing, slirp does a */
/* pretty good job on single modems already, and seting this will make */
/* interactive sessions less responsive */
/* XXXXX Talk about having fast modem as unit 0 */
#undef FULL_BOLT

/*
 * Define if you want slirp to use less CPU
 * You will notice a small lag in interactive sessions, but it's not that bad
 * Things like Netscape/ftp/etc. are completely unaffected
 * This is mainly for sysadmins who have many slirp users
 */
#undef USE_LOWCPU

/* Define this if your compiler doesn't like prototypes */
#ifndef __STDC__
#define NO_PROTOTYPES
#endif

#endif
