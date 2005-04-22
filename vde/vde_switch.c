/* Copyright 2001, 2002 Jeff Dike and others
 * Copyright 2003 Renzo Davoli (modified for daemon and vde)
 * Licensed under the GPL
 * Modified for --pidfile/-p and better cleanup management by Mattia Belletti.
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <libgen.h>
#include <endian.h>
#include <vde.h>
#include <switch.h>
#include <port.h>
#include <hash.h>
#ifdef TUNTAP
#include <tuntap.h>
#endif

#ifdef notdef
#include <stddef.h>
#endif
#include <stdarg.h>

static int hub = 0;
static char *prog;
static int daemonize = 0;
static int logok = 0;

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",prog);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);

}

enum request_type { REQ_NEW_CONTROL };

#define SWITCH_MAGIC 0xfeedface

struct request_v1 {
  uint32_t magic;
  enum request_type type;
  union {
    struct {
      unsigned char addr[ETH_ALEN];
      struct sockaddr_un name;
    } new_control;
  } u;
};

struct request_v3 {
  uint32_t magic;
  uint32_t version;
  enum request_type type;
  struct sockaddr_un sock;
};

union request {
  struct request_v1 v1;
  struct request_v3 v3;
};

static char *ctl_socket = VDESTDSOCK;
static int ctl_socket_created = 0;

static char *data_socket = NULL;
static struct sockaddr_un data_sun;

static char *pidfile = NULL;
static char pidfile_path[_POSIX_PATH_MAX];

static void cleanup(void)
{
  if(ctl_socket_created && unlink(ctl_socket) < 0){
    printlog(LOG_WARNING,"Couldn't remove control socket '%s' : %s", ctl_socket, strerror(errno));
  }
  if((data_socket != NULL) && (unlink(data_socket) < 0)){
    printlog(LOG_WARNING,"Couldn't remove data socket '%s' : %s", data_socket, strerror(errno));
  }
  if((pidfile != NULL) && unlink(pidfile_path) < 0) {
    printlog(LOG_WARNING,"Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
  }
}

/* array of pointer to struct port */
void **g_fdsdata = NULL;
int g_nfds = 0;
int g_minfds = 0;
static struct pollfd *fds = NULL;
static int maxfds = 0;
static int nfds = 0;

/* adds file descriptor 'fd' to the set of file descriptors whose input we wait
 * for in main loop */
static void add_fd(int fd)
{
  struct pollfd *p;

  /* enlarge fds and g_fdsdata array if needed */
  if(nfds == maxfds){
    maxfds = maxfds ? 2 * maxfds : 8;
    if((fds = realloc(fds, maxfds * sizeof(struct pollfd))) == NULL){
      printlog(LOG_ERR,"realloc fds %s",strerror(errno));
      exit(1);
    }
    if((g_fdsdata = realloc(g_fdsdata, maxfds * sizeof(void *))) == NULL){
      printlog(LOG_ERR,"realloc fdsdata %s",strerror(errno));
      exit(1);
    }
  }
  p = &fds[nfds];
  p->fd = fd;
  p->events = POLLIN;
  g_fdsdata[nfds]=NULL;
  nfds++;
  g_nfds=nfds;
}

static void remove_fd(int fd)
{
  int i;

  for(i = 0; i < nfds; i++){
    if(fds[i].fd == fd) break;
  }
  if(i == nfds){
    printlog(LOG_WARNING,"remove_fd : Couldn't find descriptor %d", fd);
  } else {
   memmove(&fds[i], &fds[i + 1], (maxfds - i - 1) * sizeof(struct pollfd));
   memmove(&g_fdsdata[i], &g_fdsdata[i + 1], (maxfds - i - 1) * sizeof(void *));
   nfds--;
   g_nfds=nfds;
  }
}

static void sig_handler(int sig)
{
  printlog(LOG_ERR,"Caught signal %d, cleaning up and exiting", sig);
  cleanup(1,NULL);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

static void close_descriptor(int i, int fd)
{
  close_port(i,fd);
  close(fd);
  remove_fd(fd);
}

static void new_port_v1_v3(int i, int fd, enum request_type type_group, 
			   struct sockaddr_un *sock, int data_fd)
{
  int n, err;
  enum request_type type = type_group & 0xff;
  int group=type_group >> 8;

  // group
  switch(type){
  case REQ_NEW_CONTROL:
    err = setup_sock_port(i, fd, sock, data_fd, group);
    if(err) return;
    n = write(fd, &data_sun, sizeof(data_sun));
    if(n != sizeof(data_sun)){
      printlog(LOG_WARNING,"Sending data socket name %s",strerror(errno));
      close_descriptor(i, fd);
    }
    break;
  default:
    printlog(LOG_WARNING,"Bad request type : %d", type);
    close_descriptor(i, fd);
  }
}

static void new_port(int i, int fd, int data_fd)
{
  union request req;
  int len;

  len = read(fd, &req, sizeof(req));
  if(len < 0){
    if(errno != EAGAIN){
      printlog(LOG_WARNING,"Reading request %s", strerror(errno));
      close_descriptor(i, fd);
    }
    return;
  }
  else if(len == 0){
	  printlog(LOG_WARNING,"EOF from new port");
	  close_descriptor(i, fd);
	  return;
  }
  if(req.v1.magic == SWITCH_MAGIC){
    if(req.v3.version == 3) 
      new_port_v1_v3(i,fd, req.v3.type, &req.v3.sock, data_fd);
    else if(req.v3.version > 2 || req.v3.version == 2) 
      printlog(LOG_ERR, "Request for a version %d port, which this "
	      "vde_switch doesn't support", req.v3.version);
    else new_port_v1_v3(i, fd, req.v1.type, &req.v1.u.new_control.name, data_fd);
  }
  else {
	  printlog(LOG_WARNING,"V0 request not supported");
	  close_descriptor(i, fd);
	  return;
  }
}

/* accept a new connection from socket fd, then set received connection as non
 * blocking and add it between the fds whose input we wait for */
void accept_connection(int fd)
{
  struct sockaddr addr;
  int len, new;

  len = sizeof(addr);
  new = accept(fd, &addr, &len);
  if(new < 0){
    printlog(LOG_WARNING,"accept %s",strerror(errno));
    return;
  }
  if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
    printlog(LOG_WARNING,"fcntl - setting O_NONBLOCK %s",strerror(errno));
    close(new);
    return;
  }
  add_fd(new);
}

/* check to see if given unix socket is still in use; if it isn't, remove the
 * socket from the file system */
int still_used(struct sockaddr_un *sun)
{
  int test_fd, ret = 1;

  if((test_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
    printlog(LOG_ERR,"socket %s",strerror(errno));
    exit(1);
  }
  if(connect(test_fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    if(errno == ECONNREFUSED){
      if(unlink(sun->sun_path) < 0){
	printlog(LOG_ERR,"Failed to removed unused socket '%s': %s", 
		sun->sun_path,strerror(errno));
      }
      ret = 0;
    }
    else printlog(LOG_ERR,"connect %s",strerror(errno));
  }
  close(test_fd);
  return(ret);
}

/* try to bind socket fd to unix socket at path name; resulting sockaddr is
 * returned in sock_out if != NULL; returns 0 if alright, or the error
 * otherwise. */
int bind_socket(int fd, const char *name, struct sockaddr_un *sock_out)
{
  struct sockaddr_un sun;

  sun.sun_family = AF_UNIX;
  strncpy(sun.sun_path, name, sizeof(sun.sun_path));

  if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
    if((errno == EADDRINUSE) && still_used(&sun)) return(EADDRINUSE);
    else if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
      printlog(LOG_ERR,"bind %s",strerror(errno));
      return(EPERM);
    }
  }
  if(sock_out != NULL) *sock_out = sun;
  return(0);
}


/* bind the data socket as an unix socket in the abstract namespace (as
 * detailed in man 7 unix), exit with error from the program if it fails.
 * obtained sockaddr is returned in sun, which must not be NULL. */
void bind_data_socket(int fd, struct sockaddr_un *sun)
{
  struct {
    char zero;
    int pid;
    int usecs;
  } name;
  struct timeval tv;

  name.zero = 0;
  name.pid = getpid();
  gettimeofday(&tv, NULL);
  name.usecs = tv.tv_usec;
  sun->sun_family = AF_UNIX;
  memcpy(sun->sun_path, &name, sizeof(name));
  if(bind(fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    printlog(LOG_ERR,"Binding to data socket %s",strerror(errno));
    exit(1);
  }
}

/* try to bind both control socket ctl_fd to file ctl_name and data socket
 * data_fd, as detailed in bind_socket and bind_data_socket, and exit from the
 * program with error if it can't */
void bind_sockets(int ctl_fd, const char *ctl_name, int data_fd)
{
  int err, used=0;

  /* do it in advance, so we avoid race conditions */
  ctl_socket_created = 1;

  err = bind_socket(ctl_fd, ctl_name, NULL);
  if(err == 0){
    bind_data_socket(data_fd, &data_sun);
    return;
  }
  else if(err == EADDRINUSE) used = 1;
  
  if(used){
    fprintf(stderr, "The control socket '%s' has another server "
	    "attached to it\n", ctl_name);
    fprintf(stderr, "You can either\n");
    fprintf(stderr, "\tremove '%s'\n", ctl_name);
    fprintf(stderr, "\tor rerun with a different, unused filename for a "
	    "socket\n");
  }
  else
    fprintf(stderr, "The control socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", ctl_name);
  exit(1);
}

static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, PATH_MAX - strlen(pidfile_path));
	else
		strcpy(pidfile_path, pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

static void Usage(void)
{
	printf(
			"Usage: vde_switch [OPTIONS]\n"
			"Runs a VDE switch.\n"
			"\n"
			"  -s, --sock SOCK            Choose name of the control UNIX socket\n"
			"  -s, --vdesock SOCK         Same as --sock SOCK\n"
			"  -s, --unix SOCK            Same as --sock SOCK\n"
#ifdef TUNTAP
			"  -t, --tap TAP              Enable routing through TAP tap interface\n"
#endif
			"  -d, --daemon               Daemonize vde_switch once run\n"
			"  -x, --hub                  Make the switch act as a hub\n"
			"  -p, --pidfile PIDFILE      Write pid of daemon to PIDFILE\n"
			"  -h, --help                 Display this help and exit\n"
			"  -v, --version              Display informations on version and exit\n"
			"\n"
			"Report bugs to PACKAGE_BUGREPORT\n"
			);
	exit(1);
}

static void version(void)
{
	printf(
			"VDE " PACKAGE_VERSION "\n"
			"Copyright (C) 2001, 2002 Jeff Dike and others\n"
			"Copyright 2003 Renzo Davoli (modified for daemon and vde)\n"
			"VDE comes with NO WARRANTY, to the extent permitted by law.\n"
			"You may redistribute copies of VDE under the terms of the\n"
			"GNU General Public License.\n"
			"For more information about these matters, see the files\n"
			"named COPYING.\n");
	exit(0);
}

int main(int argc, char **argv)
{
  int connect_fd, data_fd, n, i, /*new,*/ one = 1;
#ifdef TUNTAP
  char *tap_dev = NULL;
  int tap_fd  = -1;
#endif

  atexit(cleanup);
  prog = argv[0];
  /* option parsing */
  {
	  int c;
	  while (1) {
		  int option_index = 0;

		  static struct option long_options[] = {
			  {"sock", 1, 0, 's'},
			  {"vdesock", 1, 0, 's'},
			  {"unix", 1, 0, 's'},
			  {"tap", 1, 0, 't'},
			  {"daemon", 0, 0, 'd'},
			  {"hub", 0, 0, 'x'},
			  {"pidfile", 1, 0, 'p'},
			  {"help",0 , 0, 'h'},
			  {"version", 0, 0, 'v'},
			  {0, 0, 0, 0}
		  };
		  c = getopt_long_only (argc, argv, "s:t:dxp:h",
				  long_options, &option_index);
		  if (c == -1)
			  break;
		  switch (c) {
			  case 's':
				  ctl_socket=strdup(optarg);
				  break;

			  case 't':
#ifdef TUNTAP
				  tap_dev=strdup(optarg);
#else
				  fprintf(stderr, "-tap isn't supported since TUNTAP isn't enabled\n");
				  Usage();
#endif
				  break;
			  case 'x':
				  printlog(LOG_INFO,"s will be a hub instead of a switch", prog);
				  hub = 1;
				  break;
			  case 'd':
				  daemonize=1;
				  break;
				case 'p':
					pidfile=strdup(optarg);
					break;
			  case 'v':
				  version();
			  case 'h':
			  default:
				  Usage();
		  }
	  }
	  if(optind < argc)
		  Usage();

  }

	/* connect_fd is a stream UNIX socket, whose address can be reused, and set
	 * nonblocking */
  if((connect_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
	  printlog(LOG_ERR,"socket: %s",strerror(errno));
	  exit(1);
  }
  if(setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, 
			  sizeof(one)) < 0){
	  printlog(LOG_ERR,"setsockopt: %s",strerror(errno));
	  exit(1);
  }
  if(fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0){
	  printlog(LOG_ERR,"Setting O_NONBLOCK on connection fd: %s",strerror(errno));
	  exit(1);
  }
	/* data_fd is similar, but datagram */
  if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
	  printlog(LOG_ERR,"socket: %s",strerror(errno));
	  exit(1);
  }
  if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0){
	  printlog(LOG_ERR,"Setting O_NONBLOCK on data fd %s",strerror(errno));
	  exit(1);
  }

	/* make needed binds to complete connect_fd and data_fd initialization */
  bind_sockets(connect_fd, ctl_socket, data_fd);

	/* tell that connect_fd will be able to accept connections */
  if(listen(connect_fd, 15) < 0){
	  printlog(LOG_ERR,"listen: %s",strerror(errno));
	  exit(1);
  }

	{
		/* setting signal handlers.
		 * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
		 * ignores all the others signals which could cause termination. */
		struct { int sig; const char *name; int ignore; } signals[] = {
			{ SIGHUP, "SIGHUP", 0 },
			{ SIGINT, "SIGINT", 0 },
			{ SIGPIPE, "SIGPIPE", 1 },
			{ SIGALRM, "SIGALRM", 1 },
			{ SIGTERM, "SIGTERM", 0 },
			{ SIGUSR1, "SIGUSR1", 1 },
			{ SIGUSR2, "SIGUSR2", 1 },
			{ SIGPOLL, "SIGPOLL", 1 },
			{ SIGPROF, "SIGPROF", 1 },
			{ SIGVTALRM, "SIGVTALRM", 1 },
			{ SIGSTKFLT, "SIGSTKFLT", 1 },
			{ SIGIO, "SIGIO", 1 },
			{ SIGPWR, "SIGPWR", 1 },
			{ SIGUNUSED, "SIGUNUSED", 1 },
			{ 0, NULL, 0 }
		};
		int i;

		for(i = 0; signals[i].sig != 0; i++)
			if(signal(signals[i].sig,
						signals[i].ignore ? SIG_IGN : sig_handler) < 0)
				printlog(LOG_ERR,"Setting handler for %s: %s", signals[i].name,
						strerror(errno));
	}

	/* initialize ARP table */
  hash_init();

	/* take care about logging */
  if (daemonize) {
	  openlog(basename(prog), LOG_PID, 0);
	  logok=1;
	  syslog(LOG_INFO,"VDE_SWITCH started");
  }
  printlog(LOG_INFO,"attached to unix socket '%s'", ctl_socket);

	/* add stdin (if tty), connect and data fds to the set of fds we wait for
	 * input */
  if(isatty(0) && ! daemonize)
	  add_fd(0);
  add_fd(connect_fd);
  add_fd(data_fd);
  g_minfds=g_nfds;

#ifdef TUNTAP
  if(tap_dev != NULL) tap_fd = open_tap(tap_dev);
  if(tap_fd > -1) {
	  add_fd(tap_fd);
	  setup_port(g_nfds-1, tap_fd, send_tap, NULL, 0, 0);
  }
#endif

	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
  if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
    printlog(LOG_ERR, "getcwd: %s", strerror(errno));
    exit(1);
  }
	strcat(pidfile_path, "/");
  if (daemonize && daemon(0, 1)) {
	  printlog(LOG_ERR,"daemon: %s",strerror(errno));
	  exit(1);
  }

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();

	/* main loop of events processing */
  while(1){
	  char buf[128];

		/* wait for some input */
	  n = poll(fds, nfds, -1);
	  if(n < 0){
		  if(errno == EINTR) continue;
		  printlog(LOG_WARNING,"poll %s",strerror(errno));
		  break;
	  }

		/* check the input received */
	  for(i = 0; i < nfds; i++){
		  if(fds[i].revents == 0) continue;

			/* special case for standard input */
		  if(fds[i].fd == 0){
				/* POLLHUP; e.g., pressed Ctrl+C on a non-daemonized vde_switch; thus
				 * exit! */
			  if(fds[i].revents & POLLHUP){
				  printlog(LOG_WARNING,"EOF on stdin, cleaning up and exiting");
				  exit(0);
			  }

				/* otherwise read data from stdin, log it, and eventually catch EOFs as
				 * exits */
			  n = read(0, buf, sizeof(buf));
			  if(n < 0){
				  printlog(LOG_WARNING,"Reading from stdin %s",strerror(errno));
				  break;
			  }
			  else if(n == 0){
				  printlog(LOG_WARNING,"EOF on stdin, cleaning up and exiting");
				  exit(0);
			  }
		  }

			/* special case for connect fd - is there some connection pending? */
		  else if(fds[i].fd == connect_fd){
			  if(fds[i].revents & POLLHUP){
				  printlog(LOG_WARNING,"Error on connection fd");
				  continue;
			  }
			  accept_connection(connect_fd);
		  }

			/* data socket - ??? */
		  else if(fds[i].fd == data_fd) handle_sock_data(data_fd, hub);

#ifdef TUNTAP
			/* special case for tap data */
		  else if(fds[i].fd == tap_fd) handle_tap_data(i, tap_fd, hub);
#endif
		  else {
			  if (g_fdsdata[i] == NULL)
				  new_port(i,fds[i].fd, data_fd);
			  else 
				  if (handle_sock_direct_data(i, fds[i].fd, hub))
					  close_descriptor(i, fds[i].fd);
		  }
	  }
  }
  return 0;
}
