/* Copyright 2001, 2002 Jeff Dike and others
 * Copyright 2003 Renzo Davoli (modified for daemon and vde)
 * Licensed under the GPL
 */

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
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>
#include <libgen.h>
#include <endian.h>
#include "vde.h"
#include "switch.h"
#include "port.h"
#include "hash.h"
#ifdef TUNTAP
#include "tuntap.h"
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

static char *data_socket = NULL;
static struct sockaddr_un data_sun;

static void cleanup(int x,void* data)
{
  if(unlink(ctl_socket) < 0){
    printlog(LOG_WARNING,"Couldn't remove control socket '%s' : %s", ctl_socket, strerror(errno));
  }
  if((data_socket != NULL) && (unlink(data_socket) < 0)){
    printlog(LOG_WARNING,"Couldn't remove data socket '%s' : %s", data_socket, strerror(errno));
  }
}

void **g_fdsdata = NULL;
int g_nfds = 0;
int g_minfds = 0;
static struct pollfd *fds = NULL;
static int maxfds = 0;
static int nfds = 0;

static void add_fd(int fd)
{
  struct pollfd *p;

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

void bind_sockets(int ctl_fd, const char *ctl_name, int data_fd)
{
  int err, used=0;

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

static void Usage(void)
{
#ifdef TUNTAP
  fprintf(stderr, "Usage : %s [ -unix control-socket ] [ -tap tuntap-device ] [ -hub ] [-daemon]\n" , prog);
#else
  fprintf(stderr, "Usage : %s [ -unix control-socket ] [ -hub ] [-daemon]\n", prog);
#endif
  exit(1);
}

int main(int argc, char **argv)
{
  int connect_fd, data_fd, n, i, /*new,*/ one = 1;
  char *tap_dev = NULL;
#ifdef TUNTAP
  int tap_fd  = -1;
#endif

  on_exit(cleanup, NULL);
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
			  {"help",0,0,'h'},
			  {0, 0, 0, 0}
		  };
		  c = getopt_long_only (argc, argv, "s:t:dxh",
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
			  case 'h':
			  default:
				  Usage();
		  }
	  }
	  if(optind < argc)
		  Usage();

  }

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
  if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
	  printlog(LOG_ERR,"socket: %s",strerror(errno));
	  exit(1);
  }
  if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0){
	  printlog(LOG_ERR,"Setting O_NONBLOCK on data fd %s",strerror(errno));
	  exit(1);
  }

  bind_sockets(connect_fd, ctl_socket, data_fd);

  if(listen(connect_fd, 15) < 0){
	  printlog(LOG_ERR,"listen: %s",strerror(errno));
	  exit(1);
  }

  if(signal(SIGINT, sig_handler) < 0) {
	  printlog(LOG_ERR,"Setting handler for SIGINT: %s",strerror(errno));
  }
  hash_init();

  if (daemonize) {
	  openlog(basename(prog), LOG_PID, 0);
	  logok=1;
	  syslog(LOG_INFO,"UML_SWITCH started");
  }
  printlog(LOG_INFO,"attached to unix socket '%s'", ctl_socket);
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

  if (daemonize && daemon(0, 1)) {
	  printlog(LOG_ERR,"daemon: %s",strerror(errno));
	  exit(1);
  }

  while(1){
	  char buf[128];

	  n = poll(fds, nfds, -1);
	  if(n < 0){
		  if(errno == EINTR) continue;
		  printlog(LOG_WARNING,"poll %s",strerror(errno));
		  break;
	  }
	  for(i = 0; i < nfds; i++){
		  if(fds[i].revents == 0) continue;
		  if(fds[i].fd == 0){
			  if(fds[i].revents & POLLHUP){
				  printlog(LOG_WARNING,"EOF on stdin, cleaning up and exiting");
				  exit(0);
			  }

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
		  else if(fds[i].fd == connect_fd){
			  if(fds[i].revents & POLLHUP){
				  printlog(LOG_WARNING,"Error on connection fd");
				  continue;
			  }
			  accept_connection(connect_fd);
		  }
		  else if(fds[i].fd == data_fd) handle_sock_data(data_fd, hub);
#ifdef TUNTAP
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
