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

static int hub = 0;
static int compat_v0 = 0;

enum request_type { REQ_NEW_CONTROL };

struct request_v0 {
  enum request_type type;
  union {
    struct {
      unsigned char addr[ETH_ALEN];
      struct sockaddr_un name;
    } new_control;
  } u;
};

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
  struct request_v0 v0;
  struct request_v1 v1;
  struct request_v3 v3;
};

static char *ctl_socket = VDESTDSOCK;

static char *data_socket = NULL;
static struct sockaddr_un data_sun;

static void cleanup(int x,void* data)
{
  if(unlink(ctl_socket) < 0){
    printf("Couldn't remove control socket '%s' : ", ctl_socket);
    perror("");
  }
  if((data_socket != NULL) && (unlink(data_socket) < 0)){
    printf("Couldn't remove data socket '%s' : ", data_socket);
    perror("");
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
      perror("realloc fds");
      exit(1);
    }
    if((g_fdsdata = realloc(g_fdsdata, maxfds * sizeof(void *))) == NULL){
      perror("realloc fds");
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
    fprintf(stderr, "remove_fd : Couldn't find descriptor %d\n", fd);
  } else {
   memmove(&fds[i], &fds[i + 1], (maxfds - i - 1) * sizeof(struct pollfd));
   memmove(&g_fdsdata[i], &g_fdsdata[i + 1], (maxfds - i - 1) * sizeof(void *));
   nfds--;
   g_nfds=nfds;
  }
}

static void sig_handler(int sig)
{
  printf("Caught signal %d, cleaning up and exiting\n", sig);
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

static void new_port_v0(int i, int fd, struct request_v0 *req, int data_fd)
{
  switch(req->type){
  case REQ_NEW_CONTROL:
    setup_sock_port(i, fd, &req->u.new_control.name, data_fd,0);
    break;
  default:
    printf("Bad request type : %d\n", req->type);
    close_descriptor(i, fd);
  }
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
      perror("Sending data socket name");
      close_descriptor(i, fd);
    }
    break;
  default:
    printf("Bad request type : %d\n", type);
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
      perror("Reading request");
      close_descriptor(i, fd);
    }
    return;
  }
  else if(len == 0){
    if (! daemonize) 
	    printf("EOF from new port\n");
    else
	    syslog(LOG_NOTICE,"EOF from new port \n");
    close_descriptor(i, fd);
    return;
  }
  if(req.v1.magic == SWITCH_MAGIC){
    if(req.v3.version == 3) 
      new_port_v1_v3(i,fd, req.v3.type, &req.v3.sock, data_fd);
    else if(req.v3.version > 2 || req.v3.version == 2) 
      fprintf(stderr, "Request for a version %d port, which this "
	      "vde_switch doesn't support\n", req.v3.version);
    else new_port_v1_v3(i, fd, req.v1.type, &req.v1.u.new_control.name, data_fd);
  }
  else new_port_v0(i, fd, &req.v0, data_fd);
}

void accept_connection(int fd)
{
  struct sockaddr addr;
  int len, new;

  len = sizeof(addr);
  new = accept(fd, &addr, &len);
  if(new < 0){
    perror("accept");
    return;
  }
  if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
    perror("fcntl - setting O_NONBLOCK");
    close(new);
    return;
  }
  add_fd(new);
}

int still_used(struct sockaddr_un *sun)
{
  int test_fd, ret = 1;

  if((test_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }
  if(connect(test_fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    if(errno == ECONNREFUSED){
      if(unlink(sun->sun_path) < 0){
	fprintf(stderr, "Failed to removed unused socket '%s': ", 
		sun->sun_path);
	perror("");
      }
      ret = 0;
    }
    else perror("connect");
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
      perror("bind");
      return(EPERM);
    }
  }
  if(sock_out != NULL) *sock_out = sun;
  return(0);
}

static char *prog;

void bind_sockets_v0(int ctl_fd, const char *ctl_name, 
		     int data_fd, const char *data_name)
{
  int ctl_err, ctl_present = 0, ctl_used = 0;
  int data_err, data_present = 0, data_used = 0;
  int try_remove_ctl, try_remove_data;

  ctl_err = bind_socket(ctl_fd, ctl_name, NULL);
  if(ctl_err != 0) ctl_present = 1;
  if(ctl_err == EADDRINUSE) ctl_used = 1;

  data_err = bind_socket(data_fd, data_name, &data_sun);
  if(data_err != 0) data_present = 1;
  if(data_err == EADDRINUSE) data_used = 1;

  if(!ctl_err && !data_err){
    return;
  }

  try_remove_ctl = ctl_present;
  try_remove_data = data_present;
  if(ctl_present && ctl_used){
    fprintf(stderr, "The control socket '%s' has another server "
	    "attached to it\n", ctl_name);
    try_remove_ctl = 0;
  }
  else if(ctl_present && !ctl_used)
    fprintf(stderr, "The control socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", ctl_name);
  if(data_present && data_used){
    fprintf(stderr, "The data socket '%s' has another server "
	    "attached to it\n", data_name);
    try_remove_data = 0;
  }
  else if(data_present && !data_used)
    fprintf(stderr, "The data socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", data_name);
  if(try_remove_ctl || try_remove_data){
    fprintf(stderr, "You can either\n");
    if(try_remove_ctl && !try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", ctl_socket);
    else if(!try_remove_ctl && try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", data_socket);
    else fprintf(stderr, "\tremove '%s' and '%s'\n", ctl_socket, data_socket);
    fprintf(stderr, "\tor rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t\t%s -unix <control> <data>\n", prog);
    fprintf(stderr, "\t\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>\n");
    exit(1);
  }
  else {
    fprintf(stderr, "You should rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t%s -unix <control> <data>\n", prog);
    fprintf(stderr, "\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>'\n");
    exit(1);
  }
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
    perror("Binding to data socket");
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
  fprintf(stderr, "Usage : %s [ -unix control-socket ] [ -tap tuntap-device ] [ -hub ] [-daemon]\n"
	  "or : %s -compat-v0 [ -unix control-socket data-socket ] "
	  "[ -hub ]\n", prog, prog);
#else
  fprintf(stderr, "Usage : %s [ -unix control-socket ] [ -hub ] [-daemon]\n"
	  "or : %s -compat-v0 [ -unix control-socket data-socket ] "
	  "[ -hub ]\n", prog, prog);
#endif
  exit(1);
}

int daemonize = 0;
int main(int argc, char **argv)
{
  int connect_fd, data_fd, n, i, /*new,*/ one = 1;
  char *tap_dev = NULL;
#ifdef TUNTAP
  int tap_fd  = -1;
#endif

  on_exit(cleanup, NULL);
  prog = argv[0];
  argv++;
  argc--;
  while(argc > 0){
    if(!strcmp(argv[0], "-unix")){
      if(argc < 2) Usage();
      ctl_socket = argv[1];
      argc -= 2;
      argv += 2;
      if(!compat_v0) break;
      if(argc < 1) Usage();
      data_socket = argv[0];
      argc--;
      argv++;
    }
    if(!strcmp(argv[0], "-tap")){
#ifdef TUNTAP
      tap_dev = argv[1];
      argv += 2;
      argc -= 2;
#else
      fprintf(stderr, "-tap isn't supported since TUNTAP isn't enabled\n");
      Usage();
#endif      
    }
    else if(!strcmp(argv[0], "-hub")){
      printf("%s will be a hub instead of a switch\n", prog);
      hub = 1;
      argc--;
      argv++;
    }
    else if(!strcmp(argv[0], "-compat-v0")){
      printf("Control protocol 0 compatibility\n");
      compat_v0 = 1;
      data_socket = "/tmp/uml.data";
      argc--;
      argv++;
    }
    else if(!strcmp(argv[0], "-daemon")){
      daemonize = 1;
      argc--;
      argv++;
    }
    else Usage();
  }

  if((connect_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }
  if(setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, 
		sizeof(one)) < 0){
    perror("setsockopt");
    exit(1);
  }
  if(fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0){
    perror("Setting O_NONBLOCK on connection fd");
    exit(1);
  }
  if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
    perror("socket");
    exit(1);
  }
  if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0){
    perror("Setting O_NONBLOCK on data fd");
    exit(1);
  }

  if(compat_v0) bind_sockets_v0(connect_fd, ctl_socket, data_fd, data_socket);
  else bind_sockets(connect_fd, ctl_socket, data_fd);

  if(listen(connect_fd, 15) < 0){
    perror("listen");
    exit(1);
  }

  if(signal(SIGINT, sig_handler) < 0)
    perror("Setting handler for SIGINT");
  hash_init();

  if (!daemonize) {
  	if(compat_v0) 
    		printf("%s attached to unix sockets '%s' and '%s'\n", prog, ctl_socket,
	   	data_socket);
  	else printf("%s attached to unix socket '%s'\n", prog, ctl_socket);
  } else {
	openlog(basename(prog), LOG_PID, 0);
	syslog(LOG_INFO,"UML_SWITCH started");
  	if(compat_v0) 
    		syslog(LOG_INFO,"attached to unix sockets '%s' and '%s'\n", ctl_socket,
	   	data_socket);
  	else syslog(LOG_INFO,"attached to unix socket '%s'\n", ctl_socket);
  }
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
    perror("daemon");
    exit(1);
  }

  while(1){
    char buf[128];

    n = poll(fds, nfds, -1);
    if(n < 0){
      if(errno == EINTR) continue;
      perror("poll");
      break;
    }
    for(i = 0; i < nfds; i++){
      if(fds[i].revents == 0) continue;
      if(fds[i].fd == 0){
	if(fds[i].revents & POLLHUP){
	  printf("EOF on stdin, cleaning up and exiting\n");
	  exit(0);
	}

	n = read(0, buf, sizeof(buf));
	if(n < 0){
	  perror("Reading from stdin");
	  break;
	}
	else if(n == 0){
	  printf("EOF on stdin, cleaning up and exiting\n");
	  exit(0);
	}
      }
      else if(fds[i].fd == connect_fd){
	if(fds[i].revents & POLLHUP){
	  printf("Error on connection fd\n");
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
