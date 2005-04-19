/* Copyright 2003 Renzo Davoli
 * Based on the code of uml_switch Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <switch.h>
#include <hash.h>
#include <port.h>

struct packet {
  struct {
    unsigned char dest[ETH_ALEN];
    unsigned char src[ETH_ALEN];
    unsigned char proto[2];
  } header;
  unsigned char data[1500];
};


// for dedugging if needed
/*
void packet_dump (struct packet *p)
{
	register int i;
	printf ("packet dump dst");
	for (i=0;i<ETH_ALEN;i++)
		printf(":%02x",p->header.dest[i]);
	printf(" src");
	for (i=0;i<ETH_ALEN;i++)
		printf(":%02x",p->header.src[i]);
	printf(" proto");
	for (i=0;i<2;i++)
		printf(":%02x",p->header.proto[i]);
	printf("\n");
}
*/

/* descriptor of a port group */
struct portgroup {
	/* identifier of the port group */
	int ident;
	/* number of ports which reference this descriptor */
	int counter;
};

struct port {
  int control;
  void *data;
  int data_len;
  /* pointer to a structure containing group description; reference counting
	 * allows to share the same structure, and know at the same time how many
	 * ports are grouped together */
  struct portgroup *pg;
  void (*sender)(int fd, void *packet, int len, void *data);
};


#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)

void close_port(int i, int fd)
{
  struct port *port=(struct port *)(g_fdsdata[i]);

  if(port == NULL){
  	printlog(LOG_WARNING, "No port associated with descriptor %d", fd);
     	return;
  }
  else if(port->control != fd){
  	 printlog(LOG_WARNING, "file descriptor mismatch %d %d", port->control, fd);
     	 return;
  }

  if (port->pg != NULL) {
	  if (--port->pg->counter == 0) {
		  free(port->pg);
	  	  port->pg=NULL;
		  hash_delete_port(port);
          } else { 
	  
		  struct port *p; 
		  register int i;

		  p=NULL;
  
		  for(i=g_minfds ; i<g_nfds ; i++) {
			  p=(struct port *)(g_fdsdata[i]);
			  if(port != NULL && port != p && port->pg == p->pg) break;
		  }
		  if (p == NULL) {
			  printlog(LOG_WARNING,"portgroup inconsistency");
		  } else 
		  {
			  hash_reassign(port,p);
		  }
	  }
  }
  else {
	
	hash_delete_port(port);
  }
  
#ifdef INFO
 	 printlog(LOG_INFO,"Disconnect %d",port->control);
#endif
  free(port);
}

static void update_src(struct port *port, struct packet *p)
{
  struct port *last;

  /* We don't like broadcast source addresses */
  if(IS_BROADCAST(p->header.src)) return;  

  last = find_in_hash(p->header.src);

  if(last == NULL || (port != last && (port->pg == NULL || 
			  port->pg != last->pg))){
    /* old value differs from actual input port */

#ifdef INFO
	   printlog(LOG_INFO," Addr: %02x:%02x:%02x:%02x:%02x:%02x New port %d",
	   p->header.src[0], p->header.src[1], p->header.src[2],
	   p->header.src[3], p->header.src[4], p->header.src[5],
	   port->control);
#endif

    if(last != NULL){
#ifdef INFO
	    printlog(LOG_INFO," old port %d", last->control);
#endif
      delete_hash(p->header.src);
    }
    insert_into_hash(p->header.src, port);
  }
  update_entry_time(p->header.src);
}

static void send_dst(struct port *port, struct packet *packet, int len, 
		     int hub)
{
  struct port *target, *p;
  register int i;

  target = find_in_hash(packet->header.dest);
  if((target == NULL) || IS_BROADCAST(packet->header.dest) || hub){
#ifdef INFO
    if((target == NULL) && !IS_BROADCAST(packet->header.dest)){
      	if(port == NULL)
	      printlog(LOG_WARNING,"unknown Addr: %02x:%02x:%02x:%02x:%02x:%02x from port UNKNOWN",
	        packet->header.dest[0], packet->header.dest[1], 
	        packet->header.dest[2], packet->header.dest[3], 
	        packet->header.dest[4], packet->header.dest[5]);
	else
	      printlog(LOG_WARNING,"unknown Addr: %02x:%02x:%02x:%02x:%02x:%02x from port %d",
	        packet->header.dest[0], packet->header.dest[1], 
	        packet->header.dest[2], packet->header.dest[3], 
	        packet->header.dest[4], packet->header.dest[5], port->control);
    } 
#endif

    /* no cache or broadcast/multicast == all ports */
    for(i=g_minfds ; i<g_nfds ; i++) {
	    p=(struct port *)(g_fdsdata[i]);
	    if (p != NULL && ((p->pg == NULL && p != port) ||
				    p->pg != port->pg))
		    (*p->sender)(p->control, packet, len, p->data);
    }
  }
  else {
	if (target->pg == NULL) 
		(*target->sender)(target->control, packet, len, target->data);
	else if (target->pg != port->pg) {
		if (target->pg->counter == 1) 
			(*target->sender)(target->control, packet, len, target->data);
		else {
			for(i=g_minfds ; i<g_nfds ; i++) {
				p=(struct port *)(g_fdsdata[i]);
				if (p != NULL && p->pg == target->pg)
					(*p->sender)(p->control, packet, len, p->data);
			}
		}
	}
  }
}

static void handle_direct_data (struct port *p, int hub, struct packet *packet, int len)
{
  /* if we have an incoming port (we should) */
  if(p != NULL) update_src(p, packet);
#ifdef INFO
  else {
	  printlog(LOG_WARNING,"Unknown connection for packet, shouldn't happen.");
  }
#endif

  send_dst(p, packet, len, hub);  
}

  
void handle_tap_data(int i, int fd, int hub)
{
  struct packet packet;
  int len;
  struct port *port;

  len = read(fd, &packet, sizeof(packet));
  if(len < 0){
    if(errno != EAGAIN) printlog(LOG_WARNING,"Reading tap data %s",strerror(errno));
    return;
  }
  port=(struct port *)(g_fdsdata[i]);
  handle_direct_data(port, hub, &packet, len);
}

/* initialize a port structure with control=fd, given data+data_len and sender
 * function; add it to the port group given by identifier portgroup iff != 0,
 * and then add it to the g_fdsdata array at index i. */
int setup_port(int i, int fd, void (*sender)(int fd, void *packet, int len, 
				      void *data), void *data, int data_len, int portgroup)
{
  struct port *port;

  port = malloc(sizeof(struct port));
  if(port == NULL){
    printlog(LOG_WARNING,"malloc %s",strerror(errno));
    return(-1);
  }
  g_fdsdata[i]=port;
  port->control = fd;
  port->data = data;
  port->data_len = data_len;
  port->sender = sender;
  port->pg = NULL;
  if (portgroup != 0)
  {
	// search for other port on the same group
	  struct port *p=NULL; 
	  for(i=g_minfds ; i<g_nfds ; i++) { 
		  if (g_fdsdata != NULL) {
		    p=(struct port *)(g_fdsdata[i]);
		    if (p->pg != NULL && p->pg->ident == portgroup) {
			    port->pg=p->pg;
			    port->pg->counter++;
			    break;
		    }
		  }
	  }
		/* enlarge the structure if needed */
	  if (port->pg == NULL) 
	  { 
		  port->pg=malloc(sizeof(struct portgroup)); 
		  if(port->pg == NULL){ 
			  printlog(LOG_WARNING,"malloc %s",strerror(errno));
			  return(-1); 
		  } 
		  port->pg->ident=portgroup; 
		  port->pg->counter=1; 
	  }
  }
#ifdef INFO
  printlog(LOG_INFO,"New connection %d",fd);
#endif
  return(0);
}

struct sock_data {
  int fd;
  struct sockaddr_un sock;
};

static void send_sock(int fd, void *packet, int len, void *data)
{
  struct sock_data *mine = data;
  int err;
  
  do {
  	err = sendto(mine->fd, packet, len, 0, (struct sockaddr *) &mine->sock,
	       sizeof(mine->sock));
  } while (err == -1 && errno == EAGAIN);
  if(err != len)
	    printlog(LOG_WARNING, "send_sock sending to fd %d %s", mine->fd, strerror(errno));
}

//static int match_sock(int port_fd, int data_fd, void *port_data, 
		      //int port_data_len, void *data)
//{
  //struct sock_data *mine = data;
  //struct sock_data *port = port_data;
//
  //if(port_data_len != sizeof(*mine)) return(0);
  //return(!memcmp(&port->sock, &mine->sock, sizeof(mine->sock)));
//}

int handle_sock_data(int fd, int hub)
{
  struct packet packet;
  struct sock_data data;
  int len, socklen = sizeof(data.sock);
  struct port *p;
  register int i;
  struct sock_data *mine;
  struct sock_data *port;

  len = recvfrom(fd, &packet, sizeof(packet), 0, 
		 (struct sockaddr *) &data.sock, &socklen);
  if(len <= 0){
    if(len < 0 && errno != EAGAIN) printlog(LOG_WARNING,"handle_sock_data %s",strerror(errno));
    if (len == 0) return 1;
    else return 0;
  }
  data.fd = fd;

  p=NULL;
  for(i=g_minfds ; i<g_nfds ; i++) {
	    if (g_fdsdata[i] != NULL) { 
		    p=(struct port *)(g_fdsdata[i]); 
		    mine=&data;
		    port=p->data;
		    //if(match_sock(p->control, fd, p->data, p->data_len, &data)) break;
		    if(p->data_len == sizeof(struct sock_data) &&
				    !(memcmp(&(port->sock), &mine->sock, sizeof(mine->sock)))) break;
	    }
  }
  handle_direct_data(p,hub,&packet,len);
  return 0;
}

int handle_sock_direct_data(int i, int fd, int hub)
{
  struct packet packet;
  struct sock_data data;
  struct port *port;
  int len, socklen = sizeof(data.sock);

  len = recvfrom(fd, &packet, sizeof(packet), 0, 
		 (struct sockaddr *) &data.sock, &socklen);
  if(len <= 0){
    if(len < 0 && errno != EAGAIN) printlog(LOG_WARNING,"handle_sock_direct_data %s",strerror(errno));
    if (len == 0) return 1;
    else return 0;
  }
  data.fd = fd;

  port=(struct port *)(g_fdsdata[i]);
  handle_direct_data(port, hub, &packet, len);
  return 0;
}

int setup_sock_port(int i, int fd, struct sockaddr_un *name, int data_fd, int portgroup)
{
  struct sock_data *data;

  data = malloc(sizeof(*data));
  if(data == NULL){
    printlog(LOG_WARNING,"setup_sock_port %s",strerror(errno));
    return(-1);
  }
  *data = ((struct sock_data) { fd : 	data_fd,
				sock :	*name });
  return(setup_port(i, fd, send_sock, data, sizeof(*data), portgroup));
}

