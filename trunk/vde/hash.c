/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 * This file is part of the original uml_switch code
 * Modified 2003 Renzo Davoli
 */

#include <config.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>

#include <switch.h>
#include <hash.h>

#define HASH_SIZE 128
#define HASH_MOD 11

struct hash_entry {
  struct hash_entry *next;
  struct hash_entry *prev;
  time_t last_seen;
  void *port;
  unsigned char dst[ETH_ALEN];
};

static struct hash_entry *h[HASH_SIZE];

static int calc_hash(char *src)
{
  return ((*(u_int32_t *) &src[0] % HASH_MOD) ^ src[4] ^ src[5] ) % HASH_SIZE ;
}

static struct hash_entry *find_entry(char *dst)
{
  struct hash_entry *e;
  int k = calc_hash(dst);

  for(e = h[k]; e; e = e->next){
    if(!memcmp(&e->dst, dst, ETH_ALEN)) return(e);
  }
  return(NULL);  
}

void *find_in_hash(char *dst)
{
  struct hash_entry *e = find_entry(dst);
  if(e == NULL) return(NULL);
  return(e->port);
}

void insert_into_hash(char *src, void *port)
{
  struct hash_entry *new;
  int k = calc_hash(src);

  new = find_in_hash(src);
  if(new != NULL) return;

  new = malloc(sizeof(*new));
  if(new == NULL){
    printlog(LOG_WARNING,"Failed to malloc hash entry %s",strerror(errno));
    return;
  }

  memcpy(&new->dst, src, ETH_ALEN );
  if(h[k] != NULL) h[k]->prev = new;
  new->next = h[k];
  new->prev = NULL;
  new->port = port;
  new->last_seen = 0;
  h[k] = new;
}

void update_entry_time(char *src)
{
  struct hash_entry *e;

  e = find_entry(src);
  if(e == NULL) return;
  e->last_seen = time(NULL);
}

static void delete_hash_entry(struct hash_entry *old)
{
  int k = calc_hash(old->dst);

  if(old->prev != NULL) old->prev->next = old->next;
  if(old->next != NULL) old->next->prev = old->prev;
  if(h[k] == old) h[k] = old->next;
  free(old);
}

void delete_hash(char *dst)
{
  struct hash_entry *old = find_entry(dst);

  if(old == NULL) return;
  delete_hash_entry(old);
}

static void for_all_hash(void (*f)(struct hash_entry *, void *), void *arg)
{
  int i;
  struct hash_entry *e, *next;

  for(i = 0; i < HASH_SIZE; i++){
    for(e = h[i]; e; e = next){
      next = e->next;
      (*f)(e, arg);
    }
  }
}

struct printer {
  time_t now;
  char *(*port_id)(void *);
};

static void print_hash_entry(struct hash_entry *e, void *arg)
{
  struct printer *p = arg;

  printf("Hash: %d Addr: %02x:%02x:%02x:%02x:%02x:%02x to port: %s  " 
	 "age %ld secs\n", calc_hash(e->dst),
	 e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5],
	 (*p->port_id)(e->port), (int) p->now - e->last_seen);
}

void print_hash(char *(*port_id)(void *))
{
  struct printer p = ((struct printer) { now : 		time(NULL),
					 port_id :	port_id });

  for_all_hash(print_hash_entry, &p);
}

struct reassign_data {
	void *port;
	void *newport;
};

static void reassing_iterator (struct hash_entry *e, void *arg)
{
	struct reassign_data *p=arg;

	if (e->port == p->port)
		e->port = p->newport;
}

void hash_reassign (void *port, void *newport)
{
	struct reassign_data p=((struct reassign_data) { port : port,
							newport : newport });
	for_all_hash(reassing_iterator, &p);
}

static void delete_port_iterator (struct hash_entry *e, void *arg)
{
	if (e->port == arg)
		delete_hash_entry(e);
}

void hash_delete_port (void *port)
{
	for_all_hash(delete_port_iterator,port);
}


#define GC_INTERVAL 2
#define GC_EXPIRE 100

static void gc(struct hash_entry *e, void *now)
{
  time_t t = *(time_t *) now;

  if(e->last_seen + GC_EXPIRE < t)
    delete_hash_entry(e);
}

static void sig_alarm(int sig)
{
  struct itimerval it;
  time_t t = time(NULL);
  for_all_hash(&gc, &t);

  it.it_value.tv_sec = GC_INTERVAL;
  it.it_value.tv_usec = 0 ;
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 0 ;
  setitimer(ITIMER_REAL, &it, NULL);
}

void hash_init(void)
{
  struct sigaction sa;

  sa.sa_handler = sig_alarm;
  sa.sa_flags = SA_RESTART;
  if(sigaction(SIGALRM, &sa, NULL) < 0){
    printlog(LOG_WARNING,"Setting handler for SIGALRM %s", strerror(errno));
    return;
  }
  kill(getpid(), SIGALRM);
}
