/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 */

#ifndef __HASH_H__
#define __HASH_H__

extern void *find_in_hash(char *dst);
extern void insert_into_hash(char *src, void *port);
extern void delete_hash(char *dst);
extern void print_hash(char *(*port_id)(void *));
extern void update_entry_time(char *src);
extern void hash_init(void);
extern void hash_reassign(void *port, void *newport);
extern void hash_delete_port(void *port);

#endif
