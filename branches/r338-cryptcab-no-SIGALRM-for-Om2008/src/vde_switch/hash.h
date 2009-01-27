/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 */

#ifndef __HASH_H__
#define __HASH_H__

extern int find_in_hash(unsigned char *dst,int vlan);
extern int find_in_hash_update(unsigned char *dst,int vlan,int port);
extern void delete_hash(unsigned char *dst,int vlan);
extern void hash_init(int hash_size);
extern void hash_delete_port(int port);
extern void hash_delete_vlanport(int vlan,int port);
extern void hash_delete_vlan (int vlan);

#endif
