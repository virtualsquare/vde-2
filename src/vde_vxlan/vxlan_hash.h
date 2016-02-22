/*
 * VDE - vde_vxlan Network emulator for vde
 * Copyright (C) 2014 Renzo Davoli, Alessandro Ghedini VirtualSquare
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <netinet/in.h>

#ifndef __HASH_H__
#define __HASH_H__

extern int find_in_hash(unsigned char *dst, int vlan, in_addr_t *out);
extern int find_in_hash_update(unsigned char *dst, int vlan, in_addr_t port, in_addr_t *out);

extern in_addr_t find_in_hash_v6(unsigned char *dst, int vlan, unsigned char *out);
extern in_addr_t find_in_hash_update_v6(unsigned char *dst, int vlan, unsigned char *port, unsigned char *out);

extern void hash_gc(void);

extern void hash_init(int hash_size);

#endif
