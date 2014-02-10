/*
 * VDE - libvdeplug_vx modules 
 * Copyright (C) 2014 Renzo Davoli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#ifndef LIBVDEPLUG_VXHASH_H
#define LIBVDEPLUG_VXHASH_H

/* look in global hash table for given address, and return associated sockaddr */
struct sockaddr *vx_find_in_hash(void *table, int sa_family, int hash_mask,
		unsigned char *dst, int vlan, time_t too_old);

/* update the address associated to a MAC address*/
void vx_find_in_hash_update(void *table, int hash_mask,
		unsigned char *src, int vlan, struct sockaddr *addr, time_t now);

/* init the hash table */
/* hash_mask must be 2^n - 1 */
void *vx_hash_init(int sa_family, int hash_mask);

void vx_hash_fini(void *table);
#endif

