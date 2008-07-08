/*
 * Inter process networking (virtual distributed ethernet) module
 * management of msgbuf (one slab for each MTU)
 *  (part of the View-OS project: wiki.virtualsquare.org) 
 *
 * Copyright (C) 2007   Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 * WARNING: THIS CODE IS ALREADY EXPERIMENTAL
 *
 */

#ifndef _IPN_MSGBUF_H
#define _IPN_MSGBUF_H

struct kmem_cache *ipn_msgbuf_get(int mtu);
void ipn_msgbuf_put(struct kmem_cache *cache);
int ipn_msgbuf_init(void);
void ipn_msgbuf_fini(void);

#endif
