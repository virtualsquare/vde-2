#ifndef _IPN_CHRDEV_H
#define _IPN_CHRDEV_H
/*
 * Inter process networking (virtual distributed ethernet) module
 * Char device support
 *
 * Copyright (C) 2009   Renzo Davoli (renzo@cs.unibo.it)
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
#include "af_ipn.h"

int ipn_register_chrdev(struct ipn_network *ipnn, struct chrdevreq *devr);
int ipn_deregister_chrdev(struct ipn_network *ipnn);

#endif
