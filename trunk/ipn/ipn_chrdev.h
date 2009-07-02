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

/* register a chr device range for this ipn network */
int ipn_register_chrdev(struct ipn_network *ipnn, struct chrdevreq *devr);
/* unregister the chr device of this ipn network */
int ipn_deregister_chrdev(struct ipn_network *ipnn);
/* set/unset persistence */
int ipn_chrdev_persistence(struct ipn_network *ipnn, int persistent);
/* test persistence */
int ipn_is_persistent_chrdev(struct ipn_network *ipnn);
/* search which ipn network registered a chr device */
struct ipn_network *ipn_find_chrdev(struct chrdevreq *devr);

#endif
