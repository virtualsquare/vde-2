/* Copyright 2005 Renzo Davoli - VDE-2
 * Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 *
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */ 

#ifndef _SOCKUTILS_H
#define _SOCKUTILS_H

int still_used(struct sockaddr_un *sun);
int still_used_ipsock(struct sockaddr_in *sin);

#endif
