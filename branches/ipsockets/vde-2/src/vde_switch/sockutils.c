/* Copyright 2005 Renzo Davoli - VDE-2
 * Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
 *
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */ 

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <libgen.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "switch.h"
#include "consmgmt.h"

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <netinet/in.h>

/* check to see if given unix socket is still in use; if it isn't, remove the
 *  * socket from the file system */
int still_used(struct sockaddr_un *sun)
{
	int test_fd, ret = 1;

	if((test_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		printlog(LOG_ERR,"socket %s",strerror(errno));
		return(1);
	}
	if(connect(test_fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
		if(errno == ECONNREFUSED){
			if(unlink(sun->sun_path) < 0){
				printlog(LOG_ERR,"Failed to removed unused socket '%s': %s",
						sun->sun_path,strerror(errno));
			}
			ret = 0;
		}
		else printlog(LOG_ERR,"connect %s",strerror(errno));
	}
	close(test_fd);
	return (ret);
}

/* check to see if given unix socket is still in use; if it isn't, remove the
 *  * socket from the file system */
int still_used_ipsock(struct sockaddr_in *sin)
{
	int test_fd, ret = 1;

	if((test_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printlog(LOG_ERR,"socket %s",strerror(errno));
		return(1);
	}
	if(connect(test_fd, (struct sockaddr *) sin, sizeof(*sin)) < 0) {
		if(errno == ECONNREFUSED) {
			ret = 0;
		}
		else printlog(LOG_ERR,"connect %s",strerror(errno));
	}
	close(test_fd);
	return (ret);
}

