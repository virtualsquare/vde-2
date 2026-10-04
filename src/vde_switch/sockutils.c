/* Copyright 2005 Renzo Davoli - VDE-2
 * Mattia Belletti (C) 2004.
 * Licensed under the GPLv2
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
#include <sys/stat.h>
#include "switch.h"
#include "consmgmt.h"

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

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
	return(ret);
}

/*
 * Prepare a path for binding a unix socket: refuse symlinks and
 * non-socket files (a local attacker must not be able to redirect
 * the root-owned bind), remove a stale socket that is not in use.
 * Returns 0 when the path can be bound.
 */
int prepare_socket_path(struct sockaddr_un *sun)
{
	struct stat st;

	if (lstat(sun->sun_path, &st) < 0) {
		if (errno == ENOENT)
			return 0;
		printlog(LOG_ERR, "lstat %s: %s", sun->sun_path, strerror(errno));
		return -1;
	}
	if (S_ISLNK(st.st_mode)) {
		printlog(LOG_ERR, "refusing to bind on symlink %s", sun->sun_path);
		return -1;
	}
	if (!S_ISSOCK(st.st_mode)) {
		printlog(LOG_ERR, "%s exists and is not a socket", sun->sun_path);
		return -1;
	}
	return still_used(sun) ? -1 : 0;
}

