/* Copyright 2007 Renzo Davoli 
 * Licensed under the GPLv2
 */

#ifndef _TCP2UNIX_H
#define _TCP2UNIX_H

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

extern int tcp2unix_check;

void tcp2unix_add(int port,char *path);
char *tcp2unix_search(int port);

#endif
