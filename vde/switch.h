/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __SWITCH_H__
#define __SWITCH_H__

#define ETH_ALEN 6
void printlog(int priority, const char *format, ...);

extern void **g_fdsdata;
extern int g_nfds;
extern int g_minfds;

#endif
