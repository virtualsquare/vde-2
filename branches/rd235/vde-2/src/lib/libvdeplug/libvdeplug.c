/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013 Renzo Davoli, University of Bologna
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libvdeplug.h>
#include "libvdeplug_mod.h"

/* Per-User standard switch definition */
/* This will be prefixed by getenv("HOME") */
/* it can be a symbolic link to the switch dir */
#define STDSWITCH "/.vde2/default.switch"

extern struct vdeplug_module vdeplug_vde;
extern struct vdeplug_module vdeplug_kvde;
extern struct vdeplug_module vdeplug_udp;
extern struct vdeplug_module vdeplug_ptpf;
extern struct vdeplug_module vdeplug_ptpm;
extern struct vdeplug_module vdeplug_vxlan;
extern struct vdeplug_module vdeplug_vxvde;
//extern struct vdeplug_module vdeplug_gvde;

static struct vdeplug_module *modules[]={
	&vdeplug_vde,
	&vdeplug_kvde,
	&vdeplug_udp,
	&vdeplug_ptpf,
	&vdeplug_ptpm,
	&vdeplug_vxlan,
	&vdeplug_vxvde,
	//&vdeplug_gvde,
};

#define NVDE_MODS sizeof(modules)/sizeof(struct vdeplug_module *)

VDECONN *vde_open_real(char *given_sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	int i;
	char std_sockname[PATH_MAX];
	struct stat statbuf;
	struct vdeplug_module *module=NULL;
	char newdescr[MAXDESCR];
	int descrlen;
	struct passwd *callerpwd;
	char *ssh_client = getenv("SSH_CLIENT");
	int pid = getpid();

	callerpwd=getpwuid(getuid());
	//fprintf(stderr, "LIBVDEPLUG OPEN! %s\n",given_sockname);

	descrlen=snprintf(newdescr,MAXDESCR,"%s user=%s PID=%d",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid);

	if (ssh_client) {
		char *endofip=strchr(ssh_client,' ');
		if (endofip) *endofip=0;
		descrlen+=snprintf(newdescr+descrlen,MAXDESCR-descrlen,
				" SSH=%s", ssh_client);
		if (endofip) *endofip=' ';
	}

	if (given_sockname == NULL || *given_sockname == '\0') {
		char *homedir = getenv("HOME");
		if (homedir) {
			char *stdswitch;
			asprintf(&stdswitch, "%s%s", homedir, STDSWITCH);
			if (readlink(stdswitch,std_sockname,PATH_MAX) < 0)
				std_sockname[0]=0;
			free(stdswitch);
			given_sockname=std_sockname;
		}
	}
	if (lstat(given_sockname,&statbuf) >= 0) {
		if (S_ISREG(statbuf.st_mode)) {
			FILE *f=fopen(given_sockname,"r");
			if (f) {
				fgets(std_sockname,PATH_MAX,f);
				std_sockname[strlen(std_sockname)-1] = 0;
				given_sockname=std_sockname;
				fclose(f);
			}
		}
	}
	for (i=0; i<NVDE_MODS; i++) {
		char *new_sockname;
		if ((new_sockname=modules[i]->vde_check(given_sockname))!=NULL) {
			module=modules[i];
			given_sockname=new_sockname;
			return module->vde_open_real(given_sockname, newdescr, 
					interface_version, open_args);
		}
	}
	for (i=0; i<NVDE_MODS; i++) {
		VDECONN *rv;
		char given_sockname_copy[strlen(given_sockname)+1];
		strcpy(given_sockname_copy,given_sockname);
		if ((modules[i]->flags & ONLY_BY_CHECK)==0 &&
				(rv=modules[i]->vde_open_real(given_sockname_copy, newdescr, 
																			interface_version, open_args)) != NULL)
			return rv;
	}
	return NULL;
}

ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) 
		return conn->module->vde_recv(conn,buf,len,flags);
	else {
		errno=EBADF;
		return -1;
	}
}

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) 
		return conn->module->vde_send(conn,buf,len,flags);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_datafd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->module->vde_datafd(conn);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_ctlfd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->module->vde_ctlfd(conn);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_close(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->module->vde_close(conn);
	else {
		errno=EBADF;
		return -1;
	}
}
