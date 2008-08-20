/*
 * libvdehist - A library to manage history and command completion for vde mgmt protocol
 * Copyright (C) 2006 Renzo Davoli, University of Bologna
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


#ifndef _LIBVDEHIST_H
#define _LIBVDEHIST_H

extern char *prompt;

typedef ssize_t (* ssize_fun)();
extern ssize_fun vdehist_vderead;
extern ssize_fun vdehist_vdewrite;
extern ssize_fun vdehist_termread;
extern ssize_fun vdehist_termwrite;

#define HIST_COMMAND 0x0
#define HIST_NOCMD 0x1
#define HIST_PASSWDFLAG 0x80

struct vdehiststat;

extern char *(* vdehist_logincmd)(char *cmd,int len,struct vdehiststat *st);

void vdehist_mgmt_to_term(struct vdehiststat *st);
int vdehist_term_to_mgmt(struct vdehiststat *st);
struct vdehiststat *vdehist_new(int termfd,int mgmtfd);
void vdehist_free(struct vdehiststat *st);

int vdehist_getstatus(struct vdehiststat *st);
void vdehist_setstatus(struct vdehiststat *st,int status);

int vdehist_gettermfd(struct vdehiststat *st);

int vdehist_getmgmtfd(struct vdehiststat *st);
void vdehist_setmgmtfd(struct vdehiststat *st,int mgmtfd);

#endif
