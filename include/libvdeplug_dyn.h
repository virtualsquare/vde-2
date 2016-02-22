/*
 * libvdeplug - A library to connect to a VDE Switch.
 * dynamic loading version (requires libdl).
 *
 * Copyright (C) 2006,2007 Renzo Davoli, University of Bologna
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

/* Use this include file when you need to write an application that can
 * benefit from vde when available. 
 * Linking libvdeplug to your programs you force your application users
 * to have the library installed (otherway the dynamic linker complies
 * and the program does not start).
 *
 * 
 * usage:
 * define a struct vdepluglib variable;
 * eg:
 *         struct vdepluglib vdeplug;
 *
 * test the availability of the library and load it:
 *
 *         libvdeplug_dynopen(vdeplug);
 * if vdeplug.dl_handle is not NULL the library is ready otherwise it is
 * not available in the target system.
 *
 * if libvdeplug does exist the library function can be called
 * in this way:
 *         vdeplug.vde_open(....)
 *         vdeplug.vde_read(....)
 *         vdeplug.vde_open(....)
 *         vdeplug.vde_recv(....)
 *         vdeplug.vde_send(....)
 *         vdeplug.vde_datafd(....)
 *         vdeplug.vde_ctlfd(....)
 *         vdeplug.vde_close(....)
 * libvdeplug_dynclose(vdeplug) can be used to deallocate the dynamic library
 * when needed.
 *************************************************/

#ifndef _VDEDYNLIB_H
#define _VDEDYNLIB_H
#include <sys/types.h>
#include <dlfcn.h>
#define LIBVDEPLUG_INTERFACE_VERSION 1

struct vdeconn;
typedef struct vdeconn VDECONN;

struct vdestream;
typedef struct vdestream VDESTREAM;

/* Open a VDE connection.
 * vde_open_options:
 *   port: connect to a specific port of the switch (0=any)
 *   group: change the ownership of the communication port to a specific group
 *        (NULL=no change)
 *   mode: set communication port mode (if 0 standard socket mode applies)
 */
struct vde_open_args {
	int port;
	char *group;
	mode_t mode;
};
	
/* vde_open args:
 *   vde_switch: switch id (path)
 *   descr: description (it will appear in the port description on the switch)
 */
#define vde_open(vde_switch,descr,open_args) \
	vde_open_real((vde_switch),(descr),LIBVDEPLUG_INTERFACE_VERSION,(open_args))

struct vdepluglib {
	void *dl_handle;
	VDECONN * (*vde_open_real)(const char *vde_switch,char *descr,int interface_version, struct vde_open_args *open_args);
	ssize_t (* vde_recv)(VDECONN *conn,void *buf,size_t len,int flags);
	ssize_t (* vde_send)(VDECONN *conn,const void *buf,size_t len,int flags);
	int (* vde_datafd)(VDECONN *conn);
	int (* vde_ctlfd)(VDECONN *conn);
	int (* vde_close)(VDECONN *conn);
	VDESTREAM * (* vdestream_open)(void *opaque, int fdout,
			ssize_t (* frecv)(void *opaque, void *buf, size_t count),
			void (* ferr)(void *opaque, int type, char *format, ...)
			);
	ssize_t (* vdestream_send)(VDESTREAM *vdestream, const void *buf, size_t len);
	void (* vdestream_recv)(VDESTREAM *vdestream, unsigned char *buf, size_t len);
	void (* vdestream_close)(VDESTREAM *vdestream);
};

typedef VDECONN * (* VDE_OPEN_REAL_T)(const char *vde_switch,char *descr,int interface_version, struct vde_open_args *open_args);
typedef ssize_t (* VDE_RECV_T)(VDECONN *conn,void *buf,size_t len,int flags);
typedef ssize_t (* VDE_SEND_T)(VDECONN *conn,const void *buf,size_t len,int flags);
typedef int (* VDE_INT_FUN)(VDECONN *conn);
typedef VDESTREAM * (* VDESTREAM_OPEN_T)(void *opaque, int fdout,
			ssize_t (* frecv)(void *opaque, void *buf, size_t count),
			void (* ferr)(void *opaque, int type, char *format, ...)
			);              
typedef ssize_t (* VDESTREAM_SEND_T)(VDESTREAM *vdestream, const void *buf, size_t len);
typedef void (* VDESTREAM_RECV_T)(VDESTREAM *vdestream, unsigned char *buf, size_t len);
typedef void (* VDESTREAM_CLOSE_T)(VDESTREAM *vdestream);

#define libvdeplug_dynopen(x) ({ \
	(x).dl_handle=dlopen("libvdeplug.so",RTLD_NOW); \
	if ((x).dl_handle) { \
		(x).vde_open_real=(VDE_OPEN_REAL_T) dlsym((x).dl_handle,"vde_open_real"); \
		(x).vde_recv=(VDE_RECV_T) dlsym((x).dl_handle,"vde_recv"); \
		(x).vde_send=(VDE_SEND_T) dlsym((x).dl_handle,"vde_send"); \
		(x).vde_datafd=(VDE_INT_FUN) dlsym((x).dl_handle,"vde_datafd"); \
		(x).vde_ctlfd=(VDE_INT_FUN) dlsym((x).dl_handle,"vde_ctlfd"); \
		(x).vde_close=(VDE_INT_FUN) dlsym((x).dl_handle,"vde_close"); \
		(x).vdestream_open=(VDESTREAM_OPEN_T) dlsym((x).dl_handle,"vdestream_open"); \
		(x).vdestream_send=(VDESTREAM_SEND_T) dlsym((x).dl_handle,"vdestream_send"); \
		(x).vdestream_recv=(VDESTREAM_RECV_T) dlsym((x).dl_handle,"vdestream_recv"); \
		(x).vdestream_close=(VDESTREAM_CLOSE_T) dlsym((x).dl_handle,"vdestream_close"); \
		} else { \
		(x).vde_open_real=NULL; \
		(x).vde_send= NULL; \
		(x).vde_recv= NULL; \
		(x).vde_datafd= (x).vde_ctlfd= (x).vde_close= NULL; \
		(x).vdestream_open= NULL; \
		(x).vdestream_send= NULL; \
		(x).vdestream_recv= NULL; \
		(x).vdestream_close= NULL; \
		}\
		})

#define libvdeplug_dynclose(x) ({ \
		dlclose((x).dl_handle); \
		})

#endif
