#ifndef _VDELIB_H
#define _VDELIB_H
#include <sys/types.h>
#define LIBVDEPLUG_INTERFACE_VERSION 1

struct vdeconn;

typedef struct vdeconn VDECONN;

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
VDECONN *vde_open_real(char *vde_switch,char *descr,int interface_version,
	struct vde_open_args *open_args);

ssize_t vde_recv(VDECONN *conn,char *buf,size_t len,int flags);

ssize_t vde_send(VDECONN *conn,const char *buf,size_t len,int flags);

/* for select/poll when this fd receive data, there are packets to recv
 * (call vde_recv) */
int vde_datafd(VDECONN *conn);

/* for select/poll. the ctl socket is silent after the initial handshake.
 * when EOF the switch has closed the connection */
int vde_ctlfd(VDECONN *conn);

int vde_close(VDECONN *conn);

#endif
