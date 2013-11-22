#ifndef VDE_PLUG_H
#define VDE_PLUG_H

#define MAXDESCR 128
#define CONNECTED_P2P

struct vdeplug_module; 
struct vdeconn {
	struct vdeplug_module *module;
	unsigned char data[];
};

#define ONLY_BY_CHECK 1

struct vdeplug_module {
	int flags;
	char *(* vde_check)(char *given_sockname);
	VDECONN *(* vde_open_real)(char *given_sockname, char *descr,int interface_version,
			    struct vde_open_args *open_args);
	ssize_t (* vde_recv)(VDECONN *conn,void *buf,size_t len,int flags);
	ssize_t (* vde_send)(VDECONN *conn,const void *buf,size_t len,int flags);
	int (* vde_datafd)(VDECONN *conn);
	int (* vde_ctlfd)(VDECONN *conn);
	int (* vde_close)(VDECONN *conn);
};

#endif
