#ifndef _QEMU_COMMON_H
#define _QEMU_COMMON_H

/* fake qemu_common.h to minimize the differences between
	 qemu slirp and vde slirp support */

#ifndef MIN
#define MIN(X,Y) ((X)<(Y)?(X):(Y))
#endif

#endif
