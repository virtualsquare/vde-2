#ifndef _OSDEP_H
#define _OSDEP_H

/* fake osdep.h to minimize the differences between
	 qemu slirp and vde slirp support */

#ifdef CONFIG_NEED_OFFSETOF
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member) ({                      \
		const typeof(((type *) 0)->member) *__mptr = (ptr);     \
		(type *) ((char *) __mptr - offsetof(type, member));})
#endif

#endif
