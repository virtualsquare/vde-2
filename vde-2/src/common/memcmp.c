#include <config.h>
#include <vde.h>
#include <vdecommon.h>

int memcmp(const void *v1, const void *v2, size_t n)
{
	if (n != 0) {
		const unsigned char *s1=v1, *s2=v2;
		do {
			if (*s1++ != *s2++) return *--s1 - *--s2;
		} while (--n != 0);
	}
	return 0;
} 

