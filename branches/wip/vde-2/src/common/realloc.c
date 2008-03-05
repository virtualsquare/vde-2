#include <stdlib.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

#undef realloc

void * rpl_realloc(void *ptr, size_t size)
{
	void *mem;
	if (size <= 0){ /* For zero or less bytes, free the original memory */
		if (ptr) free(ptr);
		return NULL;
	}
	else if (!ptr) /* Allow reallocation of a NULL pointer.  */
		return malloc(size);
	else { /* Allocate a new block, copy and free the old block.  */
		mem=malloc(size);
		if (mem) {
			memcpy (mem, ptr, size);
			free(ptr);
		}
		/* Note that the contents of PTR are not damaged if there is
		   insufficient memory to realloc.  */
		return mem;
	}
}

