#ifndef OPEN_MEMSTREAM_H__
#define OPEN_MEMSTREAM_H__
#ifndef HAVE_OPEN_MEMSTREAM

#include <stdio.h>

FILE *open_memstream(char **ptr, size_t *sizeloc);

#else

#define _GNU_SOURCE
#include <stdio.h>

#endif
#endif
