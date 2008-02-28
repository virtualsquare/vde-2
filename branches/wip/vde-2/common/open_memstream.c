/*
 * Copyright (C) 2005 Richard Kettlewell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

/* BSD-compatible implementation of open_memstream */

#if HAVE_FUNOPEN
struct memstream {
  char *buffer;
  size_t size, space;

  char **ptr;
  size_t *sizeloc;
};

static int memstream_writefn(void *u, const char *buffer, int bytes) {
  struct memstream *m = u;
  size_t needed = m->size + bytes + 1;
  size_t newspace;
  char *newbuffer;
  
  assert(bytes >= 0);
  if(needed > m->space) {
    newspace = m->space ? m->space : 32;
    while(newspace && newspace < needed)
      newspace *= 2;
    if(!newspace) {
      errno = ENOMEM;
      return -1;
    }
    if(!(newbuffer = realloc(m->buffer, newspace)))
      return -1;
    m->buffer = newbuffer;
    m->space = newspace;
  }
  memcpy(m->buffer + m->size, buffer, bytes);
  m->size += bytes;
  m->buffer[m->size] = 0;
  
  *m->ptr = m->buffer;
  *m->sizeloc = m->size;
  return bytes;
}

FILE *open_memstream(char **ptr, size_t *sizeloc) {
  struct memstream *m;

  if(!(m = malloc(sizeof *m))) return 0;
  m->buffer = 0;
  m->size = 0;
  m->space = 0;
  m->ptr = ptr;
  m->sizeloc = sizeloc;
  *ptr = 0;
  *sizeloc = 0;
  return funopen(m,
                 0,                     /* read */
                 memstream_writefn,
                 0,                     /* seek */
                 0);                    /* close */
}
#endif

