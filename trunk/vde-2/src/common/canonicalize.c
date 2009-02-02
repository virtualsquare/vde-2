/*
 * Return the canonical absolute name of a given file.
 * Copyright (C) 1996-2001, 2002 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 * Modified for um-viewos (C) Renzo Davoli 2005-2006
 * Simplified for VDE (c) Ludovico Gardenghi 2008

 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>
#include <config.h>

/*
 * Return the canonical absolute name of file NAME.  A canonical name does not
 * contain any `.', `..' components nor any repeated path separators ('/') or
 * symlinks.  All path components must exist.  ; otherwise, if the canonical
 * name is PATH_MAX chars or more, returns null with `errno' set to
 * ENAMETOOLONG; if the name fits in fewer than PATH_MAX chars, returns the
 * name in RESOLVED.  If the name cannot be resolved and RESOLVED is non-NULL,
 * it contains the path of the first component that cannot be resolved.  If
 * the path can be resolved, RESOLVED holds the same value as the value
 * returned.
 */

char *vde_realpath(const char *name, char *resolved)
{
	char *dest, *extra_buf=NULL;
	const char *start, *end, *resolved_limit; 
	char *resolved_root = resolved + 1;
	char *ret_path = NULL;
	int num_links = 0;
	int validstat = 0;
	struct stat pst;

	if (!name || !resolved)
	{
		errno = EINVAL;
		goto abort;
	}

	if (name[0] == '\0')
	{
		/* As per Single Unix Specification V2 we must return an error if
		   the name argument points to an empty string.  */
		errno = ENOENT;
		goto abort;
	}

	if ((extra_buf=(char *)calloc(PATH_MAX, sizeof(char)))==NULL) {
		errno = ENOMEM;
		goto abort;
	}

	resolved_limit = resolved + PATH_MAX;

	/* relative path, the first char is not '/' */
	if (name[0] != '/')
	{
		if (!getcwd(resolved, PATH_MAX))
		{
			resolved[0] = '\0';
			goto abort;
		}

		dest = strchr (resolved, '\0');
	}
	else
	{
		/* absolute path */
		dest = resolved_root;
		resolved[0] = '/';

		/* special case "/" */
		if (name[1] == 0)
		{
			*dest = '\0';
			ret_path = resolved;
			goto cleanup;
		}
	}

	/* now resolved is the current wd or "/", navigate through the path */
	for (start = end = name; *start; start = end)
	{
		int n;

		/* Skip sequence of multiple path-separators.  */
		while (*start == '/')
			++start;

		/* Find end of path component.  */
		for (end = start; *end && *end != '/'; ++end);

		if (end - start == 0)
			break;
		else if (end - start == 1 && start[0] == '.')
			/* nothing */;
		else if (end - start == 2 && start[0] == '.' && start[1] == '.')
		{
			/* Back up to previous component, ignore if at root already.  */
			validstat = 0;
			if (dest > resolved_root)
				while ((--dest)[-1] != '/');
		}
		else
		{
			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) >= resolved_limit)
			{
				errno = ENAMETOOLONG;
				if (dest > resolved_root)
					dest--;
				*dest = '\0';
				goto abort;
			}

			/* copy the component, don't use mempcpy for better portability */
			dest = (char*)memcpy(dest, start, end - start) + (end - start);
			*dest = '\0';

			/*check the dir along the path */
			validstat = 1;
			if (lstat(resolved, &pst) < 0)
				goto abort;
			else
			{
				/* this is a symbolic link, thus restart the navigation from
				 * the symlink location */
				if (S_ISLNK (pst.st_mode))
				{
					char buf[PATH_MAX];
					size_t len;

					if (++num_links > MAXSYMLINKS)
					{
						errno = ELOOP;
						goto abort;
					}

					/* symlink! */
					validstat = 0;
					n = readlink (resolved, buf, PATH_MAX);
					if (n < 0)
						goto abort;

					buf[n] = '\0';

					len = strlen (end);
					if ((long) (n + len) >= PATH_MAX)
					{
						errno = ENAMETOOLONG;
						goto abort;
					}

					/* Careful here, end may be a pointer into extra_buf... */
					memmove (&extra_buf[n], end, len + 1);
					name = end = memcpy (extra_buf, buf, n);

					if (buf[0] == '/')
						dest = resolved_root;	/* It's an absolute symlink */
					else
						/* Back up to previous component, ignore if at root already: */
						if (dest > resolved + 1)
							while ((--dest)[-1] != '/');
				}
				else if (*end == '/' && !S_ISDIR(pst.st_mode))
				{
					errno = ENOTDIR;
					goto abort;
				}
				else if (*end == '/')
				{
					if (access(resolved, X_OK) != 0)
					{
						errno = EACCES;
						goto abort;
					}
				}
			}
		}
	}
	if (dest > resolved + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	ret_path = resolved;
	goto cleanup;

abort:
	ret_path = NULL;
cleanup:
	if (extra_buf) free(extra_buf);
	return ret_path;
}
