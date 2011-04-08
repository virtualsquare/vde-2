/* Return the canonical absolute name of a given file.
	 Copyright (C) 1996-2001, 2002 Free Software Foundation, Inc.
	 This file is part of the GNU C Library.
	 Modified for um-viewos (C) Renzo Davoli 2005-2006
	 Simplified for VDE (c) Ludovico Gardenghi 2008

	 The GNU C Library is free software; you can redistribute it and/or
	 modify it under the terms of the GNU Lesser General Public
	 License as published by the Free Software Foundation; either
	 version 2.1 of the License, or (at your option) any later version.

	 The GNU C Library is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 Lesser General Public License for more details.

	 You should have received a copy of the GNU Lesser General Public
	 License along with the GNU C Library; if not, write to the Free
	 Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
	 02110-1301 USA.  */

#ifndef CANONICALIZE_H
#define CANONICALIZE_H

char *vde_realpath(const char *name, char *resolved);

#endif
