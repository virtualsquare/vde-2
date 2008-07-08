/*
 * Copyright (C) 2007 - Renzo Davoli, Luca Bigliardi
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/** 
 * @file cmdparse.h
 * @brief finite state automata for communication and parsing
 * @author Renzo Davoli, Luca Bigliardi
 * @date 2007-05-17
 */

#ifndef _CMDPARSE_H_
#define _CMDPARSE_H_

/** A state of automata */
struct utmstate;

/** Automata */
struct utm {
	struct utmstate *head;
	int timeout;
};

/** Automata buffer containing data read but not parsed yet.
 * State machine has finished to chomp whole parse buffer
 * when pos == len
 */
struct utm_buf {
	char *buf;
	int len;
	int pos;
};

/** Automata output.
 * In a parse machine is possible to build a list of outputs,
 * each element can be tagged.
 */
struct utm_out {
	char *buf;
	size_t sz;
	int tag;
	struct utm_out *next;
};

/** 
 * @brief utmout_alloc - create an empty automata output buffer
 * 
 * @return pointer to the empty buffer, NULL if error
 */
struct utm_out *utmout_alloc(void);

/** 
 * @brief utmout_free - safe destroy output buffer list
 * 
 * @param out automata output buffer list to free
 */
void utmout_free(struct utm_out *out);

/** 
 * @brief utm_alloc - create finite state automata
 * 
 * @param conf configuration file containing the list of states
 * 
 * @return finite state automata on success, NULL on error
 */
struct utm *utm_alloc(char *conf);

/** 
 * @brief utm_free - free finite state automata structure
 * 
 * @param utm finite state automata to destroy
 */
void utm_free(struct utm *utm);

/** 
 * @brief utm_run
 * 
 * @param utm finite state automata
 * @param buf automata buffer (related to fd)
 * @param fd file descriptor to read and write to
 * @param argc number of arguments in argv
 * @param argv NULL terminated list of arguments
 * @param out output buffer of machine
 * @param debug run machine in verbose mode
 * 
 * @return exit value of machine, it depends to configuration
 */
int utm_run(struct utm *utm, struct utm_buf *buf, int fd, int argc, char **argv, struct utm_out *out, int debug);

#endif
