/*
 * Copyright (C) 2007 - Luca Bigliardi
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
 * @file libvdemgmt.h
 * @brief Functions for console management handling, client side.
 * @author Luca Bigliardi
 * @date 2007-05-16
 */

#ifndef _LIBVDEMGMT_H_
#define _LIBVDEMGMT_H_

/** A console management connection */
struct vdemgmt;

/**
 * @brief vdemgmt_open - Connect to console management socket.
 *
 * @param path of console management socket
 * @return pointer to a struct vdemgmt, NULL if error
 */
extern struct vdemgmt *vdemgmt_open(const char *path);

/** 
 * @brief vdemgmt_close - Close a console management connection. 
 * 
 * @param conn structure of connection that you want to close
 */
extern void vdemgmt_close(struct vdemgmt *conn);

/** 
 * @brief vdemgmt_getfd - Extract file descriptor of a console connection.
 * 
 * @param conn structure of connection
 * 
 * @return integer representing file descriptor, -1 if error
 */
extern int vdemgmt_getfd(struct vdemgmt *conn);

/** Container of output from a synchronous command. */
struct vdemgmt_out {
	char *buf;
	size_t sz;
};

/** 
 * @brief vdemgmt_freeout - Free vdemgmt_out data structure
 * 
 * @param out data structure
 */
extern void vdemgmt_freeout(struct vdemgmt_out *out);

/** 
 * @brief vdemgmt_rstout - Empty vdemgmt_out data structure
 * 
 * @param out data structure
 */
extern void vdemgmt_rstout(struct vdemgmt_out *out);

/** 
 * @brief vdemgmt_sendcmd - Send a synchronous command 
 * 
 * @param conn structure of connection to send command to
 * @param cmd command to send
 * @param out pointer to an output container, if NULL the output is discarded
 * 
 * @return the same return value of command executed
 */
extern int vdemgmt_sendcmd(struct vdemgmt *conn, const char *cmd, struct vdemgmt_out *out);

/** 
 * @brief vdemgmt_asyncreg - Register func handler for async output from debug events
 * 
 * @param conn structure of connection to activate debug events to
 * @param event debug feature to activate
 * @param callback the handler
 * 
 * @return 0 on success, error code otherwise
 */
extern int vdemgmt_asyncreg(struct vdemgmt *conn, const char *event, void (*callback)(const char *event, const int tag, const char *data) );

/** 
 * @brief vdemgmt_asyncunreg - Unregister func handler for async output from debug events
 * 
 * @param conn structure of connection to deactivate debug events to
 * @param event debug feature to deactivate
 * 
 * @return 0 on success, error code otherwise
 */
extern void vdemgmt_asyncunreg(struct vdemgmt *conn, const char *event);

/** 
* @brief vdemgmt_asyncrecv - Call appropriate handler when an asynchronous output is incoming
* 
* @param conn connection from whom asynchronous data is incoming
*/
extern void vdemgmt_asyncrecv(struct vdemgmt *conn);

/** 
 * @brief vdemgmt_getbanner - Get banner received from management socket
 * 
 * @param conn structure of connection
 * 
 * @return const pointer to banner string
 */
extern const char *vdemgmt_getbanner(struct vdemgmt *conn);

/** 
 * @brief vdemgmt_getprompt - Get prompt received from management socket
 * 
 * @param conn structure of connection
 * 
 * @return const pointer to prompt string
 */
extern const char *vdemgmt_getprompt(struct vdemgmt *conn);

/** 
 * @brief vdemgmt_getversion - Get version received from management socket
 * 
 * @param conn structure of connection
 * 
 * @return const pointer to version string
 */
extern const char *vdemgmt_getversion(struct vdemgmt *conn);

/** 
* @brief vdemgmt_commandlist - Retrieve list of commands available from management socket
* 
* @param conn structure of connection
* 
* @return array of string NULL terminated, NULL if error
*/
extern char **vdemgmt_commandlist(struct vdemgmt *conn);

/** 
* @brief vdemgmt_freecommandlist - Free array returned from vdemgmt_commandlist
* 
* @param *cl array of string NULL terminated
*/
extern void vdemgmt_freecommandlist(char **cl);

#endif
