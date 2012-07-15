/*
 * Copyright (c) 2012, Juniper Networks, Inc. All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 *
 * Minimal terminal emulator on a UNIX stream socket
 * Batch of commands can also be executed by specifying collection of
 * vde commands delimited by ';' or specifying the file name that
 * contains those vde commands.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

/* For ip sockets */
#include <arpa/inet.h>
#include <netdb.h> /* gethostbyname */
#include <errno.h>

#define	LOGOUT_CMD 	"logout"
#define	SHUTDOWN_CMD	"shutdown"

#define BUFSIZE		(4 * 1024)
#define	DELIMITER	";"
#define	IPSOCK_FILE_FIELD_LEN	256

static int
read_ctl_socket_file(char *sock_filename, char *server_name, int *server_port)
{
	FILE	*fp;
	char 	field_name[IPSOCK_FILE_FIELD_LEN];
	int	rc = -1;

	if ((fp = fopen(sock_filename, "r")) == NULL) {
		return(EIO);
	}
	if (fscanf(fp, "%s%s", field_name, server_name) == 2)
		if (fscanf(fp, "%s%d", field_name, server_port) == 2)
			rc = 0;
	fclose(fp);
	return (rc);
}

static void exec_cmd(int fd, char *cmd)
{
	int len;
	char buf[BUFSIZE];

	write(fd, cmd, (int)strlen(cmd));
	usleep(1024 * 128);
	if((strcmp(cmd, LOGOUT_CMD) != 0) && (strcmp(cmd, SHUTDOWN_CMD) != 0)) {
		printf("Reading for command: %s\n", cmd);
		bzero(buf, BUFSIZE);
		while ((len = read(fd, buf, BUFSIZE)) >= BUFSIZE)
			printf("%s", buf);
		buf[len] = 0;
		printf("%s\n", buf);
	} else {
		exit(0);
	}
}

static void process_cmd_string(int fd, char *cmd_str)
{
	char	*str;

	if (cmd_str[0] == '#') /* Comment, skip */
		return;

	/* extract first string from string sequence */
	str = strtok(cmd_str, DELIMITER);
	if (str == NULL)
		return;

	/* loop until finishied */
	while (1) {
		exec_cmd(fd, str);
		str = strtok(NULL, DELIMITER);
		if (str == NULL)
			break;
	}
}

static void process_cmd_file(int fd, char *filename)
{
	FILE	*fp;
	char	buffer[BUFSIZE];

	if ((fp = fopen(filename, "r")) == NULL) {
		printf("Could not open: %s\n", filename);
		return;
	}
	while (fgets(buffer, BUFSIZE, fp) != NULL) {
		process_cmd_string(fd, buffer);
	}
	fclose(fp);
}


static void execute_batch(int fd, char *arg)
{
	struct	stat st;
	int	filetype;

	if (stat(arg, &st) != 0) {
		process_cmd_string(fd, arg);
	} else {
		filetype = st.st_mode & S_IFMT;
		if (filetype == S_IFREG) {
			process_cmd_file(fd, arg);
		} else {
			printf("'%s' is neither a string nor a regular file\n",
				arg);
		}
	}
}

static void execute_interactive(int fd)
{
	static struct pollfd pfd[] = {
		{STDIN_FILENO,POLLIN | POLLHUP, 0},
		{STDIN_FILENO,POLLIN | POLLHUP, 0}};
	static int fileout[] = {STDOUT_FILENO, STDOUT_FILENO};
	char buf[BUFSIZE];

	pfd[1].fd = fileout[0] = fd;
	while(1) {
		int m, i, n = poll(pfd, 2, -1);
		for(i = 0; n > 0; i++) {
			if(pfd[i].revents & POLLHUP)
				exit(0);
			if(pfd[i].revents & POLLIN) {
				n--;
				if((m = read(pfd[i].fd,buf, BUFSIZE)) == 0)
					exit(0);
				write(fileout[i], buf, m);
			}
		}
	}
}

static int open_connection_ip(char *server_name, int server_port)
{
	int 	fd;
	struct sockaddr_in sockin;
	struct hostent *host;

	printf("Connecting to %s: %d ...\n", server_name, server_port);

	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(server_port);

	host = gethostbyname(server_name);
	if (host == NULL) {
		printf("Remote server %s not found", server_name);
		return (-1);
	}
    	memset(&(sockin.sin_zero), '\0', 8);

	sockin.sin_addr = *((struct in_addr *)host->h_addr);

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket() error ");
		return (-1);
	}

	if (connect(fd, (struct sockaddr *) &sockin,
		sizeof(struct sockaddr_in)) != 0) {
		printf("Connection to %s:%d failed",
			server_name, server_port);
		return(-1);
	}
	return (fd);
}

static int open_connection_ip_file(char *sock_filename)
{
	char	server_name[IPSOCK_FILE_FIELD_LEN];
	int	server_port;
	int rc;

	if ((rc = read_ctl_socket_file(sock_filename, server_name, &server_port))
		!= 0) {
		printf("Could not open MGT file: %s", sock_filename);
		return rc;
	}
	return open_connection_ip(server_name, server_port);
}

static int open_connection_unix(char *sock_filename)
{
	int fd, rv;
	struct sockaddr_un sun;

	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s", sock_filename);
	if((fd=socket(PF_UNIX,SOCK_STREAM,0))<0) {
		perror("Socket opening error");
		return(-1);
	}
	if ((rv=connect(fd,(struct sockaddr *)(&sun),sizeof(sun))) < 0) {
		perror("Socket connecting error");
		return(-1);
	}
	return (fd);
}

static int open_connection_file(char *sock_filename)
{

	struct	stat 	st;
	int	filetype;

	if (stat(sock_filename, &st) != 0) {
		printf("Error accessing file: %s\n", sock_filename);
		return (-1);
	}

	filetype = st.st_mode & S_IFMT;

	switch (filetype) {
		case S_IFREG:
		/*
		 * If its a regular file, then the file contains the IP
		 * and port information where we need to connect to using
		 * IP sockets, instead of the default UNIX sockets.
		 */
			printf("\nUsing IP SOCKETS for MGT(%s)\n", sock_filename);
			return(open_connection_ip_file(sock_filename));
			break;
		case S_IFSOCK:
			printf("\nUsing UNIX SOCKETS (%s) for MGT\n", sock_filename);
			return(open_connection_unix(sock_filename));
			break;
		default:
			printf("Unsupported socket file type: %X\n", filetype);
			break;
	}
	return (-1);
}

static void print_help(char *progname, int e)
{
	printf("Usage: %s <options>\n", progname);
	printf("\t-s: Server name\n");
	printf("\t-p: Port Number\n");
	printf("\t-c: Command/File with commands\n");
	printf("\t-f: File Name (unix sock or ip sock info file)\n");
	printf("\t-h: print this help\n");
	if (e)
		exit(0);
}

int main(int argc, char *argv[])
{
	char 	*server = NULL, *command = NULL, c;
	int	port = -1, fd = -1;
	char	*filename = NULL;

	if (argc <= 1)
		print_help(argv[0], 1);

	while ((c = getopt(argc, argv, "s:p:c:f:h")) != -1) {
		switch (c) {
		case 's':
			server = strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'c':
			command = strdup(optarg);
			break;
		case 'f':
			filename = strdup(optarg);
			break;
		case 'h':
			print_help(argv[0], 1);
			break;
		}
	}

	if (server && port > 0) {
		fd = open_connection_ip(server, port);
	} else if (filename) {
		fd = open_connection_file(filename);
	}

	if (fd <= 0)
		exit(1);

	if (command) {
		execute_batch(fd, command);
		exec_cmd(fd, LOGOUT_CMD);
	} else {
		execute_interactive(fd);
	}
	close(fd);
	return (0);
}
