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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

#define STD_SOCK_DIR INSTALLPATH"/var/run"
#define STD_RC_DIR INSTALLPATH"/etc/vde2"

void usage(char *progname){
	/* TODO: write it better */
	printf("Usage: %s OPTIONS command\n", progname);
	printf("\t-s sockname  management socket path (default is %s/%s)\n", STD_SOCK_DIR, basename(progname));
	printf("\t-f rcfile    configuration path (default is %s/%s)\n", STD_RC_DIR, basename(progname));
	printf("\t-v           run parse machine in debug mode\n");
}

int main(int argc,char *argv[])
{
	struct sockaddr_un sun;
	int fd, rv;
	char *rcfile=NULL;
	char *sockname=NULL;
	int debug=0;

	struct utm *utm;
	struct utm_out *outbuf;
	struct utm_buf parsebuf;

	int option_index = 0;
	static struct option long_options[] = {
		{"rcfile", 1, 0, 'f'},
		{"sock", 1, 0, 's'},
		{"verbose", 0, 0, 'v'},
	};
	int c;
	while ((c=getopt_long (argc, argv, "f:s:v",
					long_options, &option_index)) >= 0)
	{
		switch (c) {
			case 'f': rcfile=strdup(optarg); break;
			case 's': sockname=strdup(optarg); break;
			case 'v': debug=1; break;
		}
	}

	if(argc-optind == 0){ usage(argv[0]); return -1; }

	if (!rcfile) asprintf(&rcfile,"%s/%s",STD_RC_DIR,basename(argv[0]));
	if( (utm=utm_alloc(rcfile)) == NULL ) { perror("alloc parse machine"); usage(argv[0]); return -1;}

	if (!sockname) asprintf(&sockname,"%s/%s",STD_SOCK_DIR,basename(argv[0]));
	sun.sun_family=PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s",sockname);
	fd=socket(PF_UNIX,SOCK_STREAM,0);
	if(fcntl(fd, F_SETFL, O_NONBLOCK) < 0){ perror("nonblock"); return -1; }
	if( connect(fd,(struct sockaddr *)(&sun),sizeof(sun)) ){ perror("connect"); return -1; }

	memset(&parsebuf, 0, sizeof(struct utm_buf));
	outbuf=utmout_alloc();

	rv=utm_run(utm,&parsebuf,fd,argc-optind,argv+optind,outbuf,debug);
	if(outbuf->sz) write(1, outbuf->buf, outbuf->sz);
	utmout_free(outbuf);
	close(fd);

	return rv;
}
