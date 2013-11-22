/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013 Renzo Davoli, University of Bologna
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/types.h>

#define MAXPACKET 2046
#ifndef MIN
#define MIN(X,Y) (((X)<(Y))?(X):(Y))
#endif

struct vdestream {
	void *opaque;
	int fdout;
	ssize_t (*frecv)(void *opaque, void *buf, size_t count);
	void (*ferr)(void *opaque, int type, char *format, ...);
	char fragment[MAXPACKET];
	char *fragp;
	unsigned int rnx,remaining;
};

VDESTREAM *vdestream_open(void *opaque,
		int fdout,
		ssize_t (*frecv)(void *opaque, void *buf, size_t count),
		void (*ferr)(void *opaque, int type, char *format, ...)
		)
{
	VDESTREAM *vdestream;
	if ((vdestream=calloc(1,sizeof(struct vdestream)))==NULL) {
		errno=ENOMEM;
		return NULL;
	} else {
		vdestream->opaque=opaque;
		vdestream->fdout=fdout;
		vdestream->frecv=frecv;
		vdestream->ferr=ferr;
		return vdestream;
	}
}

ssize_t vdestream_send(VDESTREAM *vdestream, const void *buf, size_t len)
{
	if (len <= MAXPACKET) {
		unsigned char header[2];
		struct iovec iov[2]={{header,2},{(void *)buf,len}};
		header[0]=len >> 8;
		header[1]=len & 0xff;
		return writev(vdestream->fdout,iov,2);
	} else
		return 0;
}

void vdestream_recv(VDESTREAM *vdestream, unsigned char *buf, size_t len)
{
	//fprintf(stderr,"%s: splitpacket rnx=%d remaining=%d size=%d\n",myname,rnx,vdestream->remaining,len);
	if (len==0) return;
	if (vdestream->rnx>0) {
		register int amount=MIN(vdestream->remaining,len);
		//fprintf(stderr,"%s: fragment amount %d\n",myname,amount);
		memcpy(vdestream->fragp,buf,amount);
		vdestream->remaining-=amount;
		vdestream->fragp+=amount;
		buf+=amount;
		len-=amount;
		if (vdestream->remaining==0) {
			//fprintf(stderr,"%s: delivered defrag %d\n",myname,vdestream->rnx);
			vdestream->frecv(vdestream->opaque,vdestream->fragment,vdestream->rnx);
			vdestream->rnx=0;
		}
	}
	while (len > 1) {
		vdestream->rnx=(buf[0]<<8)+buf[1];
		len-=2;
		//fprintf(stderr,"%s %d: packet %d size %d %x %x\n",myname,getpid(),vdestream->rnx,len,buf[0],buf[1]);
		buf+=2;
		if (vdestream->rnx == 0)
			continue;
		if (vdestream->rnx > MAXPACKET) {
			if (vdestream->ferr != NULL)
				vdestream->ferr(vdestream->opaque,PACKET_LENGTH_ERROR,
						"size %d expected size %d",len,vdestream->rnx);
			vdestream->rnx=0;
			return;
		}
		if (vdestream->rnx > len) {
			//fprintf(stderr,"%s: begin defrag %d\n",myname,vdestream->rnx);
			vdestream->fragp=vdestream->fragment;
			memcpy(vdestream->fragp,buf,len);
			vdestream->remaining=vdestream->rnx-len;
			vdestream->fragp+=len;
			len=0;
		} else {
			//fprintf(stderr,"%s: deliver %d\n",myname,vdestream->rnx);
			vdestream->frecv(vdestream->opaque,buf,vdestream->rnx);
			buf+=vdestream->rnx;
			len-=vdestream->rnx;
			vdestream->rnx=0;
		}
	}
}

void vdestream_close(VDESTREAM *vdestream)
{
	free(vdestream);
}

