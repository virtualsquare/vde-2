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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <config.h>
#include <utils/cmdparse.h>
#include "libvdemgmt.h"

#ifndef HAVE_STRNDUP
#include <utils/strndup.h>
#endif

#define OPENMACHINE_RC INSTALLPATH"/etc/libvdemgmt/openmachine.rc"
#define CLOSEMACHINE_RC INSTALLPATH"/etc/libvdemgmt/closemachine.rc"
#define SENDCMD_RC INSTALLPATH"/etc/libvdemgmt/sendcmd.rc"
#define ASYNCRECV_RC INSTALLPATH"/etc/libvdemgmt/asyncrecv.rc"

#define DEBUGADD "debug/add"
#define DEBUGDEL "debug/del"

#define CHECK(expr, errval)  { if ((expr) == (errval)) { perror(__func__); goto error; } }
#define CHECKNOT(expr, retval)  { if ((expr) != (retval)) { perror(__func__); goto error; } }

#define DATATAG 1
#define ASYNTAG 3

#define SKIPHEAD 5

#define DBGM 0

static struct utm* open_utm=NULL;
static struct utm* close_utm=NULL;
static struct utm* sendcmd_utm=NULL;
static struct utm* asyncrecv_utm=NULL;

struct asynctab {
	const char *event;
	void (*callback)(const char *event, const char *data);
	struct asynctab *next;
};

struct vdemgmt {
	int fd;
	struct asynctab *atab;
	struct utm_buf *pbuf;
	const char *banner;
	const char *prompt;
	const char *version;
};

/*
 * INTERNAL
 */

struct asynctab *atab_find(struct asynctab *atab, const char *event)
{
	if(!atab) return atab;

	if(!strncmp(atab->event, event, strlen(atab->event))) return atab;
	else return atab_find(atab->next, event);

}

struct asynctab *atab_add(struct asynctab *atab, struct asynctab *new)
{
	if(!atab){
		new->next=atab;
		return new;
	}else{
		atab->next=atab_add(atab->next, new);
		return atab;
	}
}

struct asynctab *atab_del(struct asynctab *atab, const char *event)
{
	if(!atab) return atab;

	if(!strncmp(atab->event, event, strlen(atab->event))){
		struct asynctab *t=atab->next;
		free(atab);
		return t;
	} else {
		atab->next=atab_del(atab->next, event);
		return atab;
	}
}

static int qstrcmp(const void *a,const void *b)
{
	return strcmp(*(char * const *)a,*(char * const *)b);
}


/*
 * INTERFACE
 */

/* open vdemgmt connection */
struct vdemgmt *vdemgmt_open(const char *path)
{

	struct sockaddr_un sun;
	struct vdemgmt *conn;
	struct utm_out *out;
	int myargc=0;
	char *myargv = NULL, *sep;

	if(!open_utm)
		CHECK( open_utm = utm_alloc(OPENMACHINE_RC) , NULL );
	if(!close_utm)
		CHECK( close_utm = utm_alloc(CLOSEMACHINE_RC) , NULL );
	if(!sendcmd_utm)
		CHECK( sendcmd_utm = utm_alloc(SENDCMD_RC) , NULL );
	if(!asyncrecv_utm)
		CHECK( asyncrecv_utm = utm_alloc(ASYNCRECV_RC) , NULL );

	/* vdemgmt connection struct */
	CHECK( conn = (struct vdemgmt*)malloc(sizeof(struct vdemgmt)) , NULL );
	memset(conn, 0, sizeof(struct vdemgmt));
	CHECK( conn->pbuf = (struct utm_buf*)malloc(sizeof(struct utm_buf)) , NULL );
	memset(conn->pbuf, 0, sizeof(struct utm_buf));

	/* connect to management socket (non block fd) */
        sun.sun_family=PF_UNIX;
        snprintf(sun.sun_path,sizeof(sun.sun_path),"%s", path);
        conn->fd = socket(PF_UNIX,SOCK_STREAM,0);
	CHECK( fcntl(conn->fd, F_SETFL, O_NONBLOCK) , -1 );
	CHECK( connect(conn->fd,(struct sockaddr *)(&sun),sizeof(sun)) , -1 );

	conn->atab = NULL;

	/* get welcome data */
	out=utmout_alloc();
	CHECKNOT( utm_run(open_utm,conn->pbuf,conn->fd,myargc,&myargv,out,DBGM), 0 );

	/* split banner / prompt and extract version */
	for( sep=out->buf+out->sz ; ! strstr(sep, "\n") ; sep--);
	conn->banner = strndup(out->buf, sep - out->buf-1);
	conn->prompt = strndup(sep+1, (out->buf+out->sz)-sep+1);
	sep=strstr(conn->banner, "V.")+2;
	conn->version = strndup(sep, strstr(sep, "\n")-sep);

	utmout_free(out);

	return conn;

error:
	if(conn){
		if(conn->pbuf){
			if(conn->pbuf->buf)
				free(conn->pbuf->buf);
			free(conn->pbuf);
		}
		if(conn->fd)
			close(conn->fd);
		free(conn);
	}
	return NULL;
}

/* close vdemgmt connection */
void vdemgmt_close(struct vdemgmt *conn)
{

	int myargc=0;
	char *myargv = NULL;
	struct utm_out *out;

	/* Deactivate all async events */
	while(conn->atab) vdemgmt_asyncunreg(conn, conn->atab->event);

	/* logout */
	out=utmout_alloc();
	utm_run(close_utm,conn->pbuf,conn->fd,myargc,&myargv,out,DBGM);
	utmout_free(out);

	close(conn->fd);
	if(conn->pbuf->buf)
		free(conn->pbuf->buf);
	free(conn->pbuf);
	free((char *)conn->banner);
	free((char *)conn->prompt);
	free((char *)conn->version);
	free(conn);
}

/* return file descriptor of vdemgmt connection */
int vdemgmt_getfd(struct vdemgmt *conn)
{
	if(conn)
		return conn->fd;
	else
		return -1;
}

/* send command cmd and wait for its output */
int vdemgmt_sendcmd(struct vdemgmt *conn, const char *cmd, struct vdemgmt_out *out)
{

	int rv=-1, myargc=0;
	char *token, *dupcmd, **myargv = NULL;
	struct utm_out *utmout, *p;
	struct asynctab *t=NULL;

	/* create myargv array from cmd */
	for( dupcmd=strdup(cmd) ; ; dupcmd=NULL){
		token = strtok(dupcmd, " ");
		myargv=realloc(myargv, (myargc+1)*sizeof(char *));
		if(!myargv) exit(1);
		myargv[myargc]=token;
		if( !token ) break;
		myargc++;
	};

	/* send command using machine */
	utmout=utmout_alloc();
	rv=utm_run(sendcmd_utm,conn->pbuf,conn->fd,myargc,myargv,utmout,DBGM);

	/* scan machine data for sync and async output */
	p=utmout;
	while(p) {
		if( (p->tag == DATATAG) && out) {
			out->sz = p->sz;
			out->buf=(char *)malloc(p->sz*sizeof(char));
			if(!out->buf) { perror(__func__); exit(-1);}
			memcpy(out->buf, p->buf, p->sz);
		}
		if( p->tag == ASYNTAG ){
			t=atab_find(conn->atab, out->buf+SKIPHEAD);
			if(t) t->callback(t->event, out->buf+strlen(t->event)+SKIPHEAD+1);
		}
		p=p->next;
	}

	utmout_free(utmout);

	return rv;
}

/* free outbuffer returned by vdemgmt_sendcmd */
void vdemgmt_freeout(struct vdemgmt_out *out)
{
	if(out){
		if(out->buf) free(out->buf);
		free(out);
	}
}

/* reset outbuffer after vdemgmt_sendcmd, */
void vdemgmt_rstout(struct vdemgmt_out *out)
{
	if(out){
		if(out->buf) free(out->buf);
		out->buf = NULL;
		out->sz = 0;
	}
}

/* register func as handler for asyncronous output received with command cmd */
int vdemgmt_asyncreg(struct vdemgmt *conn, const char *event, void (*callback)(const char *event, const char *data) )
{

	struct asynctab *new = NULL;
	char *swcmd = NULL;
	int rv=-1;

	if( atab_find(conn->atab, event) ) return rv;

	/* Activate debug */
	CHECK( asprintf(&swcmd,"%s %s",DEBUGADD,event) , -1 );
	CHECKNOT( rv=vdemgmt_sendcmd(conn, swcmd , NULL) , 0);
	free(swcmd); swcmd=NULL;

	/* Add callback function to connection's async tab */
	CHECK( new = (struct asynctab*)malloc(sizeof(struct asynctab)) , NULL );
	memset(new, 0, sizeof(struct asynctab));
	new->event = strdup(event);
	new->callback = callback;
	new->next = NULL;
	conn->atab=atab_add(conn->atab, new);

	return 0;

error:
	if(swcmd) free(swcmd);
	return rv;
}

/* unregister asyncronous output callback for command cmd */
void vdemgmt_asyncunreg(struct vdemgmt *conn, const char *event)
{
	char *swcmd = NULL;

	/* Dectivate debug on switch */
	CHECK( asprintf(&swcmd,"%s %s",DEBUGDEL,event) , -1 );
	CHECKNOT( vdemgmt_sendcmd(conn, swcmd , NULL) , 0);

error:
	if(swcmd) free(swcmd);
	conn->atab=atab_del(conn->atab, event);
}

/* handle asyncronous output */
void vdemgmt_asyncrecv(struct vdemgmt *conn)
{
	int myargc=0;
	char *myargv=NULL;
	struct utm_out *out;
	struct asynctab *t;

	out=utmout_alloc();
	
	/* run async machine and call the handler for the event */
	do {
		CHECKNOT( utm_run(asyncrecv_utm,conn->pbuf,conn->fd,myargc,&myargv,out,DBGM), 0 );
		t=atab_find(conn->atab, out->buf+SKIPHEAD);
		if(t) t->callback(t->event, out->buf+strlen(t->event)+SKIPHEAD+1);
	} while ( conn->pbuf->len > conn->pbuf->pos );

error:
	utmout_free(out);

}

const char *vdemgmt_getbanner(struct vdemgmt *conn)
{
	return conn->banner;
}

const char *vdemgmt_getprompt(struct vdemgmt *conn)
{
	return conn->prompt;
}

const char *vdemgmt_getversion(struct vdemgmt *conn)
{
	return conn->version;
}

char **vdemgmt_commandlist(struct vdemgmt *conn)
{
	int i=0, j, ncommands;
	char *p=NULL, *s=NULL, **out=NULL, *es="";
	struct vdemgmt_out buf;

	memset(&buf, 0, sizeof(struct vdemgmt_out));

	CHECKNOT(vdemgmt_sendcmd(conn, "help", &buf), 0);
	p=buf.buf;
	/* skip head */
	while(strncmp(p,"------------",12)) p++;
	p=strstr(p,"\n")+2;
	/* extract command list */
	while( p < buf.buf + buf.sz){
		s=p;
		while (*s && *s!=' ' && *s!='\t') s++;
		out=realloc(out, (i+1)*sizeof(char *));
		out[i]=strndup(p, s-p);
		p=strstr(p, "\n")+2;
		i++;
	}
	ncommands=i;
	/* delete menu entries */
	for(j=0; j<i-1; j++){
		if (!strncmp(out[j],out[j+1],strlen(out[j])) &&
				out[j+1][strlen(out[j])] == '/') {
			free(out[j]); out[j]=es;
			ncommands--;
		}
	}
	/* sort and resize array */
	qsort(out,i,sizeof(char *),qstrcmp);
	memmove(out, out+(i-ncommands), ncommands*sizeof(char *));
	out=realloc(out, (ncommands+1)*sizeof(char *));
	out[ncommands]=NULL;

	return out;

error:
	return NULL;
}

void vdemgmt_freecommandlist(char **cl)
{
	int i=0;
	while(cl[i]){ free(cl[i]); cl[i]=NULL; i++; }
	free(cl);
}

/* test

void handle(const char *e, const char *d){
	printf("--received %s--\n%s\n--\n", e, d);
}

int main(int argc, char **argv){

	struct vdemgmt *conn;
	struct vdemgmt_out buf;
	char **cl;
	int rv=-1, i=0;

	memset(&buf, 0, sizeof(struct vdemgmt_out));

	if(argc < 2) {printf("bad cmd\n"); exit(-1);}
	conn = vdemgmt_open(argv[1]);
	printf("--open done--\n");
	printf("--command list--\n");
	cl=vdemgmt_commandlist(conn);
	{int j=0;
	while(cl[j]){
	printf("%d, %s\n", j, cl[j]); j++;}}
	vdemgmt_freecommandlist(cl);
	printf("--end command list--\n");
	printf("--parsebuf--\n");
	write(1, conn->pbuf->buf + conn->pbuf->pos, conn->pbuf->len - conn->pbuf->pos);
	printf("\n--end parsebuf--\n");

	printf("--banner is--\n%s\n--\n", vdemgmt_getbanner(conn));
	printf("--prompt is--\n%s\n--\n", vdemgmt_getprompt(conn));
	printf("--version is--\n%s\n--\n", vdemgmt_getversion(conn));

	rv = vdemgmt_sendcmd(conn, "port/allprint", NULL);
	printf("--null send done--\n");
	printf("--parsebuf--\n");
	write(1, conn->pbuf->buf + conn->pbuf->pos, conn->pbuf->len - conn->pbuf->pos);
	printf("\n--end parsebuf--\n");
	
	rv = vdemgmt_sendcmd(conn, "fstp/print", &buf);
	printf("--send done--\n");
	write(1, buf.buf, buf.sz);

	printf("--async reg--\n");
	rv=vdemgmt_asyncreg(conn, "fstp/root", &handle);
	printf("--return is: %d\n", rv);
	vdemgmt_rstout(&buf);
	vdemgmt_sendcmd(conn, "debug/list", &buf);
	write(1, buf.buf, buf.sz);
	printf("--async re-reg--\n");
	rv=vdemgmt_asyncreg(conn, "fstp/root", &handle);
	printf("--return is: %d\n", rv);
	printf("--begin cycle\n");
	for(i=0; i < 3; i++){
		struct pollfd pfd={vdemgmt_getfd(conn), POLLIN, 0};
		poll(&pfd,1,-1);
		vdemgmt_asyncrecv(conn);
	}
	printf("--end cycle\n");
	printf("--async unreg--\n");
	vdemgmt_asyncunreg(conn, "fstp/root");
	vdemgmt_rstout(&buf);
	vdemgmt_sendcmd(conn, "debug/list", &buf);
	write(1, buf.buf, buf.sz);

	vdemgmt_close(conn);

	return rv;


}

*/
