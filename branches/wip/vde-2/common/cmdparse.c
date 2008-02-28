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

#include "config.h"
#include "vde.h"
#include "vdecommon.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>



#define BUFSIZE 256
#define TIMEOUT 10000

enum command {ERR, IN, THROW, SEND, SHIFT, IF, GOTO, COPY, EXIT, EXITRV, SKIP, IFARG, RVATOI, OUTSHIFT, OUTTAG};

char *commandname[]= {
	"",
	"IN", 
	"THROW", 
	"SEND", 
	"SHIFT", 
	"IF", 
	"GOTO", 
	"COPY", 
	"EXIT", 
	"EXITRV",
	"SKIP",
	"IFARG",
	"RVATOI",
	"OUTSHIFT",
	"OUTTAG"
};

#define NUMCOMMANDS (sizeof(commandname)/sizeof(char *))

static const char *nullstring="";

struct utmstate {
	int num;
	enum command command;
	const char *string;
#define value nextnum;
	int nextnum;
	struct utmstate *next;
};

static struct utmstate *utmsadd(struct utmstate *head, struct utmstate *this)
{
	if (!head || head->num > this->num) {
		this->next=head;
		return this;
	} else {
		head->next=utmsadd(head->next,this);
		return head;
	}
}

static enum command searchcommand(char *name)
{
		int i;
		for (i=0; i<NUMCOMMANDS && strcmp(name,commandname[i]) != 0; i++)
			;
		if (i<NUMCOMMANDS) 
			return i;
		else
			return ERR;
}

static inline char *blankskip(char *s)
{
	while (*s && (*s==' ' || *s=='\t'))
		s++;
	return s;
}

static inline char *fieldskip(char *s)
{
	while (*s && *s!=' ' && *s!='\t' && *s!='\n') 
		s++;
	return s;
}

static int readchar(int fd, struct utm_buf *inbuf, char *out, int timeout)
{
	if (!inbuf->buf) {
		inbuf->buf=(char *)malloc(sizeof(char)*BUFSIZE);
		if(!inbuf->buf) { perror("readchar"); exit(-1); }
		inbuf->len=inbuf->pos=0;
	}
	if (inbuf->len <= inbuf->pos)
	{
		struct pollfd pfd={fd, POLLIN, 0};
		if (poll(&pfd,1,timeout) <= 0) {
			return -1;
		}
		inbuf->len=read(fd,inbuf->buf,BUFSIZE);
		if (inbuf->len==0)
			return -1;
		else
			inbuf->pos=0;
	}
	*out = (inbuf->buf[(inbuf->pos)++]);
	return 0;
}

struct utmstate *sgoto(struct utmstate *head,int nextnum)
{
	if (head) {
		if (nextnum == head->num)
			return head;
		else
			return sgoto(head->next,nextnum);
	} else {
		//fprintf(stderr,"Error Label not found: %d\n",nextnum);
		return NULL;
	}
}

void utm_freestate(struct utmstate *head)
{
	struct utmstate* rest = head->next;
	free(head);
	utm_freestate(rest);
}

struct utm *utm_alloc(char *conf)
{
	FILE *f;
	struct utm *utm=NULL;
	int line=0;
	char buf[BUFSIZE];
	if ((f=fopen(conf,"r")) == NULL) {
		//fprintf(stderr,"Configuration file error %s\n",conf);
		errno=ENOENT;
		return NULL;
	}
	utm=(struct utm*)malloc(sizeof(struct utm));
	if(!utm) {perror("utm_alloc"); exit(-1); }
	utm->timeout=TIMEOUT ; utm->head = NULL;
	while (fgets(buf,BUFSIZE,f) != NULL) {
		char *s=buf;
		int num;
		line++;
		s=blankskip(s);
		num=atoi(s);
		if (num>0) {
			/* create new automata state */
			enum command cmd;
			char *currfield;
			char c;
			s=fieldskip(s);
			s=blankskip(s);
			currfield=s;
			s=fieldskip(s);
			c=*s;*s=0;
			if ((cmd=searchcommand(currfield)) != ERR) {
				struct utmstate *new=malloc(sizeof(struct utmstate));
				if(!new) {perror("utm_alloc"); exit(-1); }
				new->num = num;
				new->command = cmd;
				*s=c;
				s=blankskip(s);
				currfield=s;
				if (*currfield=='\'') { /* first argument is a string */
					char *t;
					char skip=0; /*not escaped*/
					t=currfield=++s; /* skip ' */
					while (*s && (skip || *s != '\'')) {
						if (*s == '\\' && *(s+1) != 0) {
							s++; /* skip \ */
							switch (*s) {
								case 'n': *s='\n'; break;
								case 't': *s='\t'; break;
								case 'f': *s='\f'; break;
							}
						}
						*t++ = *s++;
					}
					c=*s;*t=0;
					new->string=strdup(currfield);
					if (c) s++;
					s=blankskip(s);
					currfield=s;
				} else {
					new->string=nullstring;
				}
				new->nextnum=atoi(currfield);
				utm->head=utmsadd(utm->head,new);
			}
		} else {
			/* add constant definition */
			if (strncmp("TIMEOUT",s,7)==0)
				utm->timeout=atoi(s+8);
		}
	}
	fclose(f);
	return(utm);
}

void utm_free(struct utm *utm)
{
	if(utm){
		if(utm->head) utm_freestate(utm->head);
		free(utm);
	}
}

int utm_run(struct utm *utm, struct utm_buf *buf, int fd, int argc, char **argv, struct utm_out *out, int debug)
{
	struct utmstate *status = utm->head;
	int len=0, curr=0, linebufsize=0, rv=-1;
	char *linebuf=NULL;

	if(debug) {int i; printf("c: %d\n", argc); for(i=0; i <=argc ; i++) printf("a[%d]: %s\n", i, argv[i]); }

	while (1) {
		int patlen=strlen(status->string);
		if (debug) printf("NOW %d parsing %s\n",status->num,linebuf?(linebuf+curr):NULL);
		switch (status -> command) {
			case ERR: /* error, return */
				if(linebuf) free(linebuf);
				return -1;
				break;
			case IN: /* eat from inbuf while timeout or pattern found */
				{
					int ltimeout=0;
					do {
						if (len==linebufsize) {
							linebufsize += BUFSIZE;
							linebuf=realloc(linebuf,sizeof(char)*(linebufsize+1));
							if(!linebuf){ perror("utm_run"); exit(-1); }
						}
						if (readchar(fd, buf, &linebuf[len], utm->timeout) < 0)
							ltimeout=1;
						else
							len++;
					} while (!ltimeout && (len < patlen || strncmp(status->string,linebuf+(len-patlen),patlen) != 0));
					linebuf[len]=0;
					if(ltimeout)
						status=sgoto(utm->head,status->nextnum);
					else
						status=status->next;
				}
				break;
			case THROW: /* drop current linebuf */
				curr=0;
				if(linebuf) *linebuf=0;
				len=0;
				status=status->next;
				break;
			case SEND: /* write command to fd */
				{
					const char *t=status->string;
					char *ptr;
					size_t size;
					FILE *mf=open_memstream(&ptr,&size);
					while (*t) { /* create the string */
						if (*t == '$' && (t==status->string || *(t-1) != '\\')) {
							t++;
							if (*t == '*' || *t == '0') { /*all parms*/
								int i;
								for (i=0;i<argc;i++) {
									if (i) fprintf(mf," ");
									fprintf(mf,argv[i]);
								}
							} else {
								int num=atoi(t);
								while (*t >='0' && *t <= '9') t++;
								if (num < argc) 
									fprintf(mf,argv[num]);
							}
						} else
							fprintf(mf,"%c",*t);
						t++;
					}
					fclose(mf);
					write (fd,ptr,size);
					free(ptr);
				}
				status=status->next;
				break;
			case SHIFT: /* eat first argument */
				argc--; argv++;
				status=status->next;
				break;
			case IF: /* goto nextnum if pattern match */
				if (linebuf && (strncmp(linebuf+curr,status->string,patlen) == 0) )
					status=sgoto(utm->head,status->nextnum);
				else
					status=status->next;
				break;
			case GOTO: /* simple goto */
				status=sgoto(utm->head,status->nextnum);
				break;
			case COPY: /* copy current linebuf to current outbuf */
				if(linebuf){
					int tocpy=strlen(linebuf+curr)+1;
					out->buf=realloc(out->buf, out->sz+tocpy);
					if(!out->buf){ perror("utm_run"); exit(-1); }
					memcpy(out->buf+out->sz, linebuf+curr, tocpy);
					out->sz+=tocpy;
				}
				status=status->next;
				break;
			case EXIT: /* exit with value */
				rv = status->nextnum;
			case EXITRV: /* exit with retval */
				if(linebuf) free(linebuf);
				return rv;
				break;
			case SKIP: /* skip after the first occurence of string or N chars */
				if(linebuf){
					char *skip=NULL;
					if(strlen(status->string)) skip=strstr(linebuf, status->string);
					if(skip) curr=(status->string+strlen(status->string))-linebuf;
					else curr+=status->nextnum;
					if(curr>len) curr=len; /* normalize */
				}
				status=status->next;
				break;
			case IFARG: /* goto if there are still arguments */
				if (argc>=0)
					status=sgoto(utm->head,status->nextnum);
				else
					status=status->next;
				break;
			case RVATOI: /* remember current number as return value the
						optional argument is the base to convert from*/
				if(!linebuf){
					rv = -1;
				}else if( status->nextnum <= 0 ){
					rv = strtol(linebuf+curr, NULL, 10);
				}else if( status->nextnum >= 2 && status->nextnum <= 36 ){
					rv = strtol(linebuf+curr, NULL, status->nextnum);
				}else{
					rv = -1;
				}
				status=status->next;
				break;
			case OUTSHIFT: /* alloc another output buffer and use it */
				out->next=utmout_alloc();
				out=out->next;
				status=status->next;
				break;
			case OUTTAG: /* set tag of current output buffer */
				out->tag=status->nextnum;
				status=status->next;
				break;
			default:
				if(linebuf) free(linebuf);
				return -1;
				break;
		}
	}
}

struct utm_out *utmout_alloc(void)
{
	struct utm_out *out = NULL;
	out = (struct utm_out*)malloc(sizeof(struct utm_out));
	if(!out) { perror(__func__); exit(-1);}
	memset(out, 0, sizeof(struct utm_out));
	return out;
}

void utmout_free(struct utm_out *out)
{
	while(out) {
		if(out->buf) free(out->buf);
		out = out->next;
	}
}


