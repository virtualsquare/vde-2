/*
 * libvdehist - A library to manage history and command completion for vde mgmt protocol
 * Copyright (C) 2006 Renzo Davoli, University of Bologna
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <arpa/telnet.h>

#include <vdecommon.h>

#define BUFSIZE 1024
#define HISTORYSIZE 32

extern char *prompt;

static char **commandlist;

typedef ssize_t (* ssize_fun)();
ssize_fun vdehist_vderead=read;
ssize_fun vdehist_vdewrite=write;
ssize_fun vdehist_termread=read;
ssize_fun vdehist_termwrite=write;

#define HIST_COMMAND 0x0
#define HIST_NOCMD 0x1
#define HIST_PASSWDFLAG 0x80

struct vdehiststat {
	unsigned char status;
	unsigned char echo;
	unsigned char telnetprotocol;
	unsigned char edited; /* the linebuf has been modified (left/right arrow)*/
	unsigned char vindata; /* 1 when in_data... (0000 end with .)*/
	char lastchar; /* for double tag*/
	char linebuf[BUFSIZE]; /*line buffer from the user*/
	int  bufindex; /*current editing position on the buf */
	char vlinebuf[BUFSIZE+1]; /*line buffer from vde*/
	int  vbufindex; /*current editing position on the buf */
	char *history[HISTORYSIZE]; /*history of the previous commands*/
	int histindex; /* index on the history (changed with up/down arrows) */
	int termfd; /* fd to the terminal */
	int mgmtfd; /* mgmt fd to vde_switch */
};

char * nologin(char *cmd,int len,struct vdehiststat *st) {
	return NULL;
}
char * (* vdehist_logincmd)(char *cmd,int len,struct vdehiststat *s)
	=nologin;

static int commonprefix(char *x, char *y,int maxlen)
{
	int len=0;
	while (*(x++)==*(y++) && len<maxlen)
		len++;
	return len;
}

static void showexpand(char *linebuf,int bufindex, int termfd)
{
	char *buf;
	size_t bufsize;
	FILE *ms=open_memstream(&buf,&bufsize);
	int nmatches=0;
	if (ms) {
		if (commandlist && bufindex>0) {
			char **s=commandlist;
			while (*s) {
				if (strncmp(linebuf,*s,bufindex)==0) {
					nmatches++;
					fprintf(ms,"%s ",*s);
				}
				s++;
			}
			fprintf(ms,"\r\n");
		}
		fclose(ms);
		if (nmatches > 1)
			vdehist_termwrite(termfd,buf,strlen(buf));
		free(buf);
	}
}

static int tabexpand(char *linebuf,int bufindex,int maxlength)
{
	if (commandlist && bufindex>0) {
		char **s=commandlist;
		int nmatches=0;
		int len=0;
		char *match=NULL;
		while (*s) {
			if (strncmp(linebuf,*s,bufindex)==0) {
				nmatches++;
				if (nmatches == 1) {
					match=*s;
					len=strlen(match);
				} else
					len=commonprefix(match,*s,len);
			}
			s++;
		}
		if (len > 0) {
			int alreadymatch=commonprefix(linebuf,match,len);
			//fprintf(stderr,"TAB %s %d -> %s %d already %d\n",linebuf,bufindex,match,len,alreadymatch);
			if ((len-alreadymatch)+strlen(linebuf) < maxlength) {
				memmove(linebuf+len,linebuf+alreadymatch,
						strlen(linebuf+alreadymatch)+1);
				memcpy(linebuf+alreadymatch,match+alreadymatch,len-alreadymatch);
				if (nmatches == 1 && linebuf[len] != ' ' && strlen(linebuf)+1 < maxlength) {
					memmove(linebuf+len+1,linebuf+len,
							strlen(linebuf+len)+1);
					linebuf[len]=' ';
					len++;
				}
				bufindex=len;
			}
		}
	}
	return bufindex;
}

#define CC_HEADER 0
#define CC_BODY 1
#define CC_TERM 2
#define MAX_KEYWORDS 128

static int qstrcmp(const void *a,const void *b)
{
	return strcmp(*(char * const *)a,*(char * const *)b);
}

struct vh_readln {
	int readbufsize;
	int readbufindex;
	char readbuf[BUFSIZE];
};

static char *vdehist_readln(int vdefd,char *linebuf,int size,struct vh_readln *vlb)
{
	int i;
	char lastch=' ';
	struct pollfd wfd={vdefd,POLLIN|POLLHUP,0};
	i=0;
	do {
		if (vlb->readbufindex==vlb->readbufsize) {
			poll(&wfd,1,-1);
			if ((vlb->readbufsize=read(vdefd,vlb->readbuf,BUFSIZE)) <= 0)
				return NULL;
			vlb->readbufindex=0;
		}
		if (vlb->readbuf[vlb->readbufindex]==' ' && lastch=='$' && vlb->readbufindex==vlb->readbufsize-1)
			return NULL;
		lastch=linebuf[i]=vlb->readbuf[vlb->readbufindex];
		i++;vlb->readbufindex++;
	} while (lastch!='\n' && i<size-1);
	linebuf[i]=0;
	return linebuf;
}

static void vdehist_create_commandlist(int vdefd)
{
	char linebuf[BUFSIZE];
	char *localclist[MAX_KEYWORDS];
	int nkeywords=0;
	int i,j;
	struct vh_readln readlnbuf={0,0};
	if (vdefd >= 0) {
		int status=CC_HEADER;
		vdehist_vdewrite(vdefd,"help\n",5);
		while (status != CC_TERM && vdehist_readln(vdefd,linebuf,BUFSIZE,&readlnbuf) != NULL) {
			if (status == CC_HEADER) {
				if (strncmp(linebuf,"------------",12) == 0)
					status=CC_BODY;
			} else {
				if (strncmp(linebuf,".\n",2) == 0)
					status=CC_TERM;
				else {
					char *s=linebuf;
					while (*s!=' ' && *s != 0)
						s++;
					*s=0; /* take the first token */
					localclist[nkeywords]=strdup(linebuf);
					if (nkeywords<MAX_KEYWORDS) nkeywords++;
				}
			}
		}
		while (vdehist_readln(vdefd,linebuf,BUFSIZE,&readlnbuf) != NULL) 
			;
		qsort(localclist,nkeywords,sizeof(char *),qstrcmp);
		for (i=j=0; i<nkeywords; i++)
			if (i<nkeywords-1 &&
					strncmp(localclist[i],localclist[i+1],strlen(localclist[i]))==0 &&
					localclist[i+1][strlen(localclist[i])] == '/') {
				free(localclist[i]); /*avoid menu*/
			} else {
				localclist[j]=localclist[i];
				j++;
			}
		nkeywords=j;
	}
	nkeywords++;
	commandlist=malloc(nkeywords*sizeof(char *));
	if (commandlist) {
		for (i=0;i<nkeywords;i++)
			commandlist[i]=localclist[i];
		commandlist[i]=NULL;
	}
	//fprintf(stderr,"%d\n",nkeywords);
	//fprintf(stderr,"%s %s\n",commandlist[0],commandlist[1]);
}

static void erase_line(struct vdehiststat *st,int prompt_too)
{
	int j;
	int size=st->bufindex+(prompt_too != 0)*strlen(prompt);
	char *buf;
	size_t bufsize;
	FILE *ms=open_memstream(&buf,&bufsize);
	if (ms) {
		for (j=0;j<size;j++)
			fputc('\010',ms);
		size=strlen(st->linebuf)+(prompt_too != 0)*strlen(prompt);
		for (j=0;j<size;j++)
			fputc(' ',ms);
		for (j=0;j<size;j++)
			fputc('\010',ms);
		fclose(ms);
		if (buf)
			vdehist_termwrite(st->termfd,buf,bufsize);
		free(buf);
	}
}

static void redraw_line(struct vdehiststat *st,int prompt_too)
{
	int j;
	int tail=strlen(st->linebuf)-st->bufindex;
	char *buf;
	size_t bufsize;
	FILE *ms=open_memstream(&buf,&bufsize);
	if (ms) {
		if (prompt_too)
			fprintf(ms,"%s%s",prompt,st->linebuf);
		else
			fprintf(ms,"%s",st->linebuf);
		for (j=0;j<tail;j++)
			fputc('\010',ms);
		fclose(ms);
		if (buf)
			vdehist_termwrite(st->termfd,buf,bufsize);
		free(buf);
	}
}

void vdehist_mgmt_to_term(struct vdehiststat *st)
{
	char buf[BUFSIZE+1];
	int n=0,ib=0;
	/* erase the input line */
	erase_line(st,1);
	/* if the communication with the manager object holds, print the output*/
	//fprintf(stderr,"mgmt2term\n");
	if (st->mgmtfd) {
		n=vdehist_vderead(st->mgmtfd,buf,BUFSIZE);
		//fprintf(stderr,"mgmt2term n=%d\n",n);
		buf[n]=0;
		while (n>0) {
			for(ib=0;ib<n;ib++)
			{
				st->vlinebuf[(st->vbufindex)++]=buf[ib];
				if (buf[ib] == '\n') {
					st->vlinebuf[(st->vbufindex)-1]='\r';
					st->vlinebuf[(st->vbufindex)]='\n';
					st->vlinebuf[(st->vbufindex)+1]='\0';
					(st->vbufindex)++;
					if (st->vindata) {
						if (st->vlinebuf[0]=='.' && st->vlinebuf[1]=='\r')
							st->vindata=0;
						else
							vdehist_termwrite(st->termfd,st->vlinebuf,(st->vbufindex));
					} else {
						char *message=st->vlinebuf;
						//fprintf(stderr,"MSG1 \"%s\"\n",message);
						while (*message != '\0' &&
								!(isdigit(message[0]) &&
									isdigit(message[1]) &&
									isdigit(message[2]) &&
									isdigit(message[3])))
							message++;
						if (strncmp(message,"0000",4)==0)
							st->vindata=1;
						else if (isdigit(message[1]) &&
								isdigit(message[2]) &&
								isdigit(message[3])) {
							if(message[0]=='1') {
								message+=5;
								vdehist_termwrite(st->termfd,message,strlen(message));
							} else if (message[0]=='3') {
								message+=5;
								vdehist_termwrite(st->termfd,"** DBG MSG: ",12);
								vdehist_termwrite(st->termfd,(message),strlen(message));
							}
						}
					}
					(st->vbufindex)=0;
				}
			}
			n=vdehist_vderead(st->mgmtfd,buf,BUFSIZE);
		}
	}
	/* redraw the input line */
	redraw_line(st,1);
}

static int hist_sendcmd(struct vdehiststat *st)
{
	char *cmd=st->linebuf;
	if (st->status != HIST_COMMAND) {
		cmd=vdehist_logincmd(cmd,st->bufindex,st); 
		if (commandlist == NULL && st->mgmtfd >= 0)
			vdehist_create_commandlist(st->mgmtfd);
		if (cmd==NULL)
			return 0;
	}
	while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	if (strncmp(cmd,"logout",6)==0)
		return 1;
	else {
		if (*cmd != 0) {
			write(st->mgmtfd,st->linebuf,st->bufindex);
			if (strncmp(cmd,"shutdown",8)==0) 
				return 2;
		}
		vdehist_termwrite(st->termfd,"\r\n",2);
		vdehist_termwrite(st->termfd,prompt,strlen(prompt));
	}
	return 0;
}

static void put_history(struct vdehiststat *st)
{
	if(st->history[st->histindex])
		free(st->history[st->histindex]);
	st->history[st->histindex]=strdup(st->linebuf);
}

static void get_history(int change,struct vdehiststat *st)
{
	st->histindex += change;
	if(st->histindex < 0) st->histindex=0;
	if(st->histindex >= HISTORYSIZE) st->histindex=HISTORYSIZE-1;
	if(st->history[st->histindex] == NULL) (st->histindex)--;
	strcpy(st->linebuf,st->history[st->histindex]);
	st->bufindex=strlen(st->linebuf);
}

static void shift_history(struct vdehiststat *st)
{
	if (st->history[HISTORYSIZE-1] != NULL)
		free(st->history[HISTORYSIZE-1]);
	memmove(st->history+1,st->history,(HISTORYSIZE-1)*sizeof(char *));
	st->history[0]=NULL;
}

static void telnet_option_send3(int fd,int action,int object)
{
	char opt[3];
	opt[0]=0xff;
	opt[1]=action;
	opt[2]=object;
	vdehist_termwrite(fd,opt,3);
}

static int telnet_options(struct vdehiststat *st,unsigned char *s)
{
	register int action_n_object;
	if (st->telnetprotocol == 0) {
		st->telnetprotocol=1;
		st->echo=0;
		telnet_option_send3(st->termfd,WILL,TELOPT_ECHO);
	}
	int skip=2;
	s++;
	action_n_object=((*s)<<8) + (*(s+1));
	switch (action_n_object) {
		case (DO<<8) + TELOPT_ECHO:
			//printf("okay echo\n");
			st->echo=1;
			break;
		case (WILL<<8) + TELOPT_ECHO:
			telnet_option_send3(st->termfd,DONT,TELOPT_ECHO);
			telnet_option_send3(st->termfd,WILL,TELOPT_ECHO);
			break;
		case (DO<<8) + TELOPT_SGA:
			//printf("do sga -> okay will sga\n");
			telnet_option_send3(st->termfd,WILL,TELOPT_SGA);
			break;
		case (WILL<<8) + TELOPT_TTYPE:
			//printf("will tty -> dont tty\n");
			telnet_option_send3(st->termfd,DONT,TELOPT_TTYPE);
			break;
		default:
			//printf("not managed yet %x %x\n",*s,*(s+1));
			if (*s == WILL)
				telnet_option_send3(st->termfd,DONT,*(s+1));
			else if (*s == DO)
				telnet_option_send3(st->termfd,WONT,*(s+1));
	}
	return skip;
}

int vdehist_term_to_mgmt(struct vdehiststat *st)
{
	unsigned char buf[BUFSIZE];
	int n,i,rv=0;
	n=vdehist_termread(st->termfd,buf,BUFSIZE);
	//printf("termto mgmt N%d %x %x %x %x\n",n,buf[0],buf[1],buf[2],buf[3]);
	if (n==0)
		return 1;
	else if (n<0)
		return n;
	else {
		for (i=0;i<n && strlen(st->linebuf)<BUFSIZE;i++) {
			if (buf[i] == 0xff && buf[i+1] == 0xff)
				i++;
			if(buf[i]==0) buf[i]='\n'; /*telnet encode \n as a 0 when in raw mode*/
			if (buf[i] == 0xff && buf[i+1] != 0xff) {
				i+=telnet_options(st,buf+i);
			} else 

				if(buf[i] == 0x1b) {
					/* ESCAPE! */
					if (buf[i+1]=='[' && st->status == HIST_COMMAND) {
						st->edited=1;
						switch (buf[i+2]) {
							case 'A': //fprintf(stderr,"UP\n");
								erase_line(st,0);
								put_history(st);
								get_history(1,st);
								redraw_line(st,0);
								st->bufindex=strlen(st->linebuf);
								break;
							case 'B': //fprintf(stderr,"DOWN\n");
								erase_line(st,0);
								put_history(st);
								get_history(-1,st);
								redraw_line(st,0);
								break;
							case 'C': //fprintf(stderr,"RIGHT\n");
								if (st->linebuf[st->bufindex] != '\0') {
									vdehist_termwrite(st->termfd,"\033[C",3);
									(st->bufindex)++;
								}
								break;
							case 'D': //fprintf(stderr,"LEFT\n");
								if (st->bufindex > 0) {
									vdehist_termwrite(st->termfd,"\033[D",3);
									(st->bufindex)--;
								}
								break;
						}
						i+=3;
					}
					else
						i+=2;/* ignored */
				} else if(buf[i] < 0x20 && !(buf[i] == '\n' || buf[i] == '\r')) {
					/*ctrl*/
					if (buf[i] == 4) /*ctrl D is a shortcut for UNIX people! */ {
						rv=1;
						break;
					}
					switch (buf[i]) {
						case 3:  /*ctrl C cleans the current buffer */
							erase_line(st,0);
							st->bufindex=0;
							st->linebuf[(st->bufindex)]=0;
							break;
						case 12: /* ctrl L redraw */
							erase_line(st,1);
							redraw_line(st,1);
							break;
						case 1: /* ctrl A begin of line */
							erase_line(st,0);
							st->bufindex=0;
							redraw_line(st,0);
							break;
						case 5: /* ctrl E endofline */
							erase_line(st,0);
							st->bufindex=strlen(st->linebuf);
							redraw_line(st,0);
						case '\t': /* tab */
							if (st->lastchar== '\t') {
								erase_line(st,1);
								showexpand(st->linebuf,st->bufindex,st->termfd);
								redraw_line(st,1);
							} else {
								erase_line(st,0);
								st->bufindex=tabexpand(st->linebuf,st->bufindex,BUFSIZE);
								redraw_line(st,0);
							}
							break;
					}
				} else if(buf[i] == 0x7f) {
					if(st->bufindex > 0) {
						char *x;
						(st->bufindex)--;
						x=st->linebuf+st->bufindex;
						memmove(x,x+1,strlen(x));
						if (st->echo && !(st->status & HIST_PASSWDFLAG)) {
							if (st->edited)
								vdehist_termwrite(st->termfd,"\010\033[P",4);
							else
								vdehist_termwrite(st->termfd,"\010 \010",3);
						}
					}
				} else {
					if (st->echo && !(st->status & HIST_PASSWDFLAG)) {
						if (st->edited && buf[i] >= ' ')
							vdehist_termwrite(st->termfd,"\033[@",3);
						vdehist_termwrite(st->termfd,&(buf[i]),1);
					}
					if (buf[i] != '\r') {
						if (buf[i]=='\n') {
							if (st->status == HIST_COMMAND) {
								st->histindex=0;
								put_history(st);
								if (strlen(st->linebuf) > 0)
									shift_history(st);
							}
							st->bufindex=strlen(st->linebuf);
							if ((rv=hist_sendcmd(st)) != 0)
								break; 
							st->bufindex=st->edited=st->histindex=0;
							st->linebuf[(st->bufindex)]=0;
						} else {
							char *x;
							x=st->linebuf+st->bufindex;
							memmove(x+1,x,strlen(x)+1);
							st->linebuf[(st->bufindex)++]=buf[i];
						}
					}
				}
			st->lastchar=buf[i];
		}
	}
	return rv;
}

struct vdehiststat *vdehist_new(int termfd,int mgmtfd) {
	struct vdehiststat *st;
	if (commandlist == NULL && mgmtfd >= 0)
		vdehist_create_commandlist(mgmtfd);
	st=malloc(sizeof(struct vdehiststat));
	if (st) {
		int i;
		if (mgmtfd < 0)
			st->status=HIST_NOCMD;
		else
			st->status=HIST_COMMAND;
		st->echo=1;
		st->telnetprotocol=0;
		st->bufindex=st->edited=st->histindex=st->vbufindex=st->vindata=st->lastchar=0;
		st->linebuf[(st->bufindex)]=0;
		st->vlinebuf[(st->vbufindex)]=0;
		st->termfd=termfd;
		st->mgmtfd=mgmtfd;
		for (i=0;i<HISTORYSIZE;i++)
			st->history[i]=0;
	}
	return st;
}

void vdehist_free(struct vdehiststat *st)
{
	if (st) {
		int i;
		for (i=0;i<HISTORYSIZE;i++)
			if(st->history[i])
				free(st->history[i]);
		free(st);
	}
}

int vdehist_getstatus(struct vdehiststat *st) 
{
	return st->status;
}

void vdehist_setstatus(struct vdehiststat *st,int status) 
{
	st->status=status;
}


int vdehist_gettermfd(struct vdehiststat *st) 
{
	return st->termfd;
}


int vdehist_getmgmtfd(struct vdehiststat *st) 
{
	return st->mgmtfd;
}

void vdehist_setmgmtfd(struct vdehiststat *st,int mgmtfd) 
{
	st->mgmtfd=mgmtfd;
}


