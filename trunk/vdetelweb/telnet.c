/*   
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   telnet.c: telnet module
 *   
 *   Copyright 2005,2007 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */

#define _GNU_SOURCE
#include <config.h>
#include  <stdio.h>
#include  <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include  <errno.h>
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <sys/poll.h>
#include <linux/un.h>
#include  <netinet/in.h>
#include  <arpa/inet.h>
#include  <arpa/telnet.h>
#include  <string.h>
#include <getopt.h>
#include "vdetelweb.h"
#include <lwipv6.h>

#define TELNET_TCP_PORT 23
#define TELNET_LOGIN 0x0
#define TELNET_COMMAND 0x1
#define TELNET_PASSWD 0x80
#define HISTORYSIZE 32

static char **commandlist;

struct telnetstat {
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
	int lwipfd; /* fd to the network */
	int vdemgmtfd; /* mgmt fd to vde_switch */
};

void telnet_close(int fn,int fd)
{
	struct telnetstat *st=status[fn];
	int i;
	for (i=0;i<HISTORYSIZE;i++)
		if(st->history[i])
			free(st->history[i]);
	delpfd(pfdsearch(st->lwipfd));
	lwip_close(st->lwipfd);
	if (st->vdemgmtfd >= 0) {
		delpfd(pfdsearch(st->vdemgmtfd));
		close(st->vdemgmtfd);
	}
	free(st);
}

#define CC_HEADER	0
#define CC_BODY 1
#define CC_TERM 2
#define MAX_KEYWORDS 128

static int commonprefix(char *x, char *y,int maxlen)
{
	int len=0;
	while (*(x++)==*(y++) && len<maxlen)
		len++;
	return len;
}

static void showexpand(char *linebuf,int bufindex, int fd)
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
			lwip_write(fd,buf,strlen(buf));
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

static int qstrcmp(const void *a,const void *b)
{
	return strcmp(*(char * const *)a,*(char * const *)b);
}
static void create_commandlist()
{
	int vdefd=openextravdem();
	char linebuf[BUFSIZE];
	char *localclist[MAX_KEYWORDS];
	int nkeywords=0;
	int i,j;
	if (vdefd) {
		int status=CC_HEADER;
		FILE *in=fdopen(vdefd,"r");
		write(vdefd,"help\n",5);
		while (status != CC_TERM && fgets(linebuf,BUFSIZE,in) != NULL) {
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
					//fprintf(stderr,"%s\n",linebuf);
					localclist[nkeywords]=strdup(linebuf);
					if (nkeywords<MAX_KEYWORDS) nkeywords++;
					//char *thiskeyword=strdup(linebuf);
				}
			}
		}
		qsort(localclist,nkeywords,sizeof(char *),qstrcmp);
		for (i=j=0; i<nkeywords-1; i++)
			if (strncmp(localclist[i],localclist[i+1],strlen(localclist[i]))==0 &&
					localclist[i+1][strlen(localclist[i])] == '/') {
				free(localclist[i]); /*avoid menu*/
			} else {
				localclist[j]=localclist[i];
				j++;
			}
		nkeywords=j;
		close(vdefd);
	}
	nkeywords++;
	commandlist=malloc(nkeywords*sizeof(char *));
	if (commandlist) {
		for (i=0;i<nkeywords;i++)
			commandlist[i]=localclist[i];
		commandlist[i]=NULL;
	}
}

static void erase_line(struct telnetstat *st,int prompt_too)
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
			lwip_write(st->lwipfd,buf,bufsize);
		free(buf);
	}
}

static void redraw_line(struct telnetstat *st,int prompt_too)
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
			lwip_write(st->lwipfd,buf,bufsize);
		free(buf);
	}
}

void telnet_getanswer(struct telnetstat *st)
{
	char buf[BUFSIZE+1];
	int n=0,ib=0;
	n=read(st->vdemgmtfd,buf,BUFSIZE);
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
						lwip_write(st->lwipfd,st->vlinebuf,(st->vbufindex));
				} else {
					char *message=st->vlinebuf;
					//fprintf(stderr,"MSG1 \"%s\"\n",message);
					while (*message != '\0' && 
							!(isdigit(message[0]) &&
							isdigit(message[1]) &&
							isdigit(message[2]) &&
							isdigit(message[3])))
						message++;
					//fprintf(stderr,"MSG2 \"%s\"\n",message);
					if (strncmp(message,"0000",4)==0)
						st->vindata=1;
					else if(message[0]=='1' &&
							isdigit(message[1]) &&
							isdigit(message[2]) &&
							isdigit(message[3])) {
						message+=5;
						lwip_write(st->lwipfd,message,strlen(message));
					} else if (message[0]=='3' &&
							isdigit(message[1]) &&
							isdigit(message[2]) &&
							isdigit(message[3])) {
						message+=5;
						lwip_write(st->lwipfd,"** DBG MSG: ",12);
						lwip_write(st->lwipfd,(message),strlen(message));
					}
				}
				(st->vbufindex)=0;
			}
		}
		n=read(st->vdemgmtfd,buf,BUFSIZE);
	}
}

void vdedata(int fn,int fd,int vdefd)
{
	struct telnetstat *st=status[fn];
	erase_line(st,1);
	if (st->vdemgmtfd)
		telnet_getanswer(st);
	redraw_line(st,1);
}

void telnet_core(int fn,int fd,int vdefd)
{
	struct telnetstat *st=status[fn];

	switch (st->status) {
		case TELNET_LOGIN:
			while (st->linebuf[st->bufindex-1] == '\n')
				st->linebuf[--st->bufindex]=0;
			if (strcmp(st->linebuf,"admin") != 0) {
				lwip_write(fd,"login incorrect\r\n\r\nLogin: ",26);
			} else {
				lwip_write(fd,"Password: ",11);
				st->status=TELNET_PASSWD;
			}
			break;
		case TELNET_PASSWD:
		case TELNET_PASSWD+1:
		case TELNET_PASSWD+2:
			while (st->linebuf[st->bufindex-1] == '\n')
				st->linebuf[--st->bufindex]=0;

			if (!sha1passwdok(st->linebuf)) {
				st->status++;
				if (st->status < TELNET_PASSWD + 3)
					lwip_write(fd,"\r\nlogin incorrect\r\n\r\nPassword: ",30);
				else
					telnet_close(fn,fd);
			} else {
				int newfn;
				int flags;
				st->vdemgmtfd=openextravdem();
				flags = fcntl(st->vdemgmtfd, F_GETFL);
				flags |= O_NONBLOCK;
				fcntl(st->vdemgmtfd, F_SETFL, flags);
				if (st->vdemgmtfd >= 0) {
					newfn=addpfd(st->vdemgmtfd,vdedata);
					status[newfn]=st;
				} else
					telnet_close(fn,fd);
				st->status=TELNET_COMMAND;
				lwip_write(fd,"\r\n",2);
				lwip_write(fd,prompt,strlen(prompt));
			}
			break;
		case TELNET_COMMAND:
			{
				char *cmd=st->linebuf;
				while (*cmd == ' ' || *cmd == '\t')
					cmd++;
				if (strncmp(cmd,"logout",6)==0)
					telnet_close(fn,fd);
				else {
					if (*cmd != 0) {
						write(st->vdemgmtfd,st->linebuf,st->bufindex);
						if (strncmp(cmd,"shutdown",8)==0) {
							telnet_close(fn,fd);
							exit(0);
						} /*else
							telnet_getanswer(fd,st->vdemgmtfd);*/
					}
					lwip_write(fd,"\r\n",2);
					lwip_write(fd,prompt,strlen(prompt));
				}
				break;
			}
	}
}

static void telnet_option_send3(int fd,int action,int object)
{
	char opt[3];
	opt[0]=0xff;
	opt[1]=action;
	opt[2]=object;
	lwip_write(fd,opt,3);
}

static int telnet_options(int fn,int fd,unsigned char *s)
{
	struct telnetstat *st=status[fn];
	register int action_n_object;
	if (st->telnetprotocol == 0) {
		st->telnetprotocol=1;
		telnet_option_send3(fd,WILL,TELOPT_ECHO);
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
			telnet_option_send3(fd,DONT,TELOPT_ECHO);
			telnet_option_send3(fd,WILL,TELOPT_ECHO);
			break;
		case (DO<<8) + TELOPT_SGA:
			//printf("do sga -> okay will sga\n");
			telnet_option_send3(fd,WILL,TELOPT_SGA);
			break;
		case (WILL<<8) + TELOPT_TTYPE:
			//printf("will tty -> dont tty\n");
			telnet_option_send3(fd,DONT,TELOPT_TTYPE);
			break;
		default:
			//printf("not managed yet %x %x\n",*s,*(s+1));
			if (*s == WILL)
				telnet_option_send3(fd,DONT,*(s+1));
			else if (*s == DO)
				telnet_option_send3(fd,WONT,*(s+1));
	}
	return skip;
}

/*
static void erase_line(int fd, struct telnetstat *st)
{
	int j;
	for (j=0;j<st->bufindex;j++)
		lwip_write(fd,"\033[D",3);
	for (j=0;j<strlen(st->linebuf);j++)
		lwip_write(fd,"\033[P",3);
}
*/

static void put_history(struct telnetstat *st)
{
	if(st->history[st->histindex])
		free(st->history[st->histindex]);
	st->history[st->histindex]=strdup(st->linebuf);
}

static void get_history(int change,struct telnetstat *st)
{
	st->histindex += change;
	if(st->histindex < 0) st->histindex=0;
	if(st->histindex >= HISTORYSIZE) st->histindex=HISTORYSIZE-1;
	if(st->history[st->histindex] == NULL) (st->histindex)--;
	strcpy(st->linebuf,st->history[st->histindex]);
	st->bufindex=strlen(st->linebuf);
}

static void shift_history(struct telnetstat *st)
{
	if (st->history[HISTORYSIZE-1] != NULL)
		free(st->history[HISTORYSIZE-1]);
	memmove(st->history+1,st->history,(HISTORYSIZE-1)*sizeof(char *));
	st->history[0]=NULL;
}

void telnetdata(int fn,int fd,int vdefd)
{
	unsigned char buf[BUFSIZE];
	int n,i;
	struct telnetstat *st=status[fn];
	n=lwip_read(fd,buf,BUFSIZE);
	//printf("N%d %x %x %x %x\n",n,buf[0],buf[1],buf[2],buf[3]);
	if (n==0) 
		telnet_close(fn,fd);
	else if (n<0)
		printlog(LOG_ERR,"telnet read err: %s",strerror(errno));
	else {
		for (i=0;i<n && strlen(st->linebuf)<BUFSIZE;i++) {
			if (buf[i] == 0xff && buf[i+1] == 0xff) 
				i++;
			if(buf[i]==0) buf[i]='\n'; /*telnet encode \n as a 0 when in raw mode*/
			if (buf[i] == 0xff && buf[i+1] != 0xff) {
				i+=telnet_options(fn,fd,buf+i);
			} else if(buf[i] == 0x1b) {
				/* ESCAPE! */
				if (buf[i+1]=='[' && st->status == TELNET_COMMAND) {
					st->edited=1;
					switch (buf[i+2]) {
						case 'A': //fprintf(stderr,"UP\n");
							erase_line(st,0);
							put_history(st);
							get_history(1,st);
							redraw_line(st,0);
							//lwip_write(fd,st->linebuf,st->bufindex);
							st->bufindex=strlen(st->linebuf);
							break;
						case 'B': //fprintf(stderr,"DOWN\n");
							erase_line(st,0);
							put_history(st);
							get_history(-1,st);
							redraw_line(st,0);
							//lwip_write(fd,st->linebuf,st->bufindex);
							break;
						case 'C': //fprintf(stderr,"RIGHT\n");
							if (st->linebuf[st->bufindex] != '\0') {
								lwip_write(fd,"\033[C",3);
								(st->bufindex)++;
							}
							break;
						case 'D': //fprintf(stderr,"LEFT\n");
							if (st->bufindex > 0) {
								lwip_write(fd,"\033[D",3);
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
					telnet_close(fn,fd);
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
							showexpand(st->linebuf,st->bufindex,fd);
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
					if (st->echo && st->status<TELNET_PASSWD) {
						if (st->edited) 
							lwip_write(fd,"\010\033[P",4);
						else
							lwip_write(fd,"\010 \010",3);
					}
				}
			} else {
				if (st->echo && st->status<TELNET_PASSWD) {
					if (st->edited && buf[i] >= ' ') 
						lwip_write(fd,"\033[@",3);
					lwip_write(fd,&(buf[i]),1);
				}
				if (buf[i] != '\r') {
					if (buf[i]=='\n') {
						if (st->status == TELNET_COMMAND) {
							st->histindex=0;
							put_history(st);
							if (strlen(st->linebuf) > 0)
								shift_history(st);
						}
						st->bufindex=strlen(st->linebuf);
						telnet_core(fn,fd,vdefd);
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
}

void telnetaccept(int fn,int fd,int vdefd)
{
	struct sockaddr_in  cli_addr;
	int newsockfd;
	unsigned int clilen;
	struct telnetstat *st;
	int newfn;
	int i;

	clilen = sizeof(cli_addr);
	newsockfd = lwip_accept(fd, (struct sockaddr *) &cli_addr, &clilen);

	if (newsockfd < 0) {
		printlog(LOG_ERR,"telnet accept err: %s",strerror(errno));
	}

	newfn=addpfd(newsockfd,telnetdata);
	status[newfn]=st=malloc(sizeof(struct telnetstat));
	st->status=TELNET_LOGIN;
	st->echo=0;
	st->telnetprotocol=0;
	st->bufindex=st->edited=st->histindex=st->vbufindex=st->vindata=st->lastchar=0;
	st->lwipfd=newsockfd;
	st->linebuf[(st->bufindex)]=0;
	st->vlinebuf[(st->vbufindex)]=0;
	st->vdemgmtfd=-1;
	for (i=0;i<HISTORYSIZE;i++)
		st->history[i]=0;
	lwip_write(newsockfd,banner,strlen(banner));
	lwip_write(newsockfd,"\r\nLogin: ",9);
}

void telnet_init(int vdefd)
{
	int sockfd;
	int one=1;
	struct sockaddr_in  serv_addr;
	sockfd=lwip_socket(AF_INET, SOCK_STREAM, 0);

	if (!sockfd) {
		printlog(LOG_ERR,"telnet socket err: %s",strerror(errno));
	}
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
				sizeof(one)) < 0){
		printlog(LOG_ERR,"telnet setsockopt: %s",strerror(errno));
		return;
	}
	if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0){
		printlog(LOG_ERR,"Setting O_NONBLOCK telnet: %s",strerror(errno));
		return;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family      = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port        = htons(TELNET_TCP_PORT);

	if (lwip_bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		printlog(LOG_ERR,"telnet bind err: %s",strerror(errno));
	}

	lwip_listen(sockfd, 5);

	addpfd(sockfd,telnetaccept);
	create_commandlist();
}
