/*   
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   telnet.c: telnet module
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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

#include <config.h>
#include  <stdio.h>
#include  <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
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

struct telnetstat {
	unsigned char status;
	unsigned char echo;
	unsigned char telnetprotocol;
	char linebuf[BUFSIZE];
	int  bufindex;
};

void telnet_close(int fn,int fd)
{
	free(status[fn]);
	delpfd(fn);
	lwip_close(fd);
}

void telnet_getanswer(int fd,int vdefd)
{
	char buf[BUFSIZE];
	char linebuf[BUFSIZE+1];
	int n=0,ib=0,il=0,indata=0,eoa=0;
	do {
		n=read(vdefd,buf,BUFSIZE);
		for(ib=0;ib<n;ib++)
		{
			linebuf[il++]=buf[ib];
			if (buf[ib] == '\n') {
				linebuf[il-1]='\r';
				linebuf[il]='\n';
				linebuf[il+1]='0';
				il++;
				if (indata) {
					if (linebuf[0]=='.' && linebuf[1]=='\r')
						indata=0;
					else
						lwip_write(fd,linebuf,il);
				} else if (strncmp(linebuf,"0000",4)==0)
					indata=1;
				else {
					if(linebuf[0]=='1' &&
							linebuf[1] >= '0' &&  linebuf[1] <= '9' &&
							linebuf[2] >= '0' &&  linebuf[2] <= '9' &&
							linebuf[3] >= '0' &&  linebuf[3] <= '9') {
						lwip_write(fd,linebuf+5,il-5);
						eoa=1;
					}
				}
				il=0;
			}
		}
	} while (!eoa);
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
			if (strcmp(st->linebuf,passwd) != 0) {
				st->status++;
				if (st->status < TELNET_PASSWD + 3)
					lwip_write(fd,"\r\nlogin incorrect\r\n\r\nPassword: ",30);
				else
					telnet_close(fn,fd);
			} else {
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
					if (*cmd != '\n') {
						write(vdefd,st->linebuf,st->bufindex);
						if (strncmp(cmd,"shutdown",8)==0) {
							telnet_close(fn,fd);
							exit(0);
						} else
							telnet_getanswer(fd,vdefd);
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

int telnetdata(int fn,int fd,int vdefd)
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
		for (i=0;i<n && st->bufindex<BUFSIZE;i++) {
			if (buf[i] == 0xff && buf[i+1] == 0xff) 
				i++;
			if(buf[i]==0) buf[i]='\n'; /*telnet encode \n as a 0 when in raw mode*/
			if (buf[i] == 0xff && buf[i+1] != 0xff) {
				i+=telnet_options(fn,fd,buf+i);
			} else if(buf[i] == 0x1b) {
				/* ESCAPE! */
				i+=2;/* ignored */
			} else if(buf[i] < 0x20 && !(buf[i] == '\n' || buf[i] == '\r')) { 
				/*ctrl*/
				if (buf[i] = 4) /*ctrl D is a shortcut for UNIX people! */ {
					telnet_close(fn,fd);
					break;
				}
			} else if(buf[i] == 0x7f) {
				if(st->bufindex > 0) {
					(st->bufindex)--;
					if (st->echo && st->status<TELNET_PASSWD)
						lwip_write(fd,"\010 \010",3);
				}
			} else {
				if (st->echo && st->status<TELNET_PASSWD)
					lwip_write(fd,&(buf[i]),1);
				if (buf[i] != '\r') {
					st->linebuf[(st->bufindex)++]=buf[i];
					if (buf[i]=='\n') {
						st->linebuf[(st->bufindex)]=0;
						telnet_core(fn,fd,vdefd);
						st->bufindex=0;
					}
				}
			}
		}
	}
}

int telnetaccept(int fn,int fd,int vdefd)
{
	struct sockaddr_in  cli_addr;
	int newsockfd;
	unsigned int clilen;
	struct telnetstat *st;
	int newfn;

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
	st->bufindex=0;
	lwip_write(newsockfd,banner,strlen(banner));
	lwip_write(newsockfd,"\r\nLogin: ",8);
	return 0;
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
}
