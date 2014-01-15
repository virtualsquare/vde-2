/*   
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   web.c: http micro server for vde mgmt
 *   
 *   Copyright 2005 Virtual Square Team University of Bologna - Italy
 *   written by Renzo Davoli 2005
 *   management of sha1 Marco Dalla Via 2008
 *   modified by Renzo Davoli 2008
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
#define __USE_GNU
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
#include  <sys/ioctl.h>
#include <linux/un.h>
#include  <netinet/in.h>
#include  <arpa/inet.h>
#include  <string.h>
#include <getopt.h>
#include "vdetelweb.h"
#include <lwipv6.h>

#define WEB_TCP_PORT 80
#define WEB_IDENTIFY 0x0
#define WEB_AUTHORIZED 0x1
#define WEB_UNAUTHORIZED 0x2
#define WEB_OP_GET 0x0
#define WEB_OP_POST 0x1
#define WEB_OP_POSTDATA 0x2

const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//static char *base64passwd;
struct webstat {
	unsigned char status;
	unsigned char op;
	unsigned int bodylen;
	char linebuf[BUFSIZE];
	char path[BUFSIZE];
	int  bufindex;
};

static void lowercase(char *s)
{
	while (*s != 0) {
		*s = tolower(*s);
		s++;
	}
}

void encode64(const char *from, char *to, int tosize) {

	int convbuf;
	int n = strlen(from);

	while ((n > 0) && (tosize > 3)) {

		convbuf = *from;
		from++;
		n--;
		convbuf <<= 8;
		if (n > 0)
			convbuf |= *from;
		from++;
		n--;
		convbuf <<= 8;
		if (n > 0)
			convbuf |= *from;
		from++;
		n--;
		*(to++) = b64_chars[convbuf >> 18];
		*(to++) = b64_chars[(convbuf >> 12) & 0x3f];
		*(to++) = (n < -1) ? '=' : b64_chars[(convbuf >> 6) & 0x3f];
		*(to++) = (n < 0)  ? '=' : b64_chars[convbuf & 0x3f];
		tosize -= 4;
	}
	*to = 0;
}

void decode64(const char *src, char *dest, int dest_size) {

	int convbuf;
	int l = strlen(src);
	char c_src[l];
	char *c;

	int i, j;

	strcpy(c_src, src);

	/* Sostitute '=' (paddings) with 0 ['A'] */
	while ((c = strchr(c_src, '=')) != NULL)
		*c = 'A';

	/* Convert 4 byte in 6 bit (64) to 3 byte in 8 bit */
	for (i = 0, j = 0; i < l; i += 4, j += 3) {

		convbuf = (((int)(strchr(b64_chars, c_src[i]) - b64_chars) << 18) +
				((int)(strchr(b64_chars, c_src[i + 1]) - b64_chars) << 12) +
				((int)(strchr(b64_chars, c_src[i + 2]) - b64_chars) << 6) +
				((int)(strchr(b64_chars, c_src[i + 3]) - b64_chars)));
		dest[j]     = ((convbuf >> 16) & 255);
		dest[j + 1] = ((convbuf >> 8) & 255);
		dest[j + 2] = ((convbuf & 255));
	}

	dest[j] = '\0';
}

#if 0
static void createbase64passwd()
{
	char buf[BUFSIZE];
	char buf64[BUFSIZE*4/3];
	snprintf(buf,BUFSIZE,"admin:%s",passwd);
	encode64(buf,buf64,BUFSIZE*4/3);
	base64passwd=strdup(buf64);
}
#endif

static void lwip_printf(int fd, const char *format, ...)
{
	char outbuf[BUFSIZE];
	va_list arg;
	va_start (arg, format);
	vsnprintf(outbuf,BUFSIZE,format,arg);
	lwip_write(fd,outbuf,strlen(outbuf));
}

static void web_close(int fn,int fd)
{
	//printf("web_close %d %d\n",fn,fd);
	free(status[fn]);
	delpfd(fn);
	lwip_close(fd);
}

static int vde_getanswer(voidfun f,void *arg,int vdefd)
{
	char buf[BUFSIZE];
	char linebuf[BUFSIZE+1];
	int n=0,ib=0,il=0,indata=0,eoa=0;
	do {
		n=read(vdefd,buf,BUFSIZE);
		if (n==0)
			exit(0);
		for(ib=0;ib<n;ib++)
		{
			linebuf[il++]=buf[ib];
			if (buf[ib] == '\n') {
				linebuf[il-1]='\r';
				linebuf[il]='\n';
				linebuf[il+1]=0;
				il++;
				if (indata) {
					if (linebuf[0]=='.' && linebuf[1]=='\r')
						indata=0;
					else
						f(arg,linebuf,il,indata,0);
				} else if (strncmp(linebuf,"0000",4)==0)
					indata=1;
				else {
					if(linebuf[0]=='1' &&
							linebuf[1] >= '0' &&  linebuf[1] <= '9' &&
							linebuf[2] >= '0' &&  linebuf[2] <= '9' &&
							linebuf[3] >= '0' &&  linebuf[3] <= '9') {
						f(arg,linebuf+5,il-5,0,atoi(linebuf));
						eoa=atoi(linebuf);
					}
				}
				il=0;
			}
		}
	} while (!eoa);
	return(eoa);
}

struct vdesub {
	char *name;
	char *descr;
	char *syntax;
	struct vdesub *next;
};

struct vdemenu {
	char *name;
	char *descr;
	struct vdesub *sub;
	struct vdemenu *next;
};

static struct vdemenu *menuhead;

static struct vdemenu *vde_findmenu(struct vdemenu *head,char *name)
{
	if (head ==  NULL)
		return NULL;
	else 
		if (strcmp(head->name,name)==0) 
			return head;
		else
			return vde_findmenu(head->next,name);
}

static void vde_addsub(struct vdesub **headp,char *name,char *syntax,char *help)
{
	if (*headp == NULL) {
		*headp=malloc(sizeof(struct vdesub));
		if (*headp != NULL) {
			(*headp)->name=name;
			(*headp)->descr=help;
			(*headp)->syntax=syntax;
			(*headp)->next=NULL;
		}
	} else
		vde_addsub(&((*headp)->next),name,syntax,help);
}

static void vde_addcmd(struct vdemenu *head,char *menu,char *name,char *syntax,char *help)
{
	if (head != NULL) {
		if (strcmp(head->name,menu) == 0)
			vde_addsub(&(head->sub),name,syntax,help);
		else
			vde_addcmd(head->next,menu,name,syntax,help);
	}
}

static void vde_addmenu(struct vdemenu **headp,char *name,char *help)
{
	if (*headp == NULL) {
		*headp=malloc(sizeof(struct vdemenu));
		if (*headp != NULL) {
			(*headp)->name=name;
			(*headp)->descr=help;
			(*headp)->sub=NULL;
			(*headp)->next=NULL;
		}
	} else
		vde_addmenu(&((*headp)->next),name,help);
}

static void vde_helpline(struct vdemenu **headp,char *buf,int len,int indata,int rv)
{
	static int nl=0;
	static int syntaxpos,helppos;
	nl++;
	if (nl==2) {
		int i;
		for (i=0;i<len && buf[i]=='-';i++) ;
		for (;i<len && buf[i]==' ';i++) ;
		syntaxpos=i;
		for (;i<len && buf[i]=='-';i++) ;
		for (;i<len && buf[i]==' ';i++) ;
		helppos=i;
	}
	else if (nl > 2 && indata && (strncmp(buf,"debug",5) !=0 )) {
		char *name;
		char *syntax;
		char *help;
		int namelen;
		for (namelen=0;namelen<syntaxpos && buf[namelen]!=' ';namelen++) ;
		if (strncmp(buf+syntaxpos,"======",5) ==0) {
			/* MENU */
			name=strndup(buf,namelen);
			help=strndup(buf+helppos,len-helppos-2);
			vde_addmenu(headp,name,help);
		} else {
			int slash;
			for (slash=0;slash<namelen && buf[slash]!='/';slash++) ;
			if (slash<namelen) {
				int synlen;
				buf[slash]=0;slash++;
				namelen-=slash;
				for (synlen=helppos-syntaxpos; synlen>0 && buf[syntaxpos+synlen-1]==' ';synlen--) ;
				name=strndup(buf+slash,namelen);
				if (synlen>0)
					syntax=strndup(buf+syntaxpos,synlen);
				else
					syntax="";
				help=strndup(buf+helppos,len-helppos-2);
				vde_addcmd(*headp,buf,name,syntax,help);
			}	
		}
	}
}

static struct vdemenu *vde_gethelp(int vdefd)
{
	struct vdemenu *head=NULL;
	write(vdefd,"help\n",5);
	vde_getanswer(vde_helpline,&head,vdefd);
	return head;
}

static void lwip_showline(int *fdp,char *buf,int len,int indata,int rv)
{
	if (indata)
		lwip_write(*fdp,buf,len);
}

static int lwip_showout(int fd, int vdefd)
{
	return vde_getanswer(lwip_showline,&fd,vdefd);
}

static int hex2num(int c)
{
	if (c>96) c-=32;
	c -='0';
	if (c>9)
		c-=7;
	return c;
}

static char *uriconv(char *in)
{
	char *s=in;
	char *t=in;
	while ((*t=*s) != 0) {
		if (*s=='+')
			*t=' ';
		if (*s=='%') {
			*t=(hex2num(*(s+1))<<4)+hex2num(*(s+2));
			s+=2;
		}
		s++;t++;
	}
	return in;
}

static void postdata_parse(int fd,int vdefd,char *menu,char *postdata)
{
	char cmdbuf[BUFSIZE];
	int cmdlen,arglen,rv;
	char *postcmd,*cmd,*endcmd,*arg=NULL;
	/*printf("PD **%s**\n",postdata);*/
	if ((postcmd=strstr(postdata,"X="))!=NULL) {
		/* enter in a text field (catched through the hidden button) */
		cmd=NULL;
		while(postdata)
		{
			char *token=strsep(&postdata,"&");
			int l=strlen(token);
			char *targ=index(token,'=');
			if(strncmp("X=",token,2) != 0) {
				if (targ+1 < token+l) {
					if(cmd==NULL) {
						char *point;
						if ((point=strstr(token,".arg")) != NULL)
							*point=0;
						cmd=token;
						arg=targ+1;
					} else 
						cmd="";
				}
			}
		}
		if(cmd!=NULL && *cmd != 0) {
			strncpy(cmdbuf,menu,BUFSIZE);
			strncat(cmdbuf,"/",BUFSIZE);
			strncat(cmdbuf,cmd,BUFSIZE);
			strncat(cmdbuf," ",BUFSIZE);
			strncat(cmdbuf,uriconv(arg),BUFSIZE);
			write(vdefd,cmdbuf,strlen(cmdbuf));
			lwip_printf(fd,"<P> </P><B>%s %s</B><PRE>",prompt,cmdbuf);
			rv=lwip_showout(fd,vdefd);
			lwip_printf(fd,"</PRE><B>Result: %s</B>\r\n",strerror(rv-1000));
		}
	}
	else if ((postcmd=strstr(postdata,"COMMAND="))!=NULL) {
		/* accept button */
		postcmd+=8;
		for(cmdlen=0;postcmd[cmdlen] != '&' && postcmd[cmdlen] != 0; cmdlen++)
			;
		strncpy(cmdbuf,menu,BUFSIZE);
		strncat(cmdbuf,"/",BUFSIZE);
		cmd=cmdbuf+strlen(cmdbuf);
		strncat(cmdbuf,postcmd,(BUFSIZE<cmdlen)?BUFSIZE:cmdlen);
		endcmd=cmdbuf+strlen(cmdbuf);
		strncat(cmdbuf,".arg",BUFSIZE);
		if ((arg=strstr(postdata,cmd))!=NULL) {
			arg+=strlen(cmd)+1;
			for(arglen=0;arg[arglen] != '&' && arg[arglen] != 0; arglen++)
				;
			arg[arglen]=0;
			*endcmd=0;
			if (*arg != 0) {
				strncat(cmdbuf," ",BUFSIZE);
				strncat(cmdbuf,uriconv(arg),BUFSIZE);
			}
		} else
			*endcmd=0;
		write(vdefd,cmdbuf,strlen(cmdbuf));
		lwip_printf(fd,"<P> </P><B>%s %s</B><PRE>",prompt,cmdbuf);
		rv=lwip_showout(fd,vdefd);
		lwip_printf(fd,"</PRE><B>Result: %s</B>\r\n",strerror(rv-1000));
	}
}

static char css[]=
"<style type=\"text/CSS\"\r\n"
"<!--\r\n"
".core {\r\n"
"font-family: Helvetica;\r\n"
"color: #0000FF;\r\n"
"background-color: #FFFFFF;\r\n"
"text-align: justify;\r\n"
"margin-left: 5pt;\r\n"
"margin-top: 5pt;\r\n"
"margin-right: 5pt;\r\n"
"margin-bottom: 5pt;\r\n"
"}\r\n"
".sidebar {\r\n"
"font-family: Helvetica;\r\n"
"font-size: 12px;\r\n"
"color: #ff0000;\r\n"
"}\r\n"
"-->\r\n"
"</style>\r\n";

static char okmsg[]= 
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"\r\n";

static char errmsg[]= 
"HTTP/1.1 404 Not Found\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<HTML><HEAD>\r\n"
"<TITLE>404 Not Found</TITLE>\r\n"
"</HEAD><BODY>\r\n"
"<H1>Not Found</H1>\r\n"
"The requested URL was not found on this server.\r\n"
"<hr>VDE 2.0 WEB MGMT INTERFACE\r\n"
"</BODY></HTML>\r\n";

static void web_this_form(int fd,struct vdemenu *this)
{
	struct vdesub *sub;
	for (sub=this->sub;sub!=NULL;sub=sub->next) {
		if (*(sub->syntax) == 0) {
			lwip_printf(fd,
					"<TR><TD width=50><INPUT type=submit size=100 name=\"%s\" value=\"%s\"></TD>\r\n"
					"<TD width=100></TD>\r\n"
					"<TD width=100></TD>\r\n"
					"<TD width=300>%s</TD></TR>\r\n",
					"COMMAND",sub->name,sub->descr);
		} else {
			lwip_printf(fd,
					"<TR><TD width=50><INPUT type=submit size=100 name=\"%s\" value=\"%s\"></TD>\r\n"
					"<TD width=100>%s</TD>\r\n"
					"<TD width=100><INPUT type=text name=\"%s.arg\"></TD>\r\n"
					"<TD width=300>%s</TD></TR>\r\n",
					"COMMAND",sub->name,sub->syntax,sub->name,sub->descr);
		}
	}
}

static void web_menu_index(int fd)
{
	struct vdemenu *this;
	lwip_printf(fd,"<P><A HREF=\"index.html\">Home Page</A></P>\r\n");
	for (this=menuhead;this!=NULL;this=this->next)
		lwip_printf(fd,"<P><A HREF=\"%s.html\">%s</A></P>\r\n",this->name,this->name);
}

static void web_create_page(char *path,int fd,int vdefd,char *postdata)
{
	struct vdemenu *this=NULL;
	char *tail;
	if ((tail=strstr(path,".html")) != NULL)
		*tail=0;
	if (*path==0 || ((this=vde_findmenu(menuhead,path)) != NULL)) {
		lwip_write(fd,okmsg,sizeof(okmsg)-1);
		lwip_printf(fd,
				"<HTML><HEAD>\r\n"
				"<TITLE>%s %s</TITLE>\r\n",
				prompt, (*path==0)?"Home Page":path);
		lwip_write(fd,css,sizeof(css)-1);
		lwip_printf(fd,
				"</HEAD><BODY class=core>\r\n"
				"<H1>%s %s</H1>\r\n"
				"<TABLE BORDER=0><TD width=80 bgcolor=#aacbff valign=top class=sidebar>", 
				prompt, (*path==0)?"Home Page":this->descr);
		web_menu_index(fd);
		if (*path==0) {/* HOME PAGE */
			int rv;
			write(vdefd,"showinfo\r\n",10);
			lwip_printf(fd,
					"</TD><TD><PRE>\r\n");
			rv=lwip_showout(fd,vdefd);
			lwip_printf(fd,"</PRE>\r\n");
			if (rv != 1000)
				lwip_printf(fd,"<B>%s</B>\r\n",strerror(rv-1000));
		} else {
			lwip_printf(fd,
					"</TD><TD><FORM action=\"%s.html\" method=post table-layout=fixed>\r\n<TABLE><THEAD><TR>\r\n"
					"<TD><INPUT type=submit name=X style=\"visibility:hidden\" ></TD>\r\n"
					"<TD><B>Syntax</B></TD><TD><B>Args</B>\r\n"
					"</TD><TD><B>Description</B></TD></TR></THEAD>\r\n",path);
			web_this_form(fd,this);
			lwip_printf(fd,"</TABLE></FORM>\r\n");
			if (postdata != NULL) {
				postdata_parse(fd,vdefd,path,postdata);
			}
		}
		lwip_printf(fd,
				"</TD></TABLE>\r\n"
				"<hr>VDE 2.0 WEB MGMT INTERFACE\r\n"
				"</BODY></HTML>\r\n");
	} else
		lwip_write(fd,errmsg,sizeof(errmsg)-1);
}

static char authmsg[]= 
"HTTP/1.1 401 Authorization Required\r\n"
"WWW-Authenticate: Basic realm=\"";

//"Content-Length: 187\r\n"
//"Connection: close\r\n"
static char authmsg2[]= "\"\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<HTML><HEAD>\r\n"
"<TITLE>401 Authorization Required</TITLE>\r\n"
"</HEAD><BODY>\r\n"
"<H1>Authorization Required</H1>\r\n"
"Login and Password required\r\n"
"<hr>\r\nVDE 2.0 WEB MGMT INTERFACE\r\n"
"</BODY></HTML>\r\n";


int web_core(int fn,int fd,int vdefd)
{
	struct webstat *st=status[fn];
	//printf("CORE %s\n",st->linebuf);
	if (st->op==WEB_OP_POSTDATA) {
		//printf("POSTDATA %s\n",st->linebuf);
		web_create_page(&(st->path[1]),fd,vdefd,st->linebuf);
		return 1;
	} else if (strncmp(st->linebuf,"GET",3) == 0) {
		//printf("GET %s\n",st->linebuf);
		sscanf(st->linebuf+4,"%s",st->path);
		st->op=WEB_OP_GET;
		return 0;
	} else if (strncmp(st->linebuf,"POST",3) == 0) {
		//printf("POST %s\n",st->linebuf);
		sscanf(st->linebuf+5,"%s",st->path);
		st->op=WEB_OP_POST;
		return 0;
	} else if (strncmp(st->linebuf,"Content-Length: ",16) == 0) {
		st->bodylen=atoi(st->linebuf+16);
		//printf("BODYLEN %d\n",st->bodylen);
		return 0;
	} else if (strncmp(st->linebuf,"Authorization: Basic",20) == 0) {
		char passwd_buf[BUFSIZE];
		char *passwd_buf_shift;
		int len=strlen(st->linebuf);
		int k=20;
		while (st->linebuf[k] == ' ') k++;
		while (st->linebuf[len-1] == '\n' ||
				st->linebuf[len-1] == '\r' ||
				st->linebuf[len-1] == ' ') {
			len--;
			st->linebuf[len]=0;
		}
		/* SHA1 */
		decode64((st->linebuf + k), passwd_buf, strlen(st->linebuf + k));
		passwd_buf_shift = (char *)(strchr(passwd_buf, ':') + 1);
		if (sha1passwdok(passwd_buf_shift))
			st->status=WEB_AUTHORIZED;
		return 0;
	} else if (st->linebuf[0]=='\n' || st->linebuf[0]=='\r') {
		switch (st->status) {
			case WEB_IDENTIFY:
				lwip_write(fd,authmsg,sizeof(authmsg)-1);
				lwip_write(fd,prompt,strlen(prompt));
				lwip_write(fd,authmsg2,sizeof(authmsg2)-1);
				return 1;
				break;
			case WEB_AUTHORIZED:
				lowercase(st->path);
				if (strcmp(st->path,"/index.html") == 0) 
					st->path[1]=0;
				if (st->op == WEB_OP_GET) {
					web_create_page(&(st->path[1]),fd,vdefd,NULL);
					return 1;
				} else {
					st->op=WEB_OP_POSTDATA;
					return 0;
				}
			default:
				return 0;
		}
	} else
		return 0;
}

void webdata(int fn,int fd,int vdefd)
{
	char buf[BUFSIZE];
	int n,i;
	struct webstat *st=status[fn];
	n=lwip_read(fd,buf,BUFSIZE);
	if (n==0) {
		web_close(fn,fd);
	}
	else if (n<0)
		printlog(LOG_ERR,"web read err: %s",strerror(errno));
	else {
		for (i=0;i<n && st->bufindex<BUFSIZE;i++) {
			st->linebuf[(st->bufindex)++]=buf[i];
			if (buf[i]=='\n' || (st->op==WEB_OP_POSTDATA && st->bufindex==st->bodylen)) {
				st->linebuf[(st->bufindex)]=0;
				if (web_core(fn,fd,vdefd)) {
					web_close(fn,fd);
					break;
				} else
					st->bufindex=0;
			}
		}
	}
}

void webaccept(int fn,int fd,int vdefd)
{
	struct sockaddr_in  cli_addr;
	int newsockfd;
	unsigned int clilen;
	struct webstat *st;
	int newfn;

	clilen = sizeof(cli_addr);
	newsockfd = lwip_accept(fd, (struct sockaddr *) &cli_addr, &clilen);

	if (newsockfd < 0) {
		printlog(LOG_ERR,"web accept err: %s",strerror(errno));
	}

	newfn=addpfd(newsockfd,webdata);
	status[newfn]=st=malloc(sizeof(struct webstat));
	st->status=WEB_IDENTIFY;
	st->op=0;
	st->bufindex=0;
}

void web_init(int vdefd)
{
	int sockfd;
	struct sockaddr_in  serv_addr;
	sockfd=lwip_socket(AF_INET, SOCK_STREAM, 0);

	if (!sockfd) {
		printlog(LOG_ERR,"web socket err: %s",strerror(errno));
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family      = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port        = htons(WEB_TCP_PORT);

	if (lwip_bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		printlog(LOG_ERR,"web bind err: %s",strerror(errno));
	}

	lwip_listen(sockfd, 5);

	//createbase64passwd();
	menuhead=vde_gethelp(vdefd);
	addpfd(sockfd,webaccept);
}
