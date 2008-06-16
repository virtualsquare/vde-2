#ifndef _VDETELWEB_H
#define _VDETELWEB_H
#define BUFSIZE 1024
typedef void (*voidfun)();

extern void *status[];

extern char *banner;
extern char *prompt;

int sha1passwdok(const char *pw);
int addpfd(int fd,voidfun cb);
void delpfd(int fn);
int pfdsearch(int fd);
int openextravdem();
void telnet_init(int vdefd);
void web_init(int vdefd);

void printlog(int priority, const char *format, ...);

#endif
