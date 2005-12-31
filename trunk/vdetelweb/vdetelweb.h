#ifndef _VDETELWEB_H
#define _VDETELWEB_H
#define BUFSIZE 1024
#define LWIPV6DL
extern void *status[];

extern char *banner;
extern char *passwd;
extern char *prompt;

void printlog(int priority, const char *format, ...);

#endif
