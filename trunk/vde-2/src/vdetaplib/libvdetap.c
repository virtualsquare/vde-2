/* Copyright 2004 Renzo Davoli
 * Reseased under the GPLv2 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#define TUNTAPPATH "/dev/net/tun"
#define VDETAPEXEC LIBEXECDIR "/vdetap"
#define VDEALLTAP "VDEALLTAP"
#define MAX 10

#define nativesym(function, name) \
    { \
        const char *msg; \
	if (native_##function == NULL) { \
	    *(void **)(&native_##function) = dlsym(RTLD_NEXT, name); \
	    if ((msg = dlerror()) != NULL) { \
 		fprintf (stderr, "%s: dlsym(%s): %s\n", PACKAGE, name, msg); \
	    } \
	} \
    }

static int     (*native_ioctl) (int d, int request, ...) = NULL;
static int     (*native_open) (const char *pathname, int flags, ...) = NULL;
static int     (*native_open64) (const char *pathname, int flags, ...) = NULL;

int tapfd[2] = {-1,-1};
static int tapcount=0;
static int tuncount=0;

static struct pidlist {
	pid_t pid;
	struct pidlist *next;
} *plh = NULL, *flh=NULL, pidpool[MAX];

static struct pidlist *plmalloc(void) {
	struct pidlist *rv;
	rv=flh;
	if (rv != NULL) 
		flh=flh->next;
	return rv;
}

/* not used? 
static void plfree (struct pidlist *el) {
	el->next=flh;
	flh=el;
}
*/

static int addpid(int pid) {
	struct pidlist *plp;
	if ((plp=plmalloc ()) != NULL) {
		plp->next=plh;
		plh=plp;
		plp->pid=pid;
		return pid;
	} else {
		kill(pid,SIGTERM);
		return -1;
	}
}

void libvdetap_init (void) __attribute((constructor));
void libvdetap_init(void)
{
	register int i;
	nativesym(ioctl, "ioctl");
	nativesym(open, "open");
	nativesym(open64, "open64");
	for (i=1;i<MAX;i++) 
		pidpool[i-1].next= &(pidpool[i]);
	flh=pidpool;
}

void libvdetap_fini(void)
{
	struct pidlist *plp=plh;
	while (plp != NULL) {
		kill(plp->pid,SIGTERM);
		plp = plp->next;
	}
}

int open(const char *path, int flags, ...)
{
	va_list ap;
	int data;

	va_start(ap, flags);
	data = va_arg(ap, int);
	va_end(ap);

	if (strcmp(path,TUNTAPPATH)==0 && tapfd[0] == -1) {
		if (socketpair(PF_UNIX, SOCK_DGRAM, 0,tapfd) == 0)
			return tapfd[0];
		else
			return -1;

	} else
		return native_open(path, flags, data);
}

int open64(const char *path, int flags, ...)
{
	va_list ap;
	int data;

	va_start(ap, flags);
	data = va_arg(ap, int);
	va_end(ap);

	if (strcmp(path,TUNTAPPATH)==0 && tapfd[0] == -1) {
		if (socketpair(PF_UNIX, SOCK_DGRAM, 0,tapfd) == 0) 
			return tapfd[0];
		else
			return -1;

	} else
		return native_open64(path, flags | O_LARGEFILE, data);
}

static char *getvdeopt(struct ifreq *ifr,char *suffix)
{
	static char buf[16];
	char *rv;
	snprintf(buf,16,"%s_%s",ifr->ifr_name,suffix);
	if ((rv=getenv(buf)) != NULL)
		return rv;
	snprintf(buf,16,"VDEALLTAP_%s",suffix);
	if ((rv=getenv(buf)) != NULL)
		return rv;
	else
		return "";
}

#ifdef VDE_BIONIC
int ioctl(int fd, int command, ...)
#else
int ioctl(int fd, unsigned long int command, ...)
#endif
{
	va_list ap;
	char *data;
	char *vdesock;
	int pid;
	int callerpid=getpid();

	va_start(ap, command);
	data = va_arg(ap, char *);
	va_end(ap);

	if (fd == tapfd[0]) {
		if (command == TUNSETIFF) {
			struct ifreq *ifr = (struct ifreq *) data;
			char num[5];
			char name[10];
			char scallerpid[6];

			ifr->ifr_name[IFNAMSIZ-1] = '\0';
			if (ifr->ifr_name[0] == 0) {
				if (ifr->ifr_flags & IFF_TAP) 
					sprintf(name,"tap%d",tapcount++);
				else
					sprintf(name,"tun%d",tuncount++);
				strncpy(ifr->ifr_name,name,IFNAMSIZ);
			}
			else if (strchr(ifr->ifr_name, '%') != NULL) {
				sprintf(name,ifr->ifr_name,tapcount++);
				strncpy(ifr->ifr_name,name,IFNAMSIZ);
			}
			if ((ifr->ifr_flags & IFF_TAP) && (
					/* from env: single interface or VDEALLTAP */
					((vdesock=getenv(ifr->ifr_name)) != NULL) ||
						(vdesock=getenv(VDEALLTAP)) != NULL)
				 ){
				if ((pid=fork()) < 0) { 
					close(tapfd[1]);
					errno=EINVAL;
					return -1;
				} else if (pid > 0) { /*father*/
					if((pid=addpid(pid)) < 0) {
						close(tapfd[0]);
						close(tapfd[1]);
						return -1;
					} else {
						close(tapfd[1]);
						return 0;
					}
				} else { /*son*/
					plh=NULL;
					close(tapfd[0]);
					sprintf(num,"%d",tapfd[1]);
					sprintf(scallerpid,"%d",callerpid);
					return execlp(VDETAPEXEC,"-",num,vdesock,ifr->ifr_name,
							scallerpid,
							getvdeopt(ifr,"port"),
							getvdeopt(ifr,"group"),
							getvdeopt(ifr,"mode"),
							(char *) 0);
				}
			}
			else /*roll back to the native tuntap*/
			{
				int newfd;
				int saverrno;
				int resultioctl;
				close(tapfd[1]);
				if ((newfd=native_open(TUNTAPPATH,  O_RDWR, 0)) < 0) {
					saverrno=errno;
					close(tapfd[0]);
					errno=saverrno;
					return -1;
				} else
				{
					resultioctl=native_ioctl(fd, command, data);
					if (resultioctl < 0) {
						saverrno=errno;
						close(tapfd[0]);
						errno=saverrno;
						return -1;
					} else {
						dup2(newfd,tapfd[0]);
						return resultioctl;
					}
				}
			}
		} else  
			return 0;
	} else 
		return (native_ioctl(fd, command, data));
}

