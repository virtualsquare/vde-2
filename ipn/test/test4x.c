#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define AF_IPN 33
#define PF_IPN AF_IPN
#define IPN_ANY 0
#define IPN_BROADCAST 1
#define IPN_HUB 1
#define IPN_SWITCH 2
#define IPN_SWITCH_L3 3

#define IPN_SO_PREBIND 0x80
#define IPN_SO_PORT 0
#define IPN_SO_DESCR 1
#define IPN_SO_MTU (IPN_SO_PREBIND | 0)
#define IPN_SO_NUMNODES (IPN_SO_PREBIND | 1)
#define IPN_SO_MSGPOOLSIZE (IPN_SO_PREBIND | 2)
#define IPN_SO_FLAGS (IPN_SO_PREBIND | 3)
#define IPN_SO_MODE (IPN_SO_PREBIND | 4)

/* Ioctl defines */
#define IPN_SETPERSIST_NETDEV    _IOW('I', 200, int) 
#define IPN_CLRPERSIST_NETDEV    _IOW('I', 201, int) 
#define IPN_CONN_NETDEV          _IOW('I', 202, int) 
#define IPN_JOIN_NETDEV          _IOW('I', 203, int) 
#define IPN_SETPERSIST           _IOW('I', 204, int) 

#define IPN_NODEFLAG_TAP   0x10    /* This is a tap interface */
#define IPN_NODEFLAG_GRAB  0x20    /* This is a grab of a real interface */

#define IPN_PORTNO_ANY -1

#define IPN_DESCRLEN 32

#define IPN_FLAG_LOSSLESS 1

/*#define IPNTYPE IPN_BROADCAST*/
#define IPNTYPE IPN_SWITCH

char buf[256];
struct sockaddr_un sun={.sun_family=AF_IPN,.sun_path="/tmp/sockipn"};
main()
{
	int s=socket(AF_IPN,SOCK_RAW,IPNTYPE);
	int s2=socket(AF_IPN,SOCK_RAW,IPNTYPE);
	int err;
	int len;
	int flags=IPN_FLAG_LOSSLESS;
	int size=128;
	int mode=0770;
	struct ifreq ifr;
	if (s< 0)
		perror("socket");
	printf("s=%d\n",s);
	/*
	err=setsockopt(s,0,IPN_SO_FLAGS,&flags,sizeof(flags));
	if (err<0)
		perror("setsockopt");
	err=setsockopt(s,0,IPN_SO_MSGPOOLSIZE,&size,sizeof(size));
	if (err<0)
		perror("setsockopt");
	err=setsockopt(s,0,IPN_SO_MODE,&mode,sizeof(mode));
	if (err<0)
		perror("setsockopt");
		*/
	err=bind(s,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("bind");
	err=bind(s2,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("bind2");
	/*
	err=connect(s,NULL,0);
	*/
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
	ifr.ifr_flags=IPN_NODEFLAG_GRAB;
	err=ioctl(s, IPN_CONN_NETDEV, (void *) &ifr);
	if (err<0)
		perror("connect");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "ipn1", IFNAMSIZ);
	ifr.ifr_flags=IPN_NODEFLAG_TAP;
	err=ioctl(s2, IPN_CONN_NETDEV, (void *) &ifr);
	if (err<0)
		perror("connect2");

	while ((len=read(0,buf,256)) > 0) {
		//err=write(s,buf,len);
		if (err<0)
			perror("write sock");
	}
	if (len < 0)
		perror("read stdin");
	close(s);
}
