#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define AF_IPN 33
#define PF_IPN AF_IPN
#define IPN_ANY 0
#define IPN_BROADCAST 1
#define IPN_HUB 1
#define IPN_SWITCH 2
#define IPN_SWITCH_L3 3

unsigned char buf[256];
struct sockaddr_un sun={.sun_family=AF_IPN,.sun_path="/tmp/sockipn"};
main()
{
	int s=socket(AF_IPN,SOCK_RAW,IPN_BROADCAST);
	int err;
	int len;
	int i;
	if (s< 0)
		perror("socket");
	printf("s=%d\n",s);
	err=connect(s,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("connect");
	while ((len=read(s,buf,256)) > 0) {
		for (i=0;i<len;i++)
			printf("%02x:",buf[i]);
		printf("\n");
	}
	if (len < 0)
		perror("read");
	close(s);
}
