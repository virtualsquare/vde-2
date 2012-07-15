#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <af_ipn.h>

#define LIMIT 10000
char buf[256];
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
	err=bind(s,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("bind");
	err=connect(s,NULL,0);
	if (err<0)
		perror("connect");
	for (i=0;i<LIMIT;i++) {
		sprintf(buf,"%d\n",i);
		err=write(s,buf,256);
		if (err<0)
			perror("write sock");
	}
	if (len < 0)
		perror("read stdin");
	close(s);
}
