#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <af_ipn.h>

char buf[256];
struct sockaddr_un sun={.sun_family=AF_IPN,.sun_path="/tmp/sockipn"};
main()
{
	int s=socket(AF_IPN,SOCK_RAW,IPN_BROADCAST);
	int err;
	int len;
	if (s< 0) {
		s=socket(AF_IPN,SOCK_RAW,IPN_BROADCAST);
		if (s< 0)
			perror("socket");
	}
	printf("s=%d\n",s);
	err=connect(s,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("connect");
	while ((len=read(s,buf,256)) > 0) {
		write(1,buf,len);
	}
	if (len < 0)
		perror("read");
	close(s);
}
