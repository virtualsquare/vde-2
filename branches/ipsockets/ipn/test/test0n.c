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
	//int s=socket(AF_IPN,SOCK_RAW,IPN_BROADCAST);
	int s=socket(AF_IPN,SOCK_RAW,IPN_VDESWITCH);
	int err;
	int len;
	int flags=IPN_FLAG_LOSSLESS;
	int size=128;
	int mode=0770;
	if (s< 0)
		perror("socket");
	printf("s=%d\n",s);
#if 0
	err=setsockopt(s,0,IPN_SO_FLAGS,&flags,sizeof(flags));
	if (err<0)
		perror("setsockopt");
	err=setsockopt(s,0,IPN_SO_MSGPOOLSIZE,&size,sizeof(size));
	if (err<0)
		perror("setsockopt");
	err=setsockopt(s,0,IPN_SO_MODE,&mode,sizeof(mode));
	if (err<0)
		perror("setsockopt");
#endif
	err=bind(s,(struct sockaddr *)&sun,sizeof(sun));
	if (err<0)
		perror("bind");
#if 0
	err=connect(s,NULL,0);
	if (err<0)
		perror("connect");
#endif
	while ((len=read(0,buf,256)) > 0) {
		/* err=write(s,buf,len);
		if (err<0)
			perror("write sock"); */
	}
	if (len < 0)
		perror("read stdin");
	close(s);
}
