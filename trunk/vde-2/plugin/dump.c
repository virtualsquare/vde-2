#define _GNU_SOURCE
#include "vdeplugin.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef HAVE_OPEN_MEMSTREAM
#include <utils/open_memstream.h>
#endif

int testevent(struct dbgcl *tag,va_list v);
struct plugin vde_plugin_data={
	.name="dump",
	.help="dump packets",
};

static int dump(char *arg)
{
	int active=atoi(arg);
	int rv;
	if (active)
		rv=eventadd(testevent,"packet",NULL);
	else
		rv=eventdel(testevent,"packet",NULL);
	return 0;
}

static struct comlist cl[]={
	{"dump","============","DUMP Packets",NULL,NOARG},
	{"dump/active","0/1","start dumping data",dump,STRARG},
};

#define D_DUMP 0100 
static struct dbgcl dl[]= {
	 {"dump/packetin","dump incoming packet",D_DUMP|D_IN},
	 {"dump/packetout","dump outgoing packet",D_DUMP|D_OUT},
};


int testevent(struct dbgcl *event,va_list v)
{
	struct dbgcl *this=dl;
	switch (event->tag) {
		case D_PACKET|D_OUT: 
			this++;
		case D_PACKET|D_IN: 
			{
				int port=va_arg(v,int);
				char *buf=va_arg(v,char *);
				int len=va_arg(v,int);
				char *pktdump;
				size_t dumplen;
				FILE *out=open_memstream(&pktdump,&dumplen);
				if (out) {
					int i;
					fprintf(out,"Pkt: Port %04d len=%04d ",
							port,
							len);
					for (i=0;i<len;i++)
						fprintf(out,"%02x ",buf[i]);
					fclose(out);
					DBGOUT(this, "%s",pktdump);
					free(pktdump);
				}
			}
	}
	return 0;
}

	static void
	__attribute__ ((constructor))
init (void)
{
	ADDCL(cl);
	ADDDBGCL(dl);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	DELCL(cl);
	DELDBGCL(dl);
}
