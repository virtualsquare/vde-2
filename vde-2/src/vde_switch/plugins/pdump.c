#define _GNU_SOURCE
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <vdeplugin.h>

/* usage:
 *
 * plugin/add pdump.so
 * debug/add pdump/packetin
 * debug/add pdump/packetout
 * pdump/active 1
 */

// TODO per-port dump(file?)
static int pktevent(struct dbgcl *tag, void *arg, va_list v);

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *desc = NULL;
pcap_dumper_t *dumper = NULL;
char *dumpfile = "vde_dump.cap";
static int buffered_dump = 0;

struct plugin vde_plugin_data={
	.name="pdump",
	.help="dump packets to file, in pcap format",
};

static int set_dumper(pcap_t *pcap_desc, char *file) {
	int fd;
	FILE *fp;
	if ((fd = open(file, O_WRONLY | O_NONBLOCK)) < 0)
		return -1;
	if ((fp = fdopen(fd, "w")) == NULL)
		return -1;
	dumper = pcap_dump_fopen(pcap_desc, fp);
	return 0;
}

// FIXME check if dumpfile exists, it will be trucated 
static int dump(char *arg)
{
	int active=atoi(arg);
	int rv;
	if (active){
		// TODO configurable snaplen 
		if(!desc)
			desc = pcap_open_dead(DLT_EN10MB, 96);
		
		if(!dumper)
			set_dumper(desc, dumpfile);
		
		rv=eventadd(pktevent,"packet",NULL);
	}else{
		rv=eventdel(pktevent,"packet",NULL);

		if(dumper)
			pcap_dump_flush(dumper);	
	}
	
	return rv;
}

static int setfname(FILE *fd, char *arg)
{
	if(strlen(arg)){
		if(dumper)
			pcap_dump_close(dumper);	

		dumpfile = strdup(arg);
		if(!desc)
			desc = pcap_open_dead(DLT_EN10MB, 96);
		set_dumper(desc, dumpfile);
	}
	
	printoutc(fd, "dumpfile=%s", dumpfile);	

	return 0;
}

static int setbuffered(char *arg)
{
	int b = atoi(arg);
	if (b)
		buffered_dump = 1;
	else
		buffered_dump = 0;
	return 0;
}

static struct comlist cl[]={
	{"pdump","============","DUMP Packets to file",NULL,NOARG},
	{"pdump/active","0/1","start dumping data",dump,STRARG},
	{"pdump/filename", "<file>", "set/show output filename (default: vde_dump.cap)", setfname, STRARG|WITHFILE},
	{"pdump/buffered", "0/1", "set buffered/unbuffered dump", setbuffered, STRARG},
};

/*
 *        pcap_t *pcap_open_dead(int linktype, int snaplen)
 *        int pcap_compile(pcap_t *p, struct bpf_program *fp,
 *                         char *str, int optimize, bpf_u_int32 netmask)
 *        int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
 *        void pcap_freecode(struct bpf_program *)
 */

// TODO activate debug as well when activated? 
#define D_DUMP 0100 
static struct dbgcl dl[]= {
	 {"pdump/packetin","dump incoming packet to file",D_DUMP|D_IN},
	 {"pdump/packetout","dump outgoing packet to file",D_DUMP|D_OUT},
};


static int pktevent(struct dbgcl *event,void * arg,va_list v)
{
	// is it better to define this static? 
	struct pcap_pkthdr hdr;

	if( (desc == NULL) || (dumper == NULL) ){
		return 0;
	}

	switch (event->tag) {
		case D_PACKET|D_OUT: 
		case D_PACKET|D_IN: {
							va_arg(v,int); /* port */
							unsigned char *buf=va_arg(v,unsigned char *);
							int len=va_arg(v,int);

							gettimeofday(&hdr.ts, NULL);
							hdr.caplen = len;
							hdr.len = len;
							pcap_dump((u_char *)dumper, &hdr, buf);
							if (!buffered_dump)
								pcap_dump_flush(dumper);	
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
	if(dumper)
		pcap_dump_close(dumper);

	DELCL(cl);
	DELDBGCL(dl);
}
