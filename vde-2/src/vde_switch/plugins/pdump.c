#define _GNU_SOURCE
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

#include <vdeplugin.h>

#define DEFAULT_DUMPFILE "vde_dump.cap"

/* usage:
 *
 * plugin/add pdump.so
 * debug/add pdump/packetin
 * debug/add pdump/packetout
 * pdump/active 1
 */

/*
 * TODO(godog):
 *  - configurable snaplen
 *  - per-port dump(file?)
 *  TODO(shammash):
 *  - configurable size for buffered dump
 */
static int pktevent(struct dbgcl *tag, void *arg, va_list v);

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *desc = NULL;
pcap_dumper_t *dumper = NULL;
char *dumpfile = NULL;
static int buffered_dump = 0;

struct plugin vde_plugin_data={
	.name="pdump",
	.help="dump packets to file, in pcap format",
};

static int set_dumper(FILE *console) {
	int fd;
	FILE *fp;
	if ((fd = open(dumpfile, O_WRONLY | O_CREAT, 0600)) < 0) {
		printoutc(console, "%s() open(%s): %s", __FUNCTION__, dumpfile, strerror(errno));
		return -1;
	}
	if ((fp = fdopen(fd, "w")) == NULL) {
		printoutc(console, "%s() fdopen(): %s", __FUNCTION__, strerror(errno));
		return -1;
	}
	if ((dumper = pcap_dump_fopen(desc, fp)) == NULL) {
		printoutc(console, "%s() pcap_dump_fopen(): %s", __FUNCTION__, pcap_geterr(desc));
		return -1;
	}
	return 0;
}

// FIXME check if dumpfile exists, it will be trucated 
static int dump(FILE *fd, char *arg)
{
	int active=atoi(arg);
	int rv;
	if (active){
		if(!dumper && set_dumper(fd)) {
			printoutc(fd, "ERROR: cannot dump to %s", dumpfile);
			return EINVAL;
		}
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
		free(dumpfile);
		dumpfile = strdup(arg);
		if(dumper)
			pcap_dump_close(dumper);
		if (set_dumper(fd)) {
			printoutc(fd, "ERROR: cannot dump to %s", dumpfile);
			return EINVAL;
		}
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
	{"pdump/active","0/1","start dumping data",dump,STRARG|WITHFILE},
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

/* TODO(godog): activate debug as well when activated? */
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
	desc = pcap_open_dead(DLT_EN10MB, 96);
	dumpfile = strdup(DEFAULT_DUMPFILE);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	if(dumper) {
		pcap_dump_close(dumper);
		dumper = NULL;
	}
	pcap_close(desc);
	desc = NULL;
	free(dumpfile);

	DELCL(cl);
	DELDBGCL(dl);
}
