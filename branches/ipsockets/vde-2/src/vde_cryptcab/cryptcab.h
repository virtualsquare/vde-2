/*
 * VDE Cryptcab
 * Copyright © 2006-2008 Daniele Lacamera
 * from an idea by Renzo Davoli
 *
 * Released under the terms of GNU GPL v.2
 * (http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
 * with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 */

#ifndef __CRYPTCAB_H
#define __CRYPTCAB_H

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <dirent.h>
#include <getopt.h>
#include <signal.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>


#define PORTNO 7667


#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <config.h>
#include <libvdeplug.h>

#include "crc32.h"

#define IP_SIZE 1024
#define OP_SIZE 1032
#define MAXPKT 2000
#define FILENAMESIZE 16

#ifdef XOR
  #undef XOR
#endif
#define XOR(a,b) a==b?0:1

#define before_time(a,b) a.tv_sec==b.tv_sec?a.tv_usec<b.tv_usec:a.tv_sec<b.tv_sec

#ifdef MIN
  #undef MIN
#endif
#define MIN(a,b) a<b?a:b

#define SRC_VDE 0x0
#define SRC_UDP 0x1

#define PKT_DATA 0x20
#define PKT_CTL  0x40

#define CMD_LOGIN 0x41
#define CMD_CHALLENGE 0x42
#define CMD_RESPONSE 0x44
#define CMD_AUTH_OK 0x48
#define CMD_DENY 0x4A
#define CMD_KEEPALIVE 0x4F

#define ST_CLOSED 0x100
#define ST_OPENING 0x200
#define ST_CHALLENGE 0x300
#define ST_AUTH	0x400
#define ST_SERVER 0x500
#define ST_WAIT_AUTH 0x600

#define SESSION_TIMEOUT 120
#define CHALLENGE_TIMEOUT 20
#define PRELOGIN_TIMEOUT 3
#define EXPIRE_NOW 0
#define time_now(x) gettimeofday(x,NULL)

enum e_enc_type {
	ENC_NOENC = 0,
	ENC_PRESHARED = 1,
	ENC_SSH = 2
};

/*
 * This struct contains the other endpoint's informations.
 */
struct peer
{
	struct peer *next;		/* Next list element		*/	
	unsigned long long counter; 	/* Progressive N number 	*/
	unsigned char key[16];		/* Blowfish key			*/
	unsigned char iv[8];		/* Blowfish vector		*/
	char id[FILENAMESIZE];		/* Filename for key on server	*/
	char challenge[128];		/* 128B Challenge for 4WHS	*/
	struct sockaddr_in in_a;	/* Current transport address	*/
	struct sockaddr_in handover_a;	/* Handover transport address	*/
	struct timeval expire;		/* Expiration timer		*/
	unsigned short state;		/* Connection state		*/
	VDECONN *plug;			/* Vde connection channel 	*/
	
};
#define ip_address(X) X->in_a.sin_addr.s_addr
#define after(a,b) (a.tv_sec == b.tv_sec ) ? (a.tv_usec > b.tv_usec) : (a.tv_sec > b.tv_sec)


/*
 * Each datagram received from network or from vde_plug 
 * is arranged into a struct like this.
 */
struct datagram
{
	unsigned char data[MAXPKT];
	int len;
	int src;
	struct peer *orig;
};

void vc_printlog(int priority, const char *format, ...);

void 
send_udp(unsigned char *data, size_t len, struct peer *p, unsigned char flags );

void
send_vde( const char *data, size_t len, struct peer *p);

void
vde_plug(struct peer *, char *);

int isvalid_crc32(unsigned char *block, int len);
void disable_encryption(void);
void set_nfd(int fd);
int isvalid_timestamp(unsigned char *block, int size, struct peer *p);
int data_encrypt(unsigned char *src, unsigned char *dst, int len, struct peer *p);
int data_decrypt(unsigned char *src, unsigned char *dst, int len, struct peer *p);
void set_timestamp(unsigned char *block);
void send_udp (unsigned char *data, size_t len, struct peer *p, unsigned char flags);
void send_vdeplug(const char *data, size_t len, struct peer *p);

void cryptcab_server(char *_plugname, unsigned short udp_port, enum e_enc_type enc_type, char *pre_shared);
void cryptcab_client(char *_plugname, unsigned short udp_port, enum e_enc_type _enc_type, char *_pre_shared, char *_remoteusr, char *_remotehost, unsigned short _remoteport, unsigned char _keepalives, char *scp_extra_options);

#endif
