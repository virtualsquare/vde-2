#ifndef __BLOWFISH_H
#define __BLOWFISH_H


#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/poll.h>
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
#include <libvdeplug/libvdeplug.h>

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

#define SRC_VDE 0
#define SRC_BF  1
#define SRC_CTL 2

#define PKT_DATA 0x20
#define PKT_CTL  0x40

#define CMD_LOGIN 0x41
#define CMD_CHALLENGE 0x42
#define CMD_RESPONSE 0x44
#define CMD_AUTH_OK 0x48
#define CMD_DENY 0x4A
#define CMD_HANDOVER 0x4C
#define CMD_IDENTIFY 0x4E

#define ST_CLOSED 0
#define ST_OPENING 1
#define ST_CHALLENGE 2
#define ST_AUTH	3
#define ST_SERVER 4
#define ST_WAIT_AUTH 5
#define ST_IDSENT 6

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
	unsigned char state;		/* Connection state		*/
	VDECONN *plug;			/* Vde connection channel 	*/
	
};

/*
 * Each datagram received from network or from vde_plug 
 * is arranged into a struct like this.
 */
struct datagram
{
	char data[MAXPKT];
	int len;
	int src;
	struct peer *orig;
};



struct peer
*getpeer(struct sockaddr_in address);

void
addpeer(struct peer *np);

void
removepeer(struct peer *np);

struct peer 
*generate_key (struct peer*);

//int 
//bf_encrypt (int,int);

//int
//bf_decrypt (int,int);

int 
blowfish_init(int);

struct datagram 
*blowfish_select(int timeout);

void 
send_udp( char *data, size_t len, struct peer *p, unsigned char flags );

void
send_vde( const char *data, size_t len, struct peer *p);
#endif
