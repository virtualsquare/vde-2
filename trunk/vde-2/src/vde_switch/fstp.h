/* Copyright 2005 Renzo Davoli VDE-2
 * Some minor remain from uml_switch Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPLv2 
 */

#ifndef _FSTP_H
#define _FSTP_H
#include "port.h"

#ifdef FSTP
#define FSTP_TAG 0x1

extern unsigned char bpduaddrp[];
#define ISBPDU(P) (memcmp((P)->header.dest,bpduaddrp,ETH_ALEN)==0)

void fstpshutdown(void);
int fstnewvlan(int vlan);
int fstremovevlan(int vlan);
void fstsetnumports (int val);
void fst_in_bpdu(int port, struct packet *p, int len, int vlan, int tagged);
void fstaddport(int vlan,int port,int tagged);
void fstdelport(int vlan,int port);
int fstflag(int op, int f);
void fst_init(int initnumports);
#endif
#endif
