/*
 * VDE Cryptcab
 * Copyright © 2006-2008 Daniele Lacamera
 * from an idea by Renzo Davoli
 *
 * Released under the terms of GNU GPL v.2
 * (http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
 *
 */

#ifndef _CRC32_H
#define _CRC32_H
#include <stdint.h>

void chksum_crc32gentab();
uint32_t chksum_crc32(unsigned char *block, unsigned int length);
unsigned char *crc32(unsigned char *block, unsigned int len);

#endif
