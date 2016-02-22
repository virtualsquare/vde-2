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
 * based on implementation by Finn Yannick Jacobs  Krzysztof Dabrowski, ElysiuM deeZine 
 *
 */

#ifndef _CRC32_H
#define _CRC32_H

void chksum_crc32gentab();
unsigned char *crc32(unsigned char *block, unsigned int len);

#endif
