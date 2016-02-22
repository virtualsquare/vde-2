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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

/* crc_tab[] -- this crcTable is being build by chksum_crc32GenTab().
 *		so make sure, you call it before using the other
 *		functions!
 */
u_int32_t crc_tab[256];

/* chksum_crc() -- to a given block, this one calculates the
 *				crc32-checksum until the length is
 *				reached. the crc32-checksum will be
 *				the result.
 */
u_int32_t chksum_crc32 (unsigned char *block, unsigned int length)
{
   unsigned long crc;
   unsigned long i;

   crc = 0xFFFFFFFF;
   for (i = 0; i < length; i++)
   {
      crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
   }
   return (crc ^ 0xFFFFFFFF);
}


unsigned char *crc32(unsigned char *block, unsigned int len)
{
	unsigned long crc=chksum_crc32(block,len);
	unsigned char *res=malloc(4);
	
	res[0]=crc&0x000000FF;
	res[1]=(crc&0x0000FF00)>>8;
	res[2]=(crc&0x00FF0000)>>16;
	res[3]=(crc&0xFF000000)>>24;
	return res;
}
		

/* chksum_crc32gentab() --      to a global crc_tab[256], this one will
 *				calculate the crcTable for crc32-checksums.
 *				it is generated to the polynom [..]
 */

void chksum_crc32gentab ()
{
   unsigned long crc, poly;
   int i, j;

   poly = 0xEDB88320L;
   for (i = 0; i < 256; i++)
   {
      crc = i;
      for (j = 8; j > 0; j--)
      {
	 if (crc & 1)
	 {
	    crc = (crc >> 1) ^ poly;
	 }
	 else
	 {
	    crc >>= 1;
	 }
      }
      crc_tab[i] = crc;
   }
}
