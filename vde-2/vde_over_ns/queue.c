/* ----------------------------------------------------------------------------
 *
    VDE_OVER_NS 
	(C) 2007 Daniele Lacamera

    Derived from:
    NSTX -- tunneling network-packets over DNS

     (C) 2000 by Florian Heinz and Julien Oster

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  -------------------------------------------------------------------------- */
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "fun.h"

static struct nstxqueue *qhead = NULL;
static int qlen = 0;
static int qtimeout = QUEUETIMEOUT;

struct nstxqueue *finditem (unsigned short id)
{
   struct nstxqueue *ptr;
   
   for (ptr = qhead; ptr; ptr = ptr->next)
     if (ptr->id == id)
       break;
   
   return ptr;
}

void
queueitem(unsigned short id, const char *name, const struct sockaddr_in *peer)
{
   struct nstxqueue *ptr, *tmp;
   
   if (finditem(id))
     return;
   
   qlen++;
   ptr = malloc(sizeof(struct nstxqueue));
   memset(ptr, 0, sizeof(struct nstxqueue));
   if (!qhead)
     qhead = ptr;
   else {
      for (tmp = qhead; tmp->next; tmp = tmp->next)
	;
     tmp->next = ptr;
   }
   ptr->id = id;
   if (name)
     strcpy(ptr->name, name);
   if (peer)
     memcpy(&ptr->peer, peer, sizeof(struct sockaddr_in));
   ptr->timeout = time(NULL) + qtimeout;
}

void queueid (unsigned short id)
{
   queueitem(id, NULL, NULL);
}

struct nstxqueue *dequeueitem (int id)
{
   static struct nstxqueue *tmp = NULL, *ptr;

   if (!qhead)
     return NULL;
   if (tmp)
     free(tmp);

   if ((id < 0) || (qhead->id == id))
     {
	tmp = qhead;
	qhead = qhead->next;
	qlen--;
     }
   else
     {
	ptr = qhead;
	for (tmp = qhead->next; tmp; tmp = tmp->next)
	  {
	     if (tmp->id == id)
	       {
		  ptr->next = tmp->next;
		  qlen--;
		  break;
	       }
	     ptr = tmp;
	  }
     }
   
   return tmp;
}

void timeoutqueue (void (*timeoutfn)(struct nstxqueue *))
{
   struct nstxqueue *ptr;
   time_t now;
   
   now = time(NULL);
   
   while (qhead && (qhead->timeout <= now))
     {
	if (timeoutfn)
	  timeoutfn(qhead);
	ptr = qhead;
	qhead = qhead->next;
	qlen--;
	free(ptr);
     }
}

int queuelen (void)
{
   return qlen;
}

void qsettimeout (int timeout)
{
   qtimeout = timeout;
}
