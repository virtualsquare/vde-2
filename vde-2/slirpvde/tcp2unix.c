/* Copyright 2007 Renzo Davoli 
 * Licensed under the GPLv2
 */

#include <stdlib.h>
#include <string.h>

struct tcp2unix {
	int port;
	char *path;
	struct tcp2unix *next;
};

static struct tcp2unix *head;

int tcp2unix_check;

void tcp2unix_add(int port,char *path)
{
	struct tcp2unix *new=malloc(sizeof (struct tcp2unix));

	if (new) {
		new->next=head;
		new->port=port;
		new->path=strdup(path);
		head=new;
		tcp2unix_check=1;
	}
}

char *tcp2unix_search(int port)
{
	if (head) {
		struct tcp2unix *t2u;
		for (t2u=head;t2u;t2u=t2u->next) {
			if (port==t2u->port)
				return t2u->path;
		}
	}
	return NULL;
}
