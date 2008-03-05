#include <stdlib.h>
#include <string.h>

#include <config.h>
#include <vde.h>
#include <vdecommon.h>

char *strndup(const char *s, size_t n)
{
	char *r = malloc(n+1);
	if(r){
		strncpy(r, s, n);
		r[n] = 0;
	}
	return r;
}

