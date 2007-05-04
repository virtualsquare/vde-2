/* BITARRAY (C) 2005 Renzo Davoli
 * Licensed under the GPLv2
 * Modified by Ludovico Gardenghi 2005
 *
 * A bitarray is (a pointer to) an array of memory words, can be used as a set.
 * +--------------------------------+--------------------------------+----
 * |33222222222211111111110000000000|66665555555555444444444433333333|999...
 * |10987654321098765432109876543210|32109876543210987654321098765432|543...
 * +--------------------------------+--------------------------------+----
 *
 * e.g. bit number 33 is the second LSB of the second word (in a 32 bit machine)
 *
 * bitarrays must be allocated bu BA_ALLOC
 * BA_REALLOC must know the old and the new size of the bitarray
 * BA_CHECK checks a bit (returns 0 if cleared, some value != 0 it set)
 * BA_SET sets a bit
 * BA_CLR clears a bit
 * BA_FORALL computes an expression for each set bit, 
 *           K is an integer var, must be defined in advance.
 *           it is the number of the set bit when the expression is evaluated
 * BA_FORALLFUN calls a function: first arg the index, second arg is ARG
 * BA_CARD counts how many bits are set
 *
 * BAC_ functions allocate one more trailing word to the bit array to store
 * the cardinality of the set (# of set bits).
 * This is useful when dealing with large sparse maybe empy sets.
 * BAC_SET/CLEAR are slightly more expensive but 
 * all the FORALL functions shortcut as soon as no more elements can be found.
 * If the set is empty the BAC FORALL macros exit immediately.
 * *** warning in case of memory leak may loop or segfault if the cardinality is
 *     overwritten ***
 *
 * Macro summary
 *
 * #define BA_ALLOC(N)
 * #define BA_REALLOC(B,N,M)
 * #define BA_CHECK(X,I)
 * #define BA_SET(X,I)
 * #define BA_CLR(X,I)
 * #define BA_ZAP(X,N)
 * #define BA_FORALLFUN(X,N,F,ARG)
 * #define BA_FORALL(X,N,EXPR,K)
 * #define BA_CARD(X,N)
 * #define BA_EMPTY(X,N)
 * #define BA_COPY(DST,SRC,N)     *** MUST HAVE THE SAME SIZE
 * #define BA_ADD(DST,SRC,N)      *** MUST HAVE THE SAME SIZE
 * #define BA_REMOVE(DST,SRC,N)   *** MUST HAVE THE SAME SIZE
 * #define BA_NEGATE(X,N)   *** MUST HAVE THE SAME SIZE
 *
 * #define BAC_ALLOC(N)
 * #define BAC_REALLOC(B,N,M)
 * #define BAC_CHECK(X,I)
 * #define BAC_SET(X,N,I)
 * #define BAC_CLR(X,N,I)
 * #define BAC_ZAP(X,N)
 * #define BAC_FORALLFUN(X,N,F,ARG)
 * #define BAC_FORALL(X,N,EXPR,K)
 * #define BAC_CARD(X,N)
 * #define BAC_EMPTY(X,N)
 * #define BAC_COPY(DST,SRC,N)   *** MUST HAVE THE SAME SIZE
 */

#ifndef _BITARRAY_H
#define _BITARRAY_H
#include <stdlib.h>
#include <limits.h>


#if __LONG_MAX__ == 2147483647L                     /* 32 bits */
# define __VDEWORDSIZE 32
# define __LOG_WORDSIZE (5)
# define __WORDSIZEMASK 0x1f
#elif __LONG_MAX__ == 9223372036854775807L          /* 64 bits */
# define __VDEWORDSIZE 64
# define __LOG_WORDSIZE (6)
# define __WORDSIZEMASK 0x3f
#else
# error sorry this program has been tested only on 32 or 64 bit machines
#endif

#define __WORDSIZE_1 (__VDEWORDSIZE-1)
#define __WORDSIZEROUND(VX) ((VX + __WORDSIZE_1) >> __LOG_WORDSIZE)

typedef unsigned long bitarrayelem;
typedef bitarrayelem *bitarray;

/* Simple Bit Array */
#define BA_ALLOC(N) (calloc(__WORDSIZEROUND(N),sizeof(unsigned long)))

#define BA_REALLOC(B,N,M) \
	({ register int __i;\
	 bitarray nb=realloc((B),__WORDSIZEROUND(M)*sizeof(unsigned long)); \
	 if(nb != NULL) \
	 for(__i=__WORDSIZEROUND(N);__i<__WORDSIZEROUND(M);__i++) \
	 nb[__i]=0; \
	 nb[__WORDSIZEROUND(N)-1] &= (1<<(((((N)&__WORDSIZEMASK)-1)&0x1f)+1))-1; \
	 (B)=nb;})

#define BA_CHECK(X,I) ((X) && ((X)[(I)>>__LOG_WORDSIZE] & (1 << ((I) & __WORDSIZEMASK)))) 

#define BA_SET(X,I) ((X)[(I)>>__LOG_WORDSIZE] |= (1 << ((I) & __WORDSIZEMASK)))

#define BA_CLR(X,I) ((X)[(I)>>__LOG_WORDSIZE] &= ~(1 << ((I) & __WORDSIZEMASK)))

#define BA_ZAP(X,N) \
	({ register unsigned int __i; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 (X)[__i]=0; \
	 0 ; })

#define BA_FORALLFUN(X,N,F,ARG) \
	({ register unsigned int __i,__j; \
	 register bitarrayelem __v; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 for (__v=(X)[__i],__j=0; __j < __VDEWORDSIZE; __v >>=1, __j++) \
	 if (__v & 1) (F)(__i*__VDEWORDSIZE+__j,(ARG)); \
	 0; })

#define BA_FORALL(X,N,EXPR,K) \
	({ register unsigned int __i,__j; \
	 register bitarrayelem __v; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 for (__v=(X)[__i],__j=0; __j < __VDEWORDSIZE; __v >>=1, __j++) \
	 if (__v & 1) {(K)=__i*__VDEWORDSIZE+__j;(EXPR);} \
	 0; })

#define BA_CARD(X,N) \
	({ register unsigned int __i,__j,__n=0; \
	 register bitarrayelem __v; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 for (__v=(X)[__i],__j=0; __j < __VDEWORDSIZE; __v >>=1, __j++) \
	 if (__v & 1) __n++; \
	 __n; })

#define BA_EMPTY(X,N) \
	({ register unsigned int __i; \
	 register bitarrayelem __v=0; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 __v |= (X)[__i]; \
	 __v; })

#define BA_COPY(DST,SRC,N) memcpy(DST,SRC,sizeof(bitarrayelem) * __WORDSIZEROUND(N))

#define BA_ADD(DST,SRC,N) \
	({ register unsigned int __i; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 (DST)[__i] |= (SRC)[__i]; \
	 0; })

#define BA_REMOVE(DST,SRC,N) \
	({ register unsigned int __i; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 (DST)[__i] &= ~((SRC)[__i]); \
	 nb[max-1] &= (1<<(((((N)&__WORDSIZEMASK)-1)&0x1f)+1))-1; \
	 0; })

#define BA_NEGATE(X,N) \
	({ register unsigned int __i; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 (X)[__i] = ~((X)[__i]); \
	 nb[max-1] &= (1<<(((((N)&__WORDSIZEMASK)-1)&0x1f)+1))-1; \
	 0; })

/* Bit Array with Cardinality (Count of set bit) */
/* it is stored after the last element */

#define BAC_ALLOC(N) (calloc(__WORDSIZEROUND(N)+1,sizeof(unsigned long)))

#define BAC_REALLOC(B,N,M) \
	({ register int __i;\
	 register int __size=(B)[__WORDSIZEROUND(N)]; \
	 bitarray nb=realloc((B),(__WORDSIZEROUND(M)+1)*sizeof(unsigned long)); \
	 if(nb != NULL) { \
	 (B)[__WORDSIZEROUND(M)]=__size; \
	 for(__i=__WORDSIZEROUND(N);__i<__WORDSIZEROUND(M);__i++) \
	 nb[__i]=0; }\
	 nb[__WORDSIZEROUND(N)-1] &= (1<<(((((N)&__WORDSIZEMASK)-1)&0x1f)+1))-1; \
	 (B)=nb;})

/* BA_CHECK and BAC_CHECK are the same */
#define BAC_CHECK(X,I) ((X) && ((X)[(I)>>__LOG_WORDSIZE] & (1 << ((I) & __WORDSIZEMASK))))

#define BAC_SET(X,N,I) \
	({ register int __v=(X)[(I)>>__LOG_WORDSIZE]; \
		register int __w=__v; \
		__v |= (1 << ((I) & __WORDSIZEMASK)); \
		if (__v != __w) (X)[(I)>>__LOG_WORDSIZE]=__v,((X)[__WORDSIZEROUND(N)]++); \
		})

#define BAC_CLR(X,N,I) \
	({ register int __v=(X)[(I)>>__LOG_WORDSIZE]; \
	 register int __w=__v; \
	 __v &= ~(1 << ((I) & __WORDSIZEMASK)); \
	 if (__v != __w) (X)[(I)>>__LOG_WORDSIZE]=__v,((X)[__WORDSIZEROUND(N)]--); \
	 })

#define BAC_ZAP(X,N) \
	({ register unsigned int __i; \
	 int max=__WORDSIZEROUND(N); \
	 for (__i=0; __i< max; __i++) \
	 (X)[__i]=0; \
	 (X)[__i]=0; \
	 0 ; })

#define BAC_FORALLFUN(X,N,F,ARG) \
	({ register unsigned int __i,__j; \
	 register bitarrayelem __v; \
	 register int __n=(X)[__WORDSIZEROUND(N)]; \
	 for (__i=0; __n > 0; __i++) \
	 for (__v=(X)[__i],__j=0; __j < __VDEWORDSIZE; __v >>=1, __j++) \
	 if (__v & 1) (F)(__i*__VDEWORDSIZE+__j,(ARG)),__n--; \
	 0; })

#define BAC_FORALL(X,N,EXPR,K) \
	({ register unsigned int __i,__j; \
	 register bitarrayelem __v; \
	 register int __n=(X)[__WORDSIZEROUND(N)]; \
	 for (__i=0; __n > 0; __i++) \
	 for (__v=(X)[__i],__j=0; __j < __VDEWORDSIZE; __v >>=1, __j++) \
	 if (__v & 1) (K)=__i*__VDEWORDSIZE+__j,(EXPR),__n--; \
	 0; })

#define BAC_CARD(X,N) ((X)[__WORDSIZEROUND(N)])
#define BAC_EMPTY(X,N) ((X)[__WORDSIZEROUND(N)]==0)

#define BAC_COPY(DST,SRC,N) memcpy(DST,SRC,sizeof(bitarrayelem) * __WORDSIZEROUND(N))

#if 0
/* usage example */
int fun(int i,int arg)
{
	printf("I %d\n",i);
}

int main (int argc, char *argv[])
{
	bitarray b;
	int k;
	if (argc != 2) return 0;
	int val=atoi(argv[1]);
	if (val < 34) return 0;
	printf("%d -round-> %d\n",val,__WORDSIZEROUND(val));
	b=BA_ALLOC(val);
	BA_SET(b,31);
	BA_SET(b,33);
	printf("%d -> %d\n",31,BA_CHECK(b,31));
	printf("%d -> %d\n",33,BA_CHECK(b,33));
	printf("CARD %d\n",BA_CARD(b,val));
	BA_FORALLFUN(b,val,fun,0);
	BA_FORALL(b,val,(printf("E1 %d\n",k)),k);
	printf("RE127\n");
	b=BA_REALLOC(b,val,127);
	BA_FORALL(b,127,(printf("E2 %d\n",k)),k);
	printf("RE42\n");
	b=BA_REALLOC(b,127,42);
	BA_FORALL(b,127,(printf("E3 %d\n",k)),k);
	BA_CLR(b,31);
	printf("%d -> %d\n",31,BA_CHECK(b,31));
	printf("CARD %d\n",BA_CARD(b,42));
	BA_CLR(b,33);
	printf("%d -> %d\n",33,BA_CHECK(b,33));
	printf("CARD %d\n",BA_CARD(b,42));
	b=BAC_ALLOC(val);
	if (argc != 2) return 0;
	printf("%d -> %d\n",val,__WORDSIZEROUND(val));
	BAC_SET(b,val,31);
	BAC_SET(b,val,33);
	printf("%d -> %d\n",31,BAC_CHECK(b,31));
	printf("%d -> %d\n",33,BAC_CHECK(b,33));
	printf("CARD %d\n",BAC_CARD(b,val));
	BAC_FORALLFUN(b,val,fun,0);
	BAC_FORALL(b,val,(printf("E1 %d\n",k)),k);
	printf("RE127\n");
	printf("CARD %d\n",BAC_CARD(b,val));
	b=BAC_REALLOC(b,val,127);
	BAC_FORALL(b,127,(printf("E2 %d\n",k)),k);
	printf("RE42\n");
	b=BAC_REALLOC(b,127,42);
	BAC_FORALL(b,42,(printf("E3 %d\n",k)),k);
	BAC_CLR(b,42,31);
	printf("%d -> %d\n",31,BAC_CHECK(b,31));
	printf("CARD %d\n",BAC_CARD(b,42));
	BAC_CLR(b,42,33);
	printf("%d -> %d\n",33,BAC_CHECK(b,33));
	printf("CARD %d\n",BAC_CARD(b,val));
}
#endif
#endif
