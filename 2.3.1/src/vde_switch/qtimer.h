#ifndef _QTIMER_H
#define _QTIMER_H
time_t qtime(); // returns global time (faster than time())
void qtime_csenter();
void qtime_csexit();
unsigned int qtimer_add(time_t period,int times,void (*call)(),void *arg);
void qtimer_del(unsigned int n);
void qtimer_init();
#endif
