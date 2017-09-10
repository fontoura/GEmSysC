#ifndef TEST_COMPAT_H_INCLUDED
#define TEST_COMPAT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

void IMPL_PRINTF(char * format, ...);
int IMPL_GETC();
void IMPL_START_TIMER();
void IMPL_END_TIMER();
long IMPL_READ_TIMER();

#ifdef __cplusplus
}
#endif

#endif /* TEST_COMPAT_H_INCLUDED */
