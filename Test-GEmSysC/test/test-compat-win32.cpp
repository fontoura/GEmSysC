#include "test/test-compat.h"

#include <cstdio>
#include <cstdarg>
#include <windows.h>

using namespace std;

static LARGE_INTEGER freq;
static LARGE_INTEGER start;
static LARGE_INTEGER end;

extern "C" void IMPL_PRINTF(char * format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

extern "C" int IMPL_GETC()
{
	return getchar();
}

extern "C" void IMPL_START_TIMER()
{
	Sleep(1000);
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&start);
}

extern "C" void IMPL_END_TIMER()
{
	QueryPerformanceCounter(&end);
}

extern "C" long IMPL_READ_TIMER()
{
	return (long) ((1000000 * (end.QuadPart - start.QuadPart)) / freq.QuadPart);
}
