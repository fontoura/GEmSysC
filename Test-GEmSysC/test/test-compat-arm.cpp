#include "test/test-compat.h"

#include <cstdarg>
#include <mbed.h>

Serial test_serial(p13, p14);
Timer test_timer;

extern "C" void IMPL_PRINTF(char * format, ...)
{
    va_list args;
    va_start(args, format);
    test_serial.vprintf(format, args);
    va_end(args);
}

extern "C" int IMPL_GETC()
{
	return test_serial.getc();
}

extern "C" void IMPL_START_TIMER()
{
	test_timer.reset();
	test_timer.start();
}

extern "C" void IMPL_END_TIMER()
{
	test_timer.stop();
}

extern "C" long IMPL_READ_TIMER()
{
	return test_timer.read_ms();
}
