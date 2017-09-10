#ifndef TEST_SHA256_H
#define TEST_SHA_H

//#define SHA256_VERBOSE

#define SHA256_DATA_LENGTH      ( 1000 )

#define SHA256_HASH_LENGTH      ( 256 / 8 )

typedef struct sha256_test_params
{
	struct sha256_test_params * next;
	unsigned char * buffer;
} sha256_test_params_t;

extern unsigned char sha256_buffer[SHA256_HASH_LENGTH];

extern sha256_test_params_t * sha256_tests;

long test_sha256_digest_native(long warm_up_times, long run_times);

long test_sha256_digest_cl(long warm_up_times, long run_times);

#ifdef SHA256_VERBOSE

#include "test/test-compat.h"

#define TEST_SHA256_PRINTF(...) IMPL_PRINTF(__VA_ARGS__)

#else

#define TEST_SHA256_PRINTF(...) {}

#endif

#endif
