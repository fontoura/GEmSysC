#include <wolfssl/wolfcrypt/sha256.h>

#include "test/test-sha256.h"

#include "test/test-compat.h"

long test_sha256_digest_native(long warm_up_times, long run_times)
{
	Sha256 sha256;
	wc_InitSha256(&sha256);
	sha256_test_params_t * sha256_test = sha256_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		wc_Sha256Update(&sha256, (const byte*)(sha256_test->buffer), SHA256_DATA_LENGTH);
		wc_Sha256Final(&sha256, (byte*)sha256_buffer);
		TEST_SHA256_PRINTF("%i\r\n", SHA256_HASH_LENGTH);
		sha256_test = sha256_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		wc_Sha256Update(&sha256, (const byte*)(sha256_test->buffer), SHA256_DATA_LENGTH);
		wc_Sha256Final(&sha256, (byte*)sha256_buffer);
		TEST_SHA256_PRINTF("%i\r\n", SHA256_HASH_LENGTH);
		sha256_test = sha256_test->next;
	}
	IMPL_END_TIMER();
	return IMPL_READ_TIMER();
}

unsigned char sha256_in_buffer[SHA256_DATA_LENGTH];
unsigned char sha256_hash_buffer[SHA256_HASH_LENGTH];

int sha256_digest_library()
{
	Sha256 sha256;
	wc_InitSha256(&sha256);
	wc_Sha256Update(&sha256, (const byte*)sha256_in_buffer, SHA256_DATA_LENGTH);
	wc_Sha256Final(&sha256, (byte*)sha256_hash_buffer);

	return 0;
}
