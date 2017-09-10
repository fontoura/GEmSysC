#include <cl/cl.h>
#include <cl/cl-sha256.h>

#include "test/test-sha256.h"

#include "test/test-compat.h"

clSHA256Def(sha256_engine);

long test_sha256_digest_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId digest_id;
	clSHA256Create(&digest_id, clSHA256(sha256_engine));
	sha256_test_params_t * sha256_test = sha256_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(digest_id, (const void*)(sha256_test->buffer), SHA256_DATA_LENGTH, (void*)sha256_buffer, SHA256_HASH_LENGTH, NULL);
		//TEST_SHA256_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != SHA256_HASH_LENGTH)
		{
			return -1;
		}
		sha256_test = sha256_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = clEngineProcess(digest_id, (const void*)(sha256_test->buffer), SHA256_DATA_LENGTH, (void*)sha256_buffer, SHA256_HASH_LENGTH, NULL);
		//TEST_SHA256_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != SHA256_HASH_LENGTH)
		{
			return -1;
		}
		sha256_test = sha256_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(digest_id);
	return IMPL_READ_TIMER();
}

unsigned char sha256_in_buffer[SHA256_DATA_LENGTH];
unsigned char sha256_hash_buffer[SHA256_HASH_LENGTH];

int sha256_digest_cl()
{
	clEngineInstanceId digest_id;
	clSHA256Create(&digest_id, clSHA256(sha256_engine));
	clEngineProcess(digest_id, (const void*)sha256_in_buffer, SHA256_DATA_LENGTH, (void*)sha256_hash_buffer, SHA256_HASH_LENGTH, NULL);
	clEngineFinalize(digest_id);

	return 0;
}
