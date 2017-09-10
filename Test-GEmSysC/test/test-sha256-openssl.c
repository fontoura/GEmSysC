#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "test/test-sha256.h"

#include "test/test-compat.h"

long test_sha256_digest_native(long warm_up_times, long run_times)
{
	EVP_MD_CTX * evp_digest_context = EVP_MD_CTX_create();
	EVP_DigestInit_ex(evp_digest_context, EVP_sha256(), NULL);
	sha256_test_params_t * sha256_test = sha256_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = SHA256_HASH_LENGTH;
		EVP_DigestUpdate(evp_digest_context, (const void*)(sha256_test->buffer), SHA256_DATA_LENGTH);
		EVP_DigestFinal_ex(evp_digest_context, (void*)sha256_buffer, &TEST_LEN);
		TEST_SHA256_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != SHA256_HASH_LENGTH)
		{
			return -1;
		}
		sha256_test = sha256_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = SHA256_HASH_LENGTH;
		EVP_DigestUpdate(evp_digest_context, (const void*)(sha256_test->buffer), SHA256_DATA_LENGTH);
		EVP_DigestFinal_ex(evp_digest_context, (void*)sha256_buffer, &TEST_LEN);
		TEST_SHA256_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != SHA256_HASH_LENGTH)
		{
			return -1;
		}
		sha256_test = sha256_test->next;
	}
	IMPL_END_TIMER();
	EVP_MD_CTX_destroy(evp_digest_context);
	return IMPL_READ_TIMER();
}

unsigned char sha256_in_buffer[SHA256_DATA_LENGTH];
unsigned char sha256_hash_buffer[SHA256_HASH_LENGTH];

int sha256_digest_library()
{
	EVP_MD_CTX * evp_digest_context = EVP_MD_CTX_create();
	unsigned int hash_len = SHA256_HASH_LENGTH;
	EVP_DigestInit_ex(evp_digest_context, EVP_sha256(), NULL);
	EVP_DigestUpdate(evp_digest_context, (const void*)sha256_in_buffer, SHA256_DATA_LENGTH);
	EVP_DigestFinal_ex(evp_digest_context, (void*)sha256_hash_buffer, &hash_len);
	EVP_MD_CTX_destroy(evp_digest_context);

	return 0;
}
