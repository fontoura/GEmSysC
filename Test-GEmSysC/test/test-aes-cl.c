#include <cl/cl.h>
#include <cl/cl-aes.h>

#include "test/test-aes.h"

#include "test/test-compat.h"

clAESDef(aes_engine, CL_AES_KEYLENGTH_256);

long test_aes_256_ebc_encrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId encrypt_id;
	clAESEncryptCreate(&encrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_ECB, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(encrypt_id);
	return IMPL_READ_TIMER();
}

long test_aes_256_ebc_decrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId decrypt_id;
	clAESDecryptCreate(&decrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_ECB, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(decrypt_id);
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_encrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId encrypt_id;
	clAESEncryptCreate(&encrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_CBC, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(encrypt_id);
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_decrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId decrypt_id;
	clAESDecryptCreate(&decrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_CBC, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)aes_test->buffer, AES_DATA_LENGTH, (void*)aes_buffer, AES_DATA_LENGTH, NULL);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(decrypt_id);
	return IMPL_READ_TIMER();
}

unsigned char aes_in_buffer[AES_DATA_LENGTH];
unsigned char aes_encrypted_buffer[AES_DATA_LENGTH];
unsigned char aes_decrypted_buffer[AES_DATA_LENGTH];

#define AES_SAMPLE_DATA_LENGTH ( 16 )

int aes_cbc_encrypt_then_decrypt_cl(void)
{
	// create encryption engine and encrypt data.
	clEngineInstanceId encrypt_id;
	clAESEncryptCreate(&encrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_CBC, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	clEngineProcess(encrypt_id, (const void*)aes_in_buffer, AES_DATA_LENGTH, (void*)aes_encrypted_buffer, AES_DATA_LENGTH, NULL);
	clEngineFinalize(encrypt_id);

	// create decryption engine and decrypt data.
	clEngineInstanceId decrypt_id;
	clAESDecryptCreate(&decrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_CBC, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	clEngineProcess(decrypt_id, (const void*)aes_encrypted_buffer, AES_DATA_LENGTH, (void*)aes_decrypted_buffer, AES_DATA_LENGTH, NULL);
	clEngineFinalize(decrypt_id);

	return 0;
}

int aes_ecb_encrypt_then_decrypt_cl(void)
{
	// create encryption engine and encrypt data.
	clEngineInstanceId encrypt_id;
	clAESEncryptCreate(&encrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_ECB, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	clEngineProcess(encrypt_id, (const void*)aes_in_buffer, AES_DATA_LENGTH, (void*)aes_encrypted_buffer, AES_DATA_LENGTH, NULL);
	clEngineFinalize(encrypt_id);

	// create decryption engine and decrypt data.
	clEngineInstanceId decrypt_id;
	clAESDecryptCreate(&decrypt_id, clAES(aes_engine), CL_BLOCK_CIPHER_MODE_ECB, (const void*)aes_key, AES_KEY_LENGTH, (const void*)aes_iv, AES_BLOCK_LENGTH);
	clEngineProcess(decrypt_id, (const void*)aes_encrypted_buffer, AES_DATA_LENGTH, (void*)aes_decrypted_buffer, AES_DATA_LENGTH, NULL);
	clEngineFinalize(decrypt_id);

	return 0;
}
