#include <wolfssl/wolfcrypt/aes.h>

#include "test/test-aes.h"

#include "test/test-compat.h"

long test_aes_256_ebc_encrypt_native(long warm_up_times, long run_times)
{
	// create encryption engine and encrypt data.
	Aes aes_encrypt_engine;
	wc_AesSetKeyDirect(&aes_encrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_ENCRYPTION);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
		{
			wc_AesEncryptDirect(&aes_encrypt_engine, (byte *)&(aes_buffer[i]), (const byte *)&(aes_test->buffer[i]));
		}
		TEST_AES_PRINTF("%i\r\n", AES_DATA_LENGTH);
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
		{
			wc_AesEncryptDirect(&aes_encrypt_engine, (byte *)&(aes_buffer[i]), (const byte *)&(aes_test->buffer[i]));
		}
		TEST_AES_PRINTF("%i\r\n", AES_DATA_LENGTH);
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	return IMPL_READ_TIMER();
}

long test_aes_256_ebc_decrypt_native(long warm_up_times, long run_times)
{
	// create encryption engine and encrypt data.
	Aes aes_decrypt_engine;
	wc_AesSetKeyDirect(&aes_decrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_DECRYPTION);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
		{
			wc_AesDecryptDirect(&aes_decrypt_engine, (byte *)&(aes_buffer[i]), (const byte *)&(aes_test->buffer[i]));
		}
		TEST_AES_PRINTF("%i\r\n", AES_DATA_LENGTH);
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
		{
			wc_AesDecryptDirect(&aes_decrypt_engine, (byte *)&(aes_buffer[i]), (const byte *)&(aes_test->buffer[i]));
		}
		TEST_AES_PRINTF("%i\r\n", AES_DATA_LENGTH);
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_encrypt_native(long warm_up_times, long run_times)
{
	Aes aes_encrypt_engine;
	wc_AesSetKey(&aes_encrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_ENCRYPTION);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_AesCbcEncrypt(&aes_encrypt_engine, (byte *)aes_buffer, (const byte *)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != 0)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_AesCbcEncrypt(&aes_encrypt_engine, (byte *)aes_buffer, (const byte *)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != 0)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_decrypt_native(long warm_up_times, long run_times)
{
	Aes aes_decrypt_engine;
	wc_AesSetKey(&aes_decrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_DECRYPTION);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_AesCbcDecrypt(&aes_decrypt_engine, (byte *)aes_buffer, (const byte *)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != 0)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_AesCbcDecrypt(&aes_decrypt_engine, (byte *)aes_buffer, (const byte *)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != 0)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	return IMPL_READ_TIMER();
}

unsigned char aes_in_buffer[AES_DATA_LENGTH];
unsigned char aes_encrypted_buffer[AES_DATA_LENGTH];
unsigned char aes_decrypted_buffer[AES_DATA_LENGTH];

int aes_cbc_encrypt_then_decrypt_library(void)
{
	// create encryption engine and encrypt data.
	Aes aes_encrypt_engine;
	wc_AesSetKey(&aes_encrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_ENCRYPTION);
	wc_AesCbcEncrypt(&aes_encrypt_engine, (byte *)aes_encrypted_buffer, (const byte *)aes_in_buffer, AES_DATA_LENGTH);

	// create decryption engine and decrypt data.
	Aes aes_decrypt_engine;
	wc_AesSetKey(&aes_decrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_DECRYPTION);
	wc_AesCbcDecrypt(&aes_decrypt_engine, (byte *)aes_decrypted_buffer, (const byte *)aes_encrypted_buffer, AES_DATA_LENGTH);

	return 0;
}

int aes_ecb_encrypt_then_decrypt_library(void)
{
	// create encryption engine and encrypt data.
	Aes aes_encrypt_engine;
	wc_AesSetKeyDirect(&aes_encrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_ENCRYPTION);
	for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
	{
		wc_AesEncryptDirect(&aes_encrypt_engine, (byte *)&(aes_encrypted_buffer[i]), (const byte *)&(aes_in_buffer[i]));
	}

	// create decryption engine and decrypt data.
	Aes aes_decrypt_engine;
	wc_AesSetKeyDirect(&aes_decrypt_engine, (const byte *)aes_key, AES_KEY_LENGTH, (const byte *)aes_iv, AES_DECRYPTION);
	for (int i = 0; i < AES_DATA_LENGTH; i += AES_BLOCK_LENGTH)
	{
		wc_AesEncryptDirect(&aes_decrypt_engine, (byte *)&(aes_decrypted_buffer[i]), (const byte *)&(aes_encrypted_buffer[i]));
	}

	return 0;
}
