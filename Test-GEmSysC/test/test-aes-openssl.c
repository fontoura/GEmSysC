#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "test/test-aes.h"

#include "test/test-compat.h"

long test_aes_256_ebc_encrypt_native(long warm_up_times, long run_times)
{
	int encrypt_length;
	EVP_CIPHER_CTX * evp_encrypt_context = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(evp_encrypt_context, EVP_aes_256_ecb(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_encrypt_context, 0);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_EncryptUpdate(evp_encrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_EncryptUpdate(evp_encrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	EVP_CIPHER_CTX_free(evp_encrypt_context);
	return IMPL_READ_TIMER();
}

long test_aes_256_ebc_decrypt_native(long warm_up_times, long run_times)
{
	int encrypt_length;
	EVP_CIPHER_CTX * evp_decrypt_context = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(evp_decrypt_context, EVP_aes_256_ecb(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_decrypt_context, 0);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_DecryptUpdate(evp_decrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_DecryptUpdate(evp_decrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	EVP_CIPHER_CTX_free(evp_decrypt_context);
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_encrypt_native(long warm_up_times, long run_times)
{
	int encrypt_length;
	EVP_CIPHER_CTX * evp_encrypt_context = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(evp_encrypt_context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_encrypt_context, 0);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_EncryptUpdate(evp_encrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_EncryptUpdate(evp_encrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	EVP_CIPHER_CTX_free(evp_encrypt_context);
	return IMPL_READ_TIMER();
}

long test_aes_256_cbc_decrypt_native(long warm_up_times, long run_times)
{
	int encrypt_length;
	EVP_CIPHER_CTX * evp_decrypt_context = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(evp_decrypt_context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_decrypt_context, 0);
	aes_test_params_t * aes_test = aes_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_DecryptUpdate(evp_decrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		encrypt_length = AES_DATA_LENGTH;
		EVP_DecryptUpdate(evp_decrypt_context, aes_buffer, &encrypt_length, (const unsigned char*)aes_test->buffer, AES_DATA_LENGTH);
		TEST_AES_PRINTF("%i\r\n", encrypt_length);
		if (encrypt_length != AES_DATA_LENGTH)
		{
			return -1;
		}
		aes_test = aes_test->next;
	}
	IMPL_END_TIMER();
	EVP_CIPHER_CTX_free(evp_decrypt_context);
	return IMPL_READ_TIMER();
}

unsigned char aes_in_buffer[AES_DATA_LENGTH];
unsigned char aes_encrypted_buffer[AES_DATA_LENGTH];
unsigned char aes_decrypted_buffer[AES_DATA_LENGTH];

int aes_cbc_encrypt_then_decrypt_library(void)
{
	// create encryption engine and encrypt data.
	EVP_CIPHER_CTX * evp_encrypt_context;
	int encrypt_length = AES_DATA_LENGTH;
	evp_encrypt_context = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(evp_encrypt_context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_encrypt_context, 0);
	EVP_EncryptUpdate(evp_encrypt_context, aes_encrypted_buffer, &encrypt_length, (const unsigned char*)aes_in_buffer, AES_DATA_LENGTH);
	EVP_CIPHER_CTX_free(evp_encrypt_context);

	// create decryption engine and decrypt data.
	EVP_CIPHER_CTX * evp_decrypt_context;
	int decrypt_length = AES_DATA_LENGTH;
	evp_decrypt_context = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(evp_decrypt_context, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_decrypt_context, 0);
	EVP_EncryptUpdate(evp_decrypt_context, aes_decrypted_buffer, &decrypt_length, (const unsigned char*)aes_encrypted_buffer, AES_DATA_LENGTH);
	EVP_CIPHER_CTX_free(evp_decrypt_context);

	return 0;
}

int aes_ecb_encrypt_then_decrypt_library(void)
{
	// create encryption engine and encrypt data.
	EVP_CIPHER_CTX * evp_encrypt_context;
	int encrypt_length = AES_DATA_LENGTH;
	evp_encrypt_context = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(evp_encrypt_context, EVP_aes_256_ecb(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_encrypt_context, 0);
	EVP_EncryptUpdate(evp_encrypt_context, aes_encrypted_buffer, &encrypt_length, (const unsigned char*)aes_in_buffer, AES_DATA_LENGTH);
	EVP_CIPHER_CTX_free(evp_encrypt_context);

	// create decryption engine and decrypt data.
	EVP_CIPHER_CTX * evp_decrypt_context;
	int decrypt_length = AES_DATA_LENGTH;
	evp_decrypt_context = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(evp_decrypt_context, EVP_aes_256_ecb(), NULL, aes_key, aes_iv);
	EVP_CIPHER_CTX_set_padding(evp_decrypt_context, 0);
	EVP_EncryptUpdate(evp_decrypt_context, aes_decrypted_buffer, &decrypt_length, (const unsigned char*)aes_encrypted_buffer, AES_DATA_LENGTH);
	EVP_CIPHER_CTX_free(evp_decrypt_context);

	return 0;
}
