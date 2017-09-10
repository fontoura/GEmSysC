#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "test/test-rsa.h"

#include "test/test-compat.h"

long test_rsa_2048_pkcs1v15_encrypt_native(long warm_up_times, long run_times)
{
	const unsigned char * key = (const unsigned char *)rsa_public_key;
	RSA * rsa = d2i_RSA_PUBKEY(NULL, &key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = RSA_public_encrypt(RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->pkcs1v15_decrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = RSA_public_encrypt(RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->pkcs1v15_decrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	RSA_free(rsa);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_pkcs1v15_decrypt_native(long warm_up_times, long run_times)
{
	const unsigned char * key = (const unsigned char *)rsa_private_key;
	RSA * rsa = d2i_RSAPrivateKey(NULL, &key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = RSA_private_decrypt(RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->pkcs1v15_encrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = RSA_private_decrypt(RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->pkcs1v15_encrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	RSA_free(rsa);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_oaep_encrypt_native(long warm_up_times, long run_times)
{
	const unsigned char * key = (const unsigned char *)rsa_public_key;
	RSA * rsa = d2i_RSA_PUBKEY(NULL, &key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = RSA_public_encrypt(RSA_OAEP_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->oaep_decrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_OAEP_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = RSA_public_encrypt(RSA_OAEP_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->oaep_decrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_OAEP_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	RSA_free(rsa);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_oaep_decrypt_native(long warm_up_times, long run_times)
{
	const unsigned char * key = (const unsigned char *)rsa_private_key;
	RSA * rsa = d2i_RSAPrivateKey(NULL, &key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = RSA_private_decrypt(RSA_OAEP_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->oaep_encrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_OAEP_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t++)
	{
		int TEST_LEN = RSA_private_decrypt(RSA_OAEP_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_test->oaep_encrypted_buffer, (unsigned char *)rsa_out_buffer, rsa, RSA_PKCS1_OAEP_PADDING);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	RSA_free(rsa);
	return IMPL_READ_TIMER();
}

unsigned char rsa_in_buffer[RSA_LENGTH];
unsigned char rsa_encrypted_buffer[RSA_LENGTH];
unsigned char rsa_decrypted_buffer[RSA_LENGTH];

int rsa_pkcs1v15_encrypt_then_decrypt_library()
{
	const unsigned char * public_key = (const unsigned char *)rsa_public_key;
	RSA * public_rsa = d2i_RSA_PUBKEY(NULL, &public_key, RSA_PUBLIC_KEY_LENGTH);
	RSA_public_encrypt(RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_in_buffer, (unsigned char *)rsa_encrypted_buffer, public_rsa, RSA_PKCS1_PADDING);
	RSA_free(public_rsa);

	const unsigned char * private_key = (const unsigned char *)rsa_private_key;
	RSA * private_rsa = d2i_RSAPrivateKey(NULL, &private_key, RSA_PRIVATE_KEY_LENGTH);
	RSA_private_decrypt(RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_encrypted_buffer, (unsigned char *)rsa_decrypted_buffer, private_rsa, RSA_PKCS1_PADDING);
	RSA_free(private_rsa);

	return 0;
}

int rsa_oaep_encrypt_then_decrypt_library()
{
	const unsigned char * public_key = (const unsigned char *)rsa_public_key;
	RSA * public_rsa = d2i_RSA_PUBKEY(NULL, &public_key, RSA_PUBLIC_KEY_LENGTH);
	RSA_public_encrypt(RSA_OAEP_DECRYPTED_DATA_LENGTH, (const unsigned char *)rsa_in_buffer, (unsigned char *)rsa_encrypted_buffer, public_rsa, RSA_PKCS1_OAEP_PADDING);
	RSA_free(public_rsa);

	const unsigned char * private_key = (const unsigned char *)rsa_private_key;
	RSA * private_rsa = d2i_RSAPrivateKey(NULL, &private_key, RSA_PRIVATE_KEY_LENGTH);
	RSA_private_decrypt(RSA_OAEP_ENCRYPTED_DATA_LENGTH, (const unsigned char *)rsa_encrypted_buffer, (unsigned char *)rsa_decrypted_buffer, private_rsa, RSA_PKCS1_OAEP_PADDING);
	RSA_free(private_rsa);

	return 0;
}
