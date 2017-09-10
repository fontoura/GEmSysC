#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "test/test-rsa.h"

#include "test/test-compat.h"

long test_rsa_2048_pkcs1v15_encrypt_native(long warm_up_times, long run_times)
{
	RsaKey key;
	RNG rng;
	word32 index = 0;
	wc_InitRng(&rng);
	wc_InitRsaKey(&key, NULL);
	wc_RsaPublicKeyDecode((const byte*)rsa_public_key, &index, &key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_RsaPublicEncrypt_ex((const byte *)rsa_test->pkcs1v15_decrypted_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, &rng, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_RsaPublicEncrypt_ex((const byte *)rsa_test->pkcs1v15_decrypted_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, &rng, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	wc_FreeRng(&rng);
	wc_FreeRsaKey(&key);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_pkcs1v15_decrypt_native(long warm_up_times, long run_times)
{
	RsaKey key;
	word32 index = 0;
	wc_InitRsaKey(&key, NULL);
	wc_RsaPrivateKeyDecode((const byte*)rsa_private_key, &index, &key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_RsaPrivateDecrypt_ex((const byte *)rsa_test->pkcs1v15_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_RsaPrivateDecrypt_ex((const byte *)rsa_test->pkcs1v15_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	wc_FreeRsaKey(&key);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_oaep_encrypt_native(long warm_up_times, long run_times)
{
	RsaKey key;
	RNG rng;
	word32 index = 0;
	wc_InitRng(&rng);
	wc_InitRsaKey(&key, NULL);
	wc_RsaPublicKeyDecode((const byte*)rsa_public_key, &index, &key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_RsaPublicEncrypt_ex((const byte *)rsa_test->oaep_decrypted_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_RsaPublicEncrypt_ex((const byte *)rsa_test->oaep_decrypted_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	wc_FreeRng(&rng);
	wc_FreeRsaKey(&key);
	return IMPL_READ_TIMER();
}


long test_rsa_2048_oaep_decrypt_native(long warm_up_times, long run_times)
{
	RsaKey key;
	word32 index = 0;
	wc_InitRsaKey(&key, NULL);
	wc_RsaPrivateKeyDecode((const byte*)rsa_private_key, &index, &key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t ++)
	{
		int TEST_LEN = wc_RsaPrivateDecrypt_ex((const byte *)rsa_test->oaep_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_START_TIMER();
	for (long t = 0; t < run_times; t ++)
	{
		int TEST_LEN = wc_RsaPrivateDecrypt_ex((const byte *)rsa_test->oaep_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (byte*)rsa_out_buffer, RSA_LENGTH, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	wc_FreeRsaKey(&key);
	return IMPL_READ_TIMER();
}

unsigned char rsa_in_buffer[RSA_LENGTH];
unsigned char rsa_encrypted_buffer[RSA_LENGTH];
unsigned char rsa_decrypted_buffer[RSA_LENGTH];

int rsa_pkcs1v15_encrypt_then_decrypt_library()
{
	RNG rng;
	RsaKey public_key;
	word32 public_index = 0;
	wc_InitRng(&rng);
	wc_InitRsaKey(&public_key, NULL);
	wc_RsaPublicKeyDecode((const byte*)rsa_public_key, &public_index, &public_key, RSA_PUBLIC_KEY_LENGTH);
	wc_RsaPublicEncrypt_ex((const byte *)rsa_in_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (byte*)rsa_encrypted_buffer, RSA_LENGTH, &public_key, &rng, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
	wc_FreeRng(&rng);
	wc_FreeRsaKey(&public_key);

	RsaKey private_key;
	word32 private_index = 0;
	wc_InitRsaKey(&private_key, NULL);
	wc_RsaPrivateKeyDecode((const byte*)rsa_private_key, &private_index, &private_key, RSA_PRIVATE_KEY_LENGTH);
	wc_RsaPrivateDecrypt_ex((const byte *)rsa_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (byte*)rsa_decrypted_buffer, RSA_LENGTH, &private_key, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
	wc_FreeRsaKey(&private_key);

	return 0;
}

int rsa_oaep_encrypt_then_decrypt_library()
{
	RNG rng;
	RsaKey public_key;
	word32 public_index = 0;
	wc_InitRng(&rng);
	wc_InitRsaKey(&public_key, NULL);
	wc_RsaPublicKeyDecode((const byte*)rsa_public_key, &public_index, &public_key, RSA_PUBLIC_KEY_LENGTH);
	wc_RsaPublicEncrypt_ex((const byte *)rsa_in_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (byte*)rsa_encrypted_buffer, RSA_LENGTH, &public_key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	wc_FreeRng(&rng);
	wc_FreeRsaKey(&public_key);

	RsaKey private_key;
	word32 private_index = 0;
	wc_InitRsaKey(&private_key, NULL);
	wc_RsaPrivateKeyDecode((const byte*)rsa_private_key, &private_index, &private_key, RSA_PRIVATE_KEY_LENGTH);
	wc_RsaPrivateDecrypt_ex((const byte *)rsa_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (byte*)rsa_decrypted_buffer, RSA_LENGTH, &private_key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	wc_FreeRsaKey(&private_key);

	return 0;
}
