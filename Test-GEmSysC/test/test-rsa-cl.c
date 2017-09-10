#include <cl/cl.h>
#include <cl/cl-rsa.h>

#include "test/test-rsa.h"

#include "test/test-compat.h"

clRSADef(rsa_engine, RSA_LENGTH);

long test_rsa_2048_pkcs1v15_encrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId encrypt_id;
	clRSAPublicEncryptCreate(&encrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_PKCS1v15, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_public_key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)rsa_test->pkcs1v15_decrypted_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
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
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)rsa_test->pkcs1v15_decrypted_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(encrypt_id);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_pkcs1v15_decrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId decrypt_id;
	clRSAPrivateDecryptCreate(&decrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_PKCS1v15, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_private_key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)rsa_test->pkcs1v15_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
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
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)rsa_test->pkcs1v15_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_PKCS1V15_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(decrypt_id);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_oaep_encrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId encrypt_id;
	clRSAPublicEncryptCreate(&encrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_OAEP, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_public_key, RSA_PUBLIC_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)rsa_test->oaep_decrypted_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
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
		int TEST_LEN = clEngineProcess(encrypt_id, (const void*)rsa_test->oaep_decrypted_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_ENCRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(encrypt_id);
	return IMPL_READ_TIMER();
}

long test_rsa_2048_oaep_decrypt_cl(long warm_up_times, long run_times)
{
	clEngineInstanceId decrypt_id;
	clRSAPrivateDecryptCreate(&decrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_OAEP, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_private_key, RSA_PRIVATE_KEY_LENGTH);
	rsa_test_params_t * rsa_test = rsa_tests;
	for (long t = 0; t < warm_up_times; t++)
	{
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)rsa_test->oaep_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
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
		int TEST_LEN = clEngineProcess(decrypt_id, (const void*)rsa_test->oaep_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (void*)rsa_out_buffer, RSA_LENGTH, NULL);
		TEST_RSA_PRINTF("%i\r\n", TEST_LEN);
		if (TEST_LEN != RSA_OAEP_DECRYPTED_DATA_LENGTH)
		{
			return -1;
		}
		rsa_test = rsa_test->next;
	}
	IMPL_END_TIMER();
	clEngineFinalize(decrypt_id);
	return IMPL_READ_TIMER();
}

unsigned char rsa_in_buffer[RSA_LENGTH];
unsigned char rsa_encrypted_buffer[RSA_LENGTH];
unsigned char rsa_decrypted_buffer[RSA_LENGTH];

int rsa_pkcs1v15_encrypt_then_decrypt_cl()
{
	clEngineInstanceId encrypt_id;
	clRSAPublicEncryptCreate(&encrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_PKCS1v15, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_public_key, RSA_PUBLIC_KEY_LENGTH);
	clEngineProcess(encrypt_id, (const void*)rsa_in_buffer, RSA_PKCS1V15_DECRYPTED_DATA_LENGTH, (void*)rsa_encrypted_buffer, RSA_LENGTH, NULL);
	clEngineFinalize(encrypt_id);

	clEngineInstanceId decrypt_id;
	clRSAPrivateDecryptCreate(&decrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_PKCS1v15, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_private_key, RSA_PRIVATE_KEY_LENGTH);
	clEngineProcess(decrypt_id, (const void*)rsa_encrypted_buffer, RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH, (void*)rsa_decrypted_buffer, RSA_LENGTH, NULL);
	clEngineFinalize(decrypt_id);

	return 0;
}

int rsa_oaep_encrypt_then_decrypt_cl()
{
	clEngineInstanceId encrypt_id;
	clRSAPublicEncryptCreate(&encrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_OAEP, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_public_key, RSA_PUBLIC_KEY_LENGTH);
	clEngineProcess(encrypt_id, (const void*)rsa_in_buffer, RSA_OAEP_DECRYPTED_DATA_LENGTH, (void*)rsa_encrypted_buffer, RSA_LENGTH, NULL);
	clEngineFinalize(encrypt_id);

	clEngineInstanceId decrypt_id;
	clRSAPrivateDecryptCreate(&decrypt_id, clRSA(rsa_engine), CL_RSA_PADDING_MODE_OAEP, CL_RSA_KEY_ENCODING_DER, CL_RSA_KEY_FORMAT_PKCS1, rsa_private_key, RSA_PRIVATE_KEY_LENGTH);
	clEngineProcess(decrypt_id, (const void*)rsa_encrypted_buffer, RSA_OAEP_ENCRYPTED_DATA_LENGTH, (void*)rsa_decrypted_buffer, RSA_LENGTH, NULL);
	clEngineFinalize(decrypt_id);

	return 0;
}
