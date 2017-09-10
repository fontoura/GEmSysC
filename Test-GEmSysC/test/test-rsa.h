#ifndef TEST_RSA_H
#define TEST_RSA_H

//#define RSA_VERBOSE

#define RSA_LENGTH                          ( 2048 / 8 )

#define RSA_PRIVATE_KEY_LENGTH              ( 1190 )

#define RSA_PUBLIC_KEY_LENGTH               ( 294 )

#define RSA_PKCS1V15_DECRYPTED_DATA_LENGTH  ( RSA_LENGTH - 11 )

#define RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH  ( RSA_LENGTH )

#define RSA_OAEP_DECRYPTED_DATA_LENGTH      ( RSA_LENGTH - 42 )

#define RSA_OAEP_ENCRYPTED_DATA_LENGTH      ( RSA_LENGTH )

typedef struct rsa_test_params
{
	struct rsa_test_params * next;
	unsigned char * pkcs1v15_decrypted_buffer;
	unsigned char * pkcs1v15_encrypted_buffer;
	unsigned char * oaep_decrypted_buffer;
	unsigned char * oaep_encrypted_buffer;
} rsa_test_params_t;

extern unsigned char rsa_private_key[RSA_PRIVATE_KEY_LENGTH];

extern unsigned char rsa_public_key[RSA_PUBLIC_KEY_LENGTH];

extern unsigned char rsa_out_buffer[RSA_LENGTH];

extern rsa_test_params_t * rsa_tests;

long test_rsa_2048_pkcs1v15_encrypt_native(long warm_up_times, long run_times);

long test_rsa_2048_pkcs1v15_encrypt_cl(long warm_up_times, long run_times);

long test_rsa_2048_pkcs1v15_decrypt_native(long warm_up_times, long run_times);

long test_rsa_2048_pkcs1v15_decrypt_cl(long warm_up_times, long run_times);

long test_rsa_2048_oaep_encrypt_native(long warm_up_times, long run_times);

long test_rsa_2048_oaep_encrypt_cl(long warm_up_times, long run_times);

long test_rsa_2048_oaep_decrypt_native(long warm_up_times, long run_times);

long test_rsa_2048_oaep_decrypt_cl(long warm_up_times, long run_times);

#ifdef RSA_VERBOSE

#include "test/test-compat.h"
#define TEST_RSA_PRINTF(...)    IMPL_PRINTF(__VA_ARGS__)

#else

#define TEST_RSA_PRINTF(...)    {}

#endif

#endif
