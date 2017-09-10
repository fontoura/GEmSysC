#ifndef TEST_AES_H
#define TEST_AES_H

//#define AES_VERBOSE

#define AES_KEY_LENGTH      ( 256 / 8 )

#define AES_BLOCK_LENGTH    ( 128 / 8 )

#define AES_DATA_LENGTH     ( 1024 )

typedef struct aes_test_params
{
	struct aes_test_params * next;
	unsigned char * buffer;
} aes_test_params_t;

extern unsigned char aes_key[AES_KEY_LENGTH];

extern unsigned char aes_iv[AES_BLOCK_LENGTH];

extern unsigned char aes_buffer[AES_DATA_LENGTH];

extern aes_test_params_t * aes_tests;

long test_aes_256_ebc_encrypt_native(long warm_up_times, long run_times);

long test_aes_256_ebc_encrypt_cl(long warm_up_times, long run_times);

long test_aes_256_ebc_decrypt_native(long warm_up_times, long run_times);

long test_aes_256_ebc_decrypt_cl(long warm_up_times, long run_times);

long test_aes_256_cbc_encrypt_native(long warm_up_times, long run_times);

long test_aes_256_cbc_encrypt_cl(long warm_up_times, long run_times);

long test_aes_256_cbc_decrypt_native(long warm_up_times, long run_times);

long test_aes_256_cbc_decrypt_cl(long warm_up_times, long run_times);

#ifdef AES_VERBOSE

#include "test/test-compat.h"
#define TEST_AES_PRINTF(...)    IMPL_PRINTF(__VA_ARGS__)

#else

#define TEST_AES_PRINTF(...)    {}

#endif

#endif
