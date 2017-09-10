#include "test/test-compat.h"
#include "test/test-aes.h"
#include "test/test-rsa.h"
#include "test/test-sha256.h"

#include "test/test-config.h"

#define DIRECT_TEST

void test_main()
{
	long time;
	while (1)
	{
		IMPL_PRINTF("GEmSysC test code\r\n");
#ifdef DIRECT_TEST
		IMPL_PRINTF(" a) Run all once\r\n");
		IMPL_PRINTF(" b) Run all twice\r\n");
#else
		IMPL_PRINTF(" a) AES 256 ECB encrypt\r\n");
		IMPL_PRINTF(" b) AES 256 ECB decrypt\r\n");
		IMPL_PRINTF(" c) AES 256 CBC encrypt\r\n");
		IMPL_PRINTF(" d) AES 256 CBC decrypt\r\n");
		IMPL_PRINTF(" e) RSA 2048 PKCS #1 v1.5 encrypt\r\n");
		IMPL_PRINTF(" f) RSA 2048 PKCS #1 v1.5 decrypt\r\n");
		IMPL_PRINTF(" g) RSA 2048 OAEP encrypt\r\n");
		IMPL_PRINTF(" h) RSA 2048 OAEP decrypt\r\n");
		IMPL_PRINTF(" i) SHA-256 digest\r\n");
#endif
		int c = IMPL_GETC();
		while (c == ' ' || c == '\t' || c == '\r' || c == '\n')
		{
			c = IMPL_GETC();
		}

#ifdef DIRECT_TEST
		int runs = 0;
		if (c == 'a' || c == 'A')
		{
			runs = 1;
		}
		else if (c == 'b' || c == 'B')
		{
			runs = 2;
		}

		for (int i = 0; i < runs; i ++)
		{
			IMPL_PRINTF("\r\nAES 256 ECB encrypt (run #%i)\r\n", i + 1);

			time = test_aes_256_ebc_encrypt_cl(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, AES_STEPS_2);

			time = test_aes_256_ebc_encrypt_native(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, AES_STEPS_2);


			IMPL_PRINTF("\r\nAES 256 ECB decrypt (run #%i)\r\n", i + 1);

			time = test_aes_256_ebc_decrypt_cl(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, AES_STEPS_2);

			time = test_aes_256_ebc_decrypt_native(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, AES_STEPS_2);


			IMPL_PRINTF("\r\nAES 256 CBC encrypt (run #%i)\r\n", i + 1);

			time = test_aes_256_cbc_encrypt_cl(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, AES_STEPS_2);

			time = test_aes_256_cbc_encrypt_native(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, AES_STEPS_2);


			IMPL_PRINTF("\r\nAES 256 CBC decrypt (run #%i)\r\n", i + 1);

			time = test_aes_256_cbc_decrypt_cl(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, AES_STEPS_2);

			time = test_aes_256_cbc_decrypt_native(AES_STEPS_1, AES_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, AES_STEPS_2);


			IMPL_PRINTF("\r\nAES RSA PKCS #1 v1.5 encrypt (run #%i)\r\n", i + 1);

			time = test_rsa_2048_pkcs1v15_encrypt_cl(RSA_ENCRYPT_STEPS_1, RSA_ENCRYPT_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS_2);

			time = test_rsa_2048_pkcs1v15_encrypt_native(RSA_ENCRYPT_STEPS_1, RSA_ENCRYPT_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS_2);


			IMPL_PRINTF("\r\nAES RSA PKCS #1 v1.5 decrypt (run #%i)\r\n", i + 1);

			time = test_rsa_2048_pkcs1v15_decrypt_cl(RSA_DECRYPT_STEPS_1, RSA_DECRYPT_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS_2);

			time = test_rsa_2048_pkcs1v15_decrypt_native(RSA_DECRYPT_STEPS_1, RSA_DECRYPT_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS_2);


			IMPL_PRINTF("\r\nAES RSA OAEP encrypt (run #%i)\r\n", i + 1);

			time = test_rsa_2048_oaep_encrypt_cl(RSA_ENCRYPT_STEPS_1, RSA_ENCRYPT_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS_2);

			time = test_rsa_2048_oaep_encrypt_native(RSA_ENCRYPT_STEPS_1, RSA_ENCRYPT_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS_2);


			IMPL_PRINTF("\r\nAES RSA OAEP decrypt (run #%i)\r\n", i + 1);

			time = test_rsa_2048_oaep_decrypt_cl(RSA_DECRYPT_STEPS_1, RSA_DECRYPT_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS_2);

			time = test_rsa_2048_oaep_decrypt_native(RSA_DECRYPT_STEPS_1, RSA_DECRYPT_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS_2);


			IMPL_PRINTF("\r\nSHA256 digest (run #%i)\r\n", i + 1);

			time = test_sha256_digest_cl(SHA256_STEPS_1, SHA256_STEPS_2);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to digest %i times\r\n", time, SHA256_STEPS_2);

			time = test_sha256_digest_native(SHA256_STEPS_1, SHA256_STEPS_2);
			IMPL_PRINTF(" - Native took #%ld millis to digest %i times\r\n", time, SHA256_STEPS_2);
		}
#else
		if (c == 'a' || c == 'A')
		{
			IMPL_PRINTF("\r\nAES 256 ECB encrypt\r\n");

			time = test_aes_256_ebc_encrypt_native(AES_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, AES_STEPS);

			time = test_aes_256_ebc_encrypt_cl(AES_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, AES_STEPS);

		}
		else if (c == 'b' || c == 'B')
		{
			IMPL_PRINTF("\r\nAES 256 ECB decrypt\r\n");

			time = test_aes_256_ebc_decrypt_native(AES_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, AES_STEPS);

			time = test_aes_256_ebc_decrypt_cl(AES_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, AES_STEPS);

		}
		else if (c == 'c' || c == 'C')
		{
			IMPL_PRINTF("\r\nAES 256 CBC encrypt\r\n");

			time = test_aes_256_cbc_encrypt_native(AES_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, AES_STEPS);

			time = test_aes_256_cbc_encrypt_cl(AES_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, AES_STEPS);

		}
		else if (c == 'd' || c == 'D')
		{
			IMPL_PRINTF("\r\nAES 256 CBC decrypt\r\n");

			time = test_aes_256_cbc_decrypt_native(AES_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, AES_STEPS);

			time = test_aes_256_cbc_decrypt_cl(AES_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, AES_STEPS);
		}
		else if (c == 'e' || c == 'E')
		{
			IMPL_PRINTF("\r\nAES RSA PKCS #1 v1.5 encrypt\r\n");

			time = test_rsa_2048_pkcs1v15_encrypt_native(RSA_ENCRYPT_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS);

			time = test_rsa_2048_pkcs1v15_encrypt_cl(RSA_ENCRYPT_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS);
		}
		else if (c == 'f' || c == 'F')
		{
			IMPL_PRINTF("\r\nAES RSA PKCS #1 v1.5 decrypt\r\n");

			time = test_rsa_2048_pkcs1v15_decrypt_native(RSA_DECRYPT_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS);

			time = test_rsa_2048_pkcs1v15_decrypt_cl(RSA_DECRYPT_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS);
		}
		else if (c == 'g' || c == 'G')
		{
			IMPL_PRINTF("\r\nAES RSA OAEP encrypt\r\n");

			time = test_rsa_2048_oaep_encrypt_native(RSA_ENCRYPT_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS);

			time = test_rsa_2048_oaep_encrypt_cl(RSA_ENCRYPT_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to encrypt %i times\r\n", time, RSA_ENCRYPT_STEPS);
		}
		else if (c == 'h' || c == 'H')
		{
			IMPL_PRINTF("\r\nAES RSA OAEP decrypt\r\n");

			time = test_rsa_2048_oaep_decrypt_native(RSA_DECRYPT_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS);

			time = test_rsa_2048_oaep_decrypt_cl(RSA_DECRYPT_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to decrypt %i times\r\n", time, RSA_DECRYPT_STEPS);
		}
		else if (c == 'i' || c == 'I')
		{
			IMPL_PRINTF("\r\nSHA256 digest\r\n");

			time = test_sha256_digest_native(SHA256_STEPS);
			IMPL_PRINTF(" - Native took #%ld millis to digest %i times\r\n", time, SHA256_STEPS);

			time = test_sha256_digest_cl(SHA256_STEPS);
			IMPL_PRINTF(" - GEmSysC took #%ld millis to digest %i times\r\n", time, SHA256_STEPS);
		}
#endif
		IMPL_PRINTF("\r\n");
	}
}
