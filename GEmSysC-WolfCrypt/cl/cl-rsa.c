#include <cl/cl-rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define BITS_TO_BYTES(b)            ( b / 8 )
#define CL_RSA_MIN_PADDING_PKCS1v15 ( 8 + 3 )
#define CL_RSA_MIN_PADDING_OAEP     ( 2 * BITS_TO_BYTES( 160 ) + 2 )

#define ID_FROM_RSA(x)  ( ( clEngineInstanceId ) ( void * ) ( x ) )
#define RSA_FROM_ID(x)  ( ( const clRSADef_t * ) ( void * ) ( x ) )
#define RSA_FROM_ALG(x) ( ( const clRSADef_t * ) ( x ) )

static clStatus cl_rsa_initialize(const clRSADef_t * rsa_def, const cl_rsa_engine_def_t * rsa_engine, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

static clStatus cl_rsa_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

static clStatus cl_rsa_public_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out, uint32_t out_len);

static clStatus cl_rsa_private_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out, uint32_t out_len);

static clStatus cl_rsa_get_min_decrypted_length(const clRSADef_t * rsa_def);

static clStatus cl_rsa_get_max_decrypted_length(const clRSADef_t * rsa_def);

static clStatus cl_rsa_get_encrypted_length(const clRSADef_t * rsa_def);

static clStatus cl_rsa_finalize(void * alg);

const cl_engine_def_t cl_rsa_engine_def = {
	.vtable = {
		.process = cl_rsa_process,
		.finalize = cl_rsa_finalize
	}
};

const cl_rsa_engine_def_t cl_rsa_engine_def_public_encrypt = {
	.process = cl_rsa_public_encrypt,
	.min_input_length = cl_rsa_get_min_decrypted_length,
	.max_input_length = cl_rsa_get_max_decrypted_length,
	.min_output_length = cl_rsa_get_encrypted_length,
	.max_output_length = cl_rsa_get_encrypted_length
};

const cl_rsa_engine_def_t cl_rsa_engine_def_private_decrypt = {
	.process = cl_rsa_private_decrypt,
	.min_input_length = cl_rsa_get_encrypted_length,
	.max_input_length = cl_rsa_get_encrypted_length,
	.min_output_length = cl_rsa_get_min_decrypted_length,
	.max_output_length = cl_rsa_get_max_decrypted_length
};

clStatus clRSAPrivateEncryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len)
{
	// private key encryption is not supported by wolfSSL.
	return -CL_ENOSYS;
}

clStatus clRSAPrivateDecryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len)
{
	clStatus status = cl_rsa_initialize(rsa_def, &cl_rsa_engine_def_private_decrypt, padding_mode, key_encoding, key_format, key, key_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_RSA(rsa_def);
		return CL_ENOERR;
	}
	return status;
}

clStatus clRSAPublicEncryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len)
{
	clStatus status = cl_rsa_initialize(rsa_def, &cl_rsa_engine_def_public_encrypt, padding_mode, key_encoding, key_format, key, key_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_RSA(rsa_def);
		return CL_ENOERR;
	}
	return status;
}

clStatus clRSAPublicDecryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len)
{
	// public key decryption is not supported by wolfSSL.
	return -CL_ENOSYS;
}

clStatus clRSAMinInputLength(clEngineInstanceId id)
{
	const clRSADef_t * rsa_def = RSA_FROM_ID(id);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;
	if (rsa_engine != NULL)
	{
		return rsa_engine->min_input_length(rsa_def);
	}
	return -CL_EINVAL;
}

clStatus clRSAMaxInputLength(clEngineInstanceId id)
{
	const clRSADef_t * rsa_def = RSA_FROM_ID(id);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;
	if (rsa_engine != NULL)
	{
		return rsa_engine->max_input_length(rsa_def);
	}
	return -CL_EINVAL;
}

clStatus clRSAMinOutputLength(clEngineInstanceId id)
{
	const clRSADef_t * rsa_def = RSA_FROM_ID(id);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;
	if (rsa_engine != NULL)
	{
		return rsa_engine->min_output_length(rsa_def);
	}
	return -CL_EINVAL;
}

clStatus clRSAMaxOutputLength(clEngineInstanceId id)
{
	const clRSADef_t * rsa_def = RSA_FROM_ID(id);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;
	if (rsa_engine != NULL)
	{
		return rsa_engine->max_output_length(rsa_def);
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_initialize(const clRSADef_t * rsa_def, const cl_rsa_engine_def_t* rsa_engine, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len)
{
	int ret;
	clRSAData_t * rsa_data = rsa_def->data;

	if (
		(padding_mode != CL_RSA_PADDING_MODE_PKCS1v15 && padding_mode != CL_RSA_PADDING_MODE_OAEP) ||
		(key_encoding != CL_RSA_KEY_ENCODING_DER && key_encoding != CL_RSA_KEY_ENCODING_PEM) ||
		(key_format != CL_RSA_KEY_FORMAT_PKCS1)
	)
	{
		return -CL_EINVAL;
	}

	if (key_encoding == CL_RSA_KEY_ENCODING_PEM)
	{
		// PEM encoding is not supported by wolfSSL.
		return -CL_ENOSYS;
	}

	if (rsa_engine == &cl_rsa_engine_def_public_encrypt)
	{
		ret = wc_InitRng(&(rsa_data->rng));
		if (ret != 0)
		{
			return -CL_ENOMEM;
		}
	}

	ret = wc_InitRsaKey(&(rsa_data->key), NULL);
	if (ret != 0)
	{
		if (rsa_engine == &cl_rsa_engine_def_public_encrypt)
		{
			wc_FreeRng(&(rsa_data->rng));
		}
		return -CL_ENOMEM;
	}

	uint32_t index = 0;
	if (rsa_engine == &cl_rsa_engine_def_public_encrypt)
	{
		ret = wc_RsaPublicKeyDecode((const byte*)key, &index, &(rsa_data->key), key_len);
	}
	else
	{
		ret = wc_RsaPrivateKeyDecode((const byte*)key, &index, &(rsa_data->key), key_len);
	}
	if (ret != 0)
	{
		if (rsa_engine == &cl_rsa_engine_def_public_encrypt)
		{
			wc_FreeRng(&(rsa_data->rng));
		}
		wc_FreeRsaKey(&(rsa_data->key));
		return -CL_EINVAL;
	}

	rsa_data->rsa_engine = rsa_engine;
	rsa_data->padding_mode = padding_mode;
	return CL_ENOERR;
}

static clStatus cl_rsa_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	const clRSADef_t * rsa_def = RSA_FROM_ALG(alg);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;
	if (rsa_engine == NULL)
	{
		return -CL_EINVAL;
	}
	return rsa_engine->process(rsa_def, in, in_len, out, out_len);
}

static clStatus cl_rsa_public_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out, uint32_t out_len)
{
	clRSAData_t * rsa_data = rsa_def->data;
	unsigned int block_len = wc_RsaEncryptSize(&(rsa_data->key));

	unsigned int max_len;
	if (rsa_data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		max_len = block_len - CL_RSA_MIN_PADDING_OAEP;
	}
	else
	{
		max_len = block_len - CL_RSA_MIN_PADDING_PKCS1v15;
	}

	if (in_len > max_len)
	{
		return -CL_EINVAL;
	}
	if (out_len < block_len)
	{
		return -CL_ENOMEM;
	}

	int ret;
	if (rsa_data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		ret = wc_RsaPublicEncrypt_ex(
			(const byte *)in, in_len,
			(byte*)out, out_len,
			&(rsa_data->key), &(rsa_data->rng),
			WC_RSA_OAEP_PAD,
			WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	}
	else
	{
		ret = wc_RsaPublicEncrypt_ex(
			(const byte *)in, in_len,
			(byte*)out, out_len,
			&(rsa_data->key), &(rsa_data->rng),
			WC_RSA_PKCSV15_PAD,
			WC_HASH_TYPE_NONE, 0, NULL, 0);
	}

	if (ret >= 0)
	{
		return ret;
	}

	if (ret == RSA_BUFFER_E)
	{
		return -CL_ENOMEM;
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_private_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out, uint32_t out_len)
{
	clRSAData_t * rsa_data = rsa_def->data;
	unsigned int block_len = wc_RsaEncryptSize(&(rsa_data->key));

	if (in_len > block_len)
	{
		return -CL_EINVAL;
	}

	//int ret = wc_RsaPrivateDecrypt((const byte *)in, in_len, (byte*)out, out_len, &(rsa_data->key));
	int ret;
	if (rsa_data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		ret = wc_RsaPrivateDecrypt_ex(
			(const byte *)in, in_len,
			(byte*)out, out_len,
			&(rsa_data->key),
			WC_RSA_OAEP_PAD,
			WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
	}
	else
	{
		ret = wc_RsaPrivateDecrypt_ex(
			(const byte *)in, in_len,
			(byte*)out, out_len,
			&(rsa_data->key),
			WC_RSA_PKCSV15_PAD,
			WC_HASH_TYPE_NONE, 0, NULL, 0);
	}

	if (ret >= 0)
	{
		return ret;
	}

	if (ret == RSA_BUFFER_E || ret == MEMORY_E)
	{
		return -CL_ENOMEM;
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_get_min_decrypted_length(const clRSADef_t * rsa_def)
{
	return 0;
}

static clStatus cl_rsa_get_max_decrypted_length(const clRSADef_t * rsa_def)
{
	if (rsa_def->data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		return wc_RsaEncryptSize(&(rsa_def->data->key)) - CL_RSA_MIN_PADDING_OAEP;
	}
	else
	{
		return wc_RsaEncryptSize(&(rsa_def->data->key)) - CL_RSA_MIN_PADDING_PKCS1v15;
	}
}

static clStatus cl_rsa_get_encrypted_length(const clRSADef_t * rsa_def)
{
	return wc_RsaEncryptSize(&(rsa_def->data->key));
}

static clStatus cl_rsa_finalize(void * alg)
{
	const clRSADef_t * rsa_def = RSA_FROM_ALG(alg);
	clRSAData_t * rsa_data = rsa_def->data;

	if (rsa_data->rsa_engine == &cl_rsa_engine_def_public_encrypt)
	{
		wc_FreeRng(&(rsa_data->rng));
	}
	wc_FreeRsaKey(&(rsa_data->key));
	rsa_data->rsa_engine = NULL;

	return CL_ENOERR;
}
