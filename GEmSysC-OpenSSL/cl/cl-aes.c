#include <cl/cl-aes.h>

#define ID_FROM_AES(x)  ( ( clEngineInstanceId ) ( void * ) ( x ) )
#define AES_FROM_ALG(x) ( ( const clAESDef_t * ) ( x ) )
#define AES_BLOCK_SIZE  ( 128 / 8 )

static clStatus cl_aes_initialize(const clAESDef_t * aes_def, const cl_aes_engine_def_t * engine, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len);

static clStatus cl_aes_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

static clStatus cl_aes_encrypt(const clAESDef_t * aes_def, const void * in, void * out, uint32_t len);

static clStatus cl_aes_decrypt(const clAESDef_t * aes_def, const void * in, void * out, uint32_t len);

static clStatus cl_aes_finalize(void * alg);

const cl_engine_def_t cl_aes_engine_def = {
	.vtable = {
		.process = cl_aes_process,
		.finalize = cl_aes_finalize
	}
};

const cl_aes_engine_def_t cl_aes_engine_def_encrypt = {
	.process = cl_aes_encrypt
};

const cl_aes_engine_def_t cl_aes_engine_def_decrypt = {
	.process = cl_aes_decrypt
};

clStatus clAESEncryptCreate(clEngineInstanceId * id, const clAESDef_t * aes, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len)
{
	clStatus status = cl_aes_initialize(aes, &cl_aes_engine_def_encrypt, mode, key, key_len, iv, iv_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_AES(aes);
		return CL_ENOERR;
	}
	return status;
}

clStatus clAESDecryptCreate(clEngineInstanceId * id, const clAESDef_t * aes, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len)
{
	clStatus status = cl_aes_initialize(aes, &cl_aes_engine_def_decrypt, mode, key, key_len, iv, iv_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_AES(aes);
		return CL_ENOERR;
	}
	return status;
}

static clStatus cl_aes_initialize(const clAESDef_t * aes_def, const cl_aes_engine_def_t * aes_engine, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len)
{
	clAESData_t * aes_data = aes_def->data;

	// check length of key and initialization vector.
	int len = (int)aes_def->key_length;
	if (
		(len != CL_AES_KEYLENGTH_128 && len != CL_AES_KEYLENGTH_192 && len != CL_AES_KEYLENGTH_256) ||
		(key_len != len) ||
		(iv_len != AES_BLOCK_SIZE)
	)
	{
		return -CL_EINVAL;
	}

	// get EVP cipher pointer.
	const EVP_CIPHER * evp_cipher = NULL;
	if (mode == CL_BLOCK_CIPHER_MODE_CBC)
	{
		if (aes_def->key_length == CL_AES_KEYLENGTH_128)
		{
			evp_cipher = EVP_aes_128_cbc();
		}
		else if (aes_def->key_length == CL_AES_KEYLENGTH_192)
		{
			evp_cipher = EVP_aes_192_cbc();
		}
		else if (aes_def->key_length == CL_AES_KEYLENGTH_256)
		{
			evp_cipher = EVP_aes_256_cbc();
		}
	}
	else if (mode == CL_BLOCK_CIPHER_MODE_ECB)
	{
		if (aes_def->key_length == CL_AES_KEYLENGTH_128)
		{
			evp_cipher = EVP_aes_128_ecb();
		}
		else if (aes_def->key_length == CL_AES_KEYLENGTH_192)
		{
			evp_cipher = EVP_aes_192_ecb();
		}
		else if (aes_def->key_length == CL_AES_KEYLENGTH_256)
		{
			evp_cipher = EVP_aes_256_ecb();
		}
	}

	// check whether the EVP cipher is valid.
	if (evp_cipher == NULL)
	{
		// really should not have got here...
		return -CL_ENOMEM;
	}

	// create EVP cipher context.
	EVP_CIPHER_CTX * evp_context = EVP_CIPHER_CTX_new();
	if (evp_context == NULL)
	{
		return -CL_EAGAIN;
	}

	// initialize EVP cipher context.
	if (aes_engine == &cl_aes_engine_def_encrypt)
	{
		if (!EVP_EncryptInit_ex(evp_context, evp_cipher, NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(evp_context);
			return -CL_EAGAIN;
		}
	}
	else
	{
		if (!EVP_DecryptInit_ex(evp_context, evp_cipher, NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(evp_context);
			return -CL_EAGAIN;
		}
	}

	// remove padding from EVP cipher context.
	if (!EVP_CIPHER_CTX_set_padding(evp_context, 0))
	{
		EVP_CIPHER_CTX_free(evp_context);
		return -CL_EINVAL;
	}

	// if execution got here, all previous operations were completed successfully.
	aes_data->aes_engine = aes_engine;
	aes_data->ctx = evp_context;
	aes_data->mode = mode;
	return CL_ENOERR;
}

static clStatus cl_aes_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	const clAESDef_t * aes_def = AES_FROM_ALG(alg);
	const cl_aes_engine_def_t * aes_engine = aes_def->data->aes_engine;

	// check whether engine has been initialized.
	if (aes_engine == NULL)
	{
		return -CL_EINVAL;
	}

	// check length of data block.
	uint32_t len = AES_BLOCK_SIZE * ((in_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE);
	if (len != in_len)
	{
		return -CL_EINVAL;
	}
	if (len > out_len)
	{
		return -CL_ENOMEM;
	}

	// actually process data.
	return aes_engine->process(aes_def, in, out, in_len);
}

static clStatus cl_aes_encrypt(const clAESDef_t * aes_def, const void * in, void * out, uint32_t len)
{
	clAESData_t * aes_data = aes_def->data;

	// encrypt data.
	int step_length = len;
	if (!EVP_EncryptUpdate(aes_data->ctx, (unsigned char*)out, &step_length, (const unsigned char*)in, len))
	{
		return -CL_EINVAL;
	}
	return step_length;
}

static clStatus cl_aes_decrypt(const clAESDef_t * aes_def, const void * in, void * out, uint32_t len)
{
	clAESData_t * aes_data = aes_def->data;

	// decrypt data.
	int step_length = len;
	if (!EVP_DecryptUpdate(aes_data->ctx, (unsigned char*)out, &step_length, (const unsigned char*)in, len))
	{
		return -CL_EINVAL;
	}
	return step_length;
}

static clStatus cl_aes_finalize(void * alg)
{
	const clAESDef_t * aes_def = AES_FROM_ALG(alg);
	clAESData_t * aes_data = aes_def->data;

	if (aes_data->ctx != NULL)
	{
		EVP_CIPHER_CTX_free(aes_data->ctx);
		aes_data->ctx = NULL;
	}
	aes_data->aes_engine = NULL;

	return CL_ENOERR;
}
