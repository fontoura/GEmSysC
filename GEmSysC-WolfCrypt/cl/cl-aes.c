#include <cl/cl-aes.h>

#define ID_FROM_AES(x)          ( ( clEngineInstanceId ) ( void * ) ( x ) )
#define AES_FROM_ALG(x)         ( ( const clAESDef_t * ) ( x ) )
#define POINTER_TO_INDEX(v, i)  ( &( ( v )[ i ] ) )
#define AES_BLOCK_SIZE          ( 128 / 8 )

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
	if (key_len != len || iv_len != AES_BLOCK_SIZE)
	{
		return -CL_EINVAL;
	}

	// try to set the key on the Aes structure.
	int ret = 0;
	if (mode == CL_BLOCK_CIPHER_MODE_CBC)
	{
		ret = wc_AesSetKey(&(aes_data->aes), (const byte *)key, (word32)key_len, (const byte *)iv, (aes_engine == &cl_aes_engine_def_encrypt) ? AES_ENCRYPTION : AES_DECRYPTION);
	}
	else if (mode == CL_BLOCK_CIPHER_MODE_ECB)
	{
		ret = wc_AesSetKeyDirect(&(aes_data->aes), (const byte *)key, (word32)key_len, (const byte *)iv, (aes_engine == &cl_aes_engine_def_encrypt) ? AES_ENCRYPTION : AES_DECRYPTION);
	}
	else
	{
		return -CL_EINVAL;
	}

	// check whether the previous operations failed.
	if (ret == 0)
	{
		aes_data->aes_engine = aes_engine;
		aes_data->mode = mode;
		return CL_ENOERR;
	}

	// if execution got here, all previous operations were completed successfully.
	return -CL_EINVAL;
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
	int key_len = (int)aes_def->key_length;
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

	int ret;
	if (aes_data->mode == CL_BLOCK_CIPHER_MODE_CBC)
	{
		ret = wc_AesCbcEncrypt(&(aes_data->aes), (byte *)out, (const byte *)in, (word32)len);
	}
	else if (aes_data->mode == CL_BLOCK_CIPHER_MODE_ECB)
	{
		for (uint32_t i = 0; i < len; i += AES_BLOCK_SIZE)
		{
			wc_AesEncryptDirect(&(aes_data->aes), POINTER_TO_INDEX((byte *)out, i), POINTER_TO_INDEX((const byte *)in, i));
		}
		ret = 0;
	}
	else
	{
		return -CL_EINVAL;
	}
	if (ret == 0)
	{
		return len;
	}
	return -CL_EINVAL;
}

static clStatus cl_aes_decrypt(const clAESDef_t * aes_def, const void * in, void * out, uint32_t len)
{
	clAESData_t * aes_data = aes_def->data;

	int ret;
	if (aes_data->mode == CL_BLOCK_CIPHER_MODE_CBC)
	{
		ret = wc_AesCbcDecrypt(&(aes_data->aes), (byte *)out, (const byte *)in, (word32)len);
	}
	else if (aes_data->mode == CL_BLOCK_CIPHER_MODE_ECB)
	{
		for (uint32_t i = 0; i < len; i += AES_BLOCK_SIZE)
		{
			wc_AesDecryptDirect(&(aes_data->aes), POINTER_TO_INDEX((byte *)out, i), POINTER_TO_INDEX((const byte *)in, i));
		}
		ret = 0;
	}
	else
	{
		return -CL_EINVAL;
	}
	if (ret == 0)
	{
		return len;
	}
	return -CL_EINVAL;
}

static clStatus cl_aes_finalize(void * alg)
{
	const clAESDef_t * aes_def = AES_FROM_ALG(alg);
	aes_def->data->aes_engine = NULL;
	return CL_ENOERR;
}
