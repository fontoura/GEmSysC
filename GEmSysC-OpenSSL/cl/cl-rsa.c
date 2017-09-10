#include <string.h>

#include <cl/cl-rsa.h>

#include <openssl/pem.h>

#define BITS_TO_BYTES(b)            ( b / 8 )
#define CL_RSA_MIN_PADDING_PKCS1v15 ( 8 + 3 )
#define CL_RSA_MIN_PADDING_OAEP     ( 2 * BITS_TO_BYTES( 160 ) + 2 )

#define ID_FROM_RSA(x)  ( ( clEngineInstanceId ) ( void * ) ( x ) )
#define RSA_FROM_ID(x)  ( ( const clRSADef_t * ) ( void * ) ( x ) )
#define RSA_FROM_ALG(x) ( ( const clRSADef_t * ) ( x ) )

static clStatus cl_rsa_initialize(const clRSADef_t * rsa_def, const cl_rsa_engine_def_t* rsa_engine, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

static clStatus cl_rsa_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

static clStatus cl_rsa_public_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out);

static clStatus cl_rsa_private_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out);

static clStatus cl_rsa_public_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out);

static clStatus cl_rsa_private_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out);

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

const cl_rsa_engine_def_t cl_rsa_engine_def_private_encrypt = {
	.process = cl_rsa_private_encrypt,
	.min_input_length = cl_rsa_get_min_decrypted_length,
	.max_input_length = cl_rsa_get_max_decrypted_length,
	.min_output_length = cl_rsa_get_encrypted_length,
	.max_output_length = cl_rsa_get_encrypted_length
};

const cl_rsa_engine_def_t cl_rsa_engine_def_public_decrypt = {
	.process = cl_rsa_public_decrypt,
	.min_input_length = cl_rsa_get_encrypted_length,
	.max_input_length = cl_rsa_get_encrypted_length,
	.min_output_length = cl_rsa_get_min_decrypted_length,
	.max_output_length = cl_rsa_get_max_decrypted_length

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
	clStatus status = cl_rsa_initialize(rsa_def, &cl_rsa_engine_def_private_encrypt, padding_mode, key_encoding, key_format, key, key_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_RSA(rsa_def);
		return CL_ENOERR;
	}
	return status;
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
	clStatus status = cl_rsa_initialize(rsa_def, &cl_rsa_engine_def_public_decrypt, padding_mode, key_encoding, key_format, key, key_len);
	if (status == CL_ENOERR)
	{
		*id = ID_FROM_RSA(rsa_def);
		return CL_ENOERR;
	}
	return status;
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
	clRSAData_t * rsa_data = rsa_def->data;
	RSA * rsa = NULL;

	if (
		(padding_mode != CL_RSA_PADDING_MODE_PKCS1v15 && padding_mode != CL_RSA_PADDING_MODE_OAEP) ||
		(key_encoding != CL_RSA_KEY_ENCODING_DER && key_encoding != CL_RSA_KEY_ENCODING_PEM) ||
		(key_format != CL_RSA_KEY_FORMAT_PKCS1)
	)
	{
		return -CL_EINVAL;
	}

	if (key_encoding == CL_RSA_KEY_ENCODING_DER)
	{
		if (rsa_engine == &cl_rsa_engine_def_public_encrypt || rsa_engine == &cl_rsa_engine_def_public_decrypt)
		{
			// DER-encoded public key.
			const unsigned char * p = (const unsigned char *)key;
			rsa = d2i_RSA_PUBKEY(NULL, &p, key_len);
		}
		else // if (rsa_engine == &cl_rsa_engine_def_private_encrypt || rsa_engine == &cl_rsa_engine_def_private_decrypt)
		{
			// DER-encoded private key.
			const unsigned char * p = (const unsigned char *)key;
			rsa = d2i_RSAPrivateKey(NULL, &p, key_len);
		}
	}
	else // if (key_encoding == CL_RSA_KEY_ENCODING_PEM)
	{
		if (rsa_engine == &cl_rsa_engine_def_public_encrypt || rsa_engine == &cl_rsa_engine_def_public_decrypt)
		{
			// PEM-encoded public key.
			BIO * bio = BIO_new_mem_buf((void*)key, key_len);
			rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
		else // if (rsa_engine == &cl_rsa_engine_def_private_encrypt || rsa_engine == &cl_rsa_engine_def_private_decrypt)
		{
			// PEM-encoded private key.
			BIO * bio = BIO_new_mem_buf((void*)key, key_len);
			rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
	}
	if (rsa == NULL)
	{
		// really should not have got here...
		return -CL_ENOMEM;
	}

	rsa_data->rsa_engine = rsa_engine;
	rsa_data->padding_mode = padding_mode;
	rsa_data->rsa = rsa;
	return CL_ENOERR;
}

static clStatus cl_rsa_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	const clRSADef_t * rsa_def = RSA_FROM_ALG(alg);
	const cl_rsa_engine_def_t * rsa_engine = rsa_def->data->rsa_engine;

	if (rsa_engine == NULL ||
		(int)in_len < rsa_engine->min_input_length(rsa_def) ||
		(int)in_len > rsa_engine->max_input_length(rsa_def))
	{
		return -CL_EINVAL;
	}

	if ((int)out_len < rsa_engine->min_output_length(rsa_def))
	{
		return -CL_ENOMEM;
	}

	clStatus status;
	int max_output_len = rsa_engine->max_output_length(rsa_def);
	if ((int)out_len >= max_output_len)
	{
		status = rsa_engine->process(rsa_def, in, in_len, out);
	}
	else
	{
		void * temp = malloc(max_output_len);
		status = rsa_engine->process(rsa_def, in, in_len, temp);
		if (status >= 0 && (unsigned int)status <= out_len)
		{
			memcpy((void *)out, temp, status);
		}
		else
		{
			status = -CL_ENOMEM;
		}
		free(temp);
	}
	return status;
}

static clStatus cl_rsa_public_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out)
{
	int len;
	if (rsa_def->data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		len = RSA_public_encrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_OAEP_PADDING);
	}
	else
	{
		len = RSA_public_encrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_PADDING);
	}
	if (len >= 0)
	{
		return len;
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_public_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out)
{
	int len;
	if (rsa_def->data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		len = RSA_public_decrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_OAEP_PADDING);
	}
	else
	{
		len = RSA_public_decrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_PADDING);
	}
	if (len >= 0)
	{
		return len;
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_private_encrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out)
{
	int len;
	if (rsa_def->data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		len = RSA_private_encrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_OAEP_PADDING);
	}
	else
	{
		len = RSA_private_encrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_PADDING);
	}
	if (len >= 0)
	{
		return len;
	}
	return -CL_EINVAL;
}

static clStatus cl_rsa_private_decrypt(const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out)
{
	int len;
	if (rsa_def->data->padding_mode == CL_RSA_PADDING_MODE_OAEP)
	{
		len = RSA_private_decrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_OAEP_PADDING);
	}
	else
	{
		len = RSA_private_decrypt(in_len, (const unsigned char *)in, (unsigned char *)out, rsa_def->data->rsa, RSA_PKCS1_PADDING);
	}
	if (len >= 0)
	{
		return len;
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
		return RSA_size(rsa_def->data->rsa) - CL_RSA_MIN_PADDING_OAEP;
	}
	else
	{
		return RSA_size(rsa_def->data->rsa) - CL_RSA_MIN_PADDING_PKCS1v15;
	}
}

static clStatus cl_rsa_get_encrypted_length(const clRSADef_t * rsa_def)
{
	return RSA_size(rsa_def->data->rsa);
}

static clStatus cl_rsa_finalize(void * alg)
{
	const clRSADef_t * rsa_def = RSA_FROM_ALG(alg);
	clRSAData_t * rsa_data = rsa_def->data;

	if (rsa_data->rsa != NULL)
	{
		RSA_free(rsa_data->rsa);
		rsa_data->rsa = NULL;
		rsa_data->rsa_engine = NULL;
	}

	return CL_ENOERR;
}
