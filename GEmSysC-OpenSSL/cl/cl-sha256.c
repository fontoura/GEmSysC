#include <cl/cl-sha256.h>

#define ID_FROM_SHA256(x)       ( ( clEngineInstanceId ) ( void * ) ( x ) )
#define SHA256_FROM_ALG(x)      ( ( const clSHA256Def_t * ) ( x ) )

#define SHA256_OUTPUT_LENGTH    ( 256 / 8 )

static clStatus cl_sha256_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

static clStatus cl_sha256_finalize(void * alg);

const cl_engine_def_t cl_sha256_engine_def = {
	.vtable = {
		.process = cl_sha256_process,
		.finalize = cl_sha256_finalize
	}
};

clStatus clSHA256Create(clEngineInstanceId * id, const clSHA256Def_t * sha256_def)
{
	clSHA256Data_t * sha256_data = sha256_def->data;

	// create EVP cipher context.
	EVP_MD_CTX * evp_context = EVP_MD_CTX_create();
	if (evp_context == NULL)
	{
		return -CL_EAGAIN;
	}

	// initialize EVP cipher context.
	if (!EVP_DigestInit_ex(evp_context, EVP_sha256(), NULL))
	{
		EVP_MD_CTX_destroy(evp_context);
		return -CL_EAGAIN;
	}

	// if execution got here, all previous operations were completed successfully.
	sha256_data->ctx = evp_context;
	sha256_data->finished = false;
	*id = ID_FROM_SHA256(sha256_def);
	return CL_ENOERR;
}

static clStatus cl_sha256_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	const clSHA256Def_t * sha256_def = SHA256_FROM_ALG(alg);
	clSHA256Data_t * sha256_data = sha256_def->data;
	unsigned int s = out_len;
	if (sha256_data->ctx == NULL || (in == NULL && out == NULL))
	{
		return -CL_EINVAL;
	}
	if (sha256_data->finished)
	{
		if (!EVP_DigestInit_ex(sha256_data->ctx, EVP_sha256(), NULL))
		{
			return -CL_EAGAIN;
		}
		sha256_data->finished = false;
	}
	if (in != NULL)
	{
		if (!EVP_DigestUpdate(sha256_data->ctx, in, in_len))
		{
			return -CL_EINVAL;
		}
	}
	if (out != NULL)
	{
		if (!EVP_DigestFinal_ex(sha256_data->ctx, out, &s))
		{
			return -CL_EINVAL;
		}
		sha256_data->finished = true;
		return (clStatus)s;
	}
	return CL_ENOERR;
}

static clStatus cl_sha256_finalize(void * alg)
{
	const clSHA256Def_t * sha256_def = SHA256_FROM_ALG(alg);
	clSHA256Data_t * sha256_data = sha256_def->data;
	if (sha256_data->ctx != NULL)
	{
		EVP_MD_CTX_destroy(sha256_data->ctx);
		sha256_data->ctx = NULL;
		sha256_data->finished = false;
	}

	return CL_ENOERR;
}
