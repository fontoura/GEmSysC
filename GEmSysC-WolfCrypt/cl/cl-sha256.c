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
	if (wc_InitSha256(&(sha256_data->sha256)))
	{
		return -CL_EAGAIN;
	}
	sha256_data->initialized = true;
	*id = ID_FROM_SHA256(sha256_def);
	return CL_ENOERR;
}

static clStatus cl_sha256_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	const clSHA256Def_t * sha256_def = SHA256_FROM_ALG(alg);
	clSHA256Data_t * sha256_data = sha256_def->data;
	if (!sha256_data->initialized || (in == NULL && out == NULL))
	{
		return -CL_EINVAL;
	}
	if (in != NULL)
	{
		if (wc_Sha256Update(&(sha256_data->sha256), (const byte *)in, (word32)in_len))
		{
			return -CL_EINVAL;
		}
	}
	if (out != NULL)
	{
		if (out_len < SHA256_OUTPUT_LENGTH)
		{
			return -CL_ENOMEM;
		}
		if (wc_Sha256Final(&(sha256_data->sha256), (byte *)out))
		{
			return -CL_EINVAL;
		}
		return (clStatus)SHA256_OUTPUT_LENGTH;
	}
	return CL_ENOERR;
}

static clStatus cl_sha256_finalize(void * alg)
{
	const clSHA256Def_t * sha256_def = SHA256_FROM_ALG(alg);
	sha256_def->data->initialized = false;
	return CL_ENOERR;
}
