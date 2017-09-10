#ifndef CL_RSA_INTERNAL_H_INCLUDED
#define CL_RSA_INTERNAL_H_INCLUDED

#include <cl/cl-rsa.h>

#include <wolfssl/wolfcrypt/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

#define clRSAInternalDef(name, maxKeyBytes)                                 \
	clRSAData_t cl_rsa_data__##name;                                        \
	const clRSADef_t cl_rsa_def__##name = {                                 \
		&cl_rsa_engine_def,                                                 \
		&cl_rsa_data__##name                                                \
	}

#define clRSAInternalDecl(name)                                             \
	extern const clRSADef_t cl_rsa_def__##name;

#define clRSAInternal(name)                                                 \
	( &cl_rsa_def__##name )

struct cl_rsa_data_s;
struct cl_rsa_engine_def_s;

typedef struct cl_rsa_data_s clRSAData_t;
typedef struct cl_rsa_engine_def_s cl_rsa_engine_def_t;

typedef clStatus (*cl_rsa_process_t) (const clRSADef_t * rsa_def, const void * in, uint32_t in_len, void * out, uint32_t out_len);
typedef clStatus (*cl_rsa_get_length_t) (const clRSADef_t * rsa_def);

struct cl_rsa_def_s
{
	const cl_engine_def_t * engine;
	clRSAData_t * data;
};

struct cl_rsa_data_s
{
	const cl_rsa_engine_def_t * rsa_engine;
	clRSAPaddingMode_t padding_mode;
	RsaKey key;
	RNG rng;
};

struct cl_rsa_engine_def_s
{
	cl_rsa_process_t process;
	cl_rsa_get_length_t min_input_length;
	cl_rsa_get_length_t max_input_length;
	cl_rsa_get_length_t min_output_length;
	cl_rsa_get_length_t max_output_length;
};

extern const cl_engine_def_t cl_rsa_engine_def;

#ifdef __cplusplus
}
#endif

#endif /* CL_RSA_INTERNAL_H_INCLUDED */
