#ifndef CL_SHA256_INTERNAL_H_INCLUDED
#define CL_SHA256_INTERNAL_H_INCLUDED

#include <cl/cl-sha256.h>

#include <wolfssl/wolfcrypt/sha256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define clSHA256InternalDef(name)                                           \
	clSHA256Data_t cl_sha256_data__##name;                                  \
	const clSHA256Def_t cl_sha256_def__##name = {                           \
		&cl_sha256_engine_def,                                              \
		&cl_sha256_data__##name                                             \
	}

#define clSHA256InternalDecl(name)                                          \
	extern const clSHA256Def_t cl_sha256_def__##name;

#define clSHA256Internal(name)                                              \
	( &cl_sha256_def__##name )

struct cl_sha256_data_s;

typedef struct cl_sha256_data_s clSHA256Data_t;

struct cl_sha256_def_s
{
	const cl_engine_def_t * engine;
	clSHA256Data_t * data;
};

struct cl_sha256_data_s
{
	Sha256 sha256;
	unsigned int initialized : 1;
};

extern const cl_engine_def_t cl_sha256_engine_def;

#ifdef __cplusplus
}
#endif

#endif /* CL_SHA256_INTERNAL_H_INCLUDED */
