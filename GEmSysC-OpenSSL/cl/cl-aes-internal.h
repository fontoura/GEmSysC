#ifndef CL_AES_INTERNAL_H_INCLUDED
#define CL_AES_INTERNAL_H_INCLUDED

#include <cl/cl-aes.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

#define clAESInternalDef(name, keyLength)                                   \
	clAESData_t cl_aes_data__##name;                                        \
	const clAESDef_t cl_aes_def__##name = {                                 \
		&cl_aes_engine_def,                                                 \
		&cl_aes_data__##name,                                               \
		keyLength                                                           \
	}

#define clAESInternalDecl(name)                                             \
	extern const clAESDef_t cl_aes_def__##name;

#define clAESInternal(name)                                                 \
	( &cl_aes_def__##name )

struct cl_aes_data_s;
struct cl_aes_engine_def_s;

typedef struct cl_aes_data_s clAESData_t;
typedef struct cl_aes_engine_def_s cl_aes_engine_def_t;

typedef clStatus (*cl_aes_process_t) (const clAESDef_t * aes_def, const void * in, void * out, uint32_t len);

struct cl_aes_def_s
{
	const cl_engine_def_t * engine;
	clAESData_t * data;
	clAESKeyLength_t key_length;
};

struct cl_aes_data_s
{
	const struct cl_aes_engine_def_s * aes_engine;
	clBlockCipherMode mode;
	EVP_CIPHER_CTX * ctx;
};

struct cl_aes_engine_def_s
{
	cl_aes_process_t process;
};

extern const cl_engine_def_t cl_aes_engine_def;

#ifdef __cplusplus
}
#endif

#endif /* CL_AES_INTERNAL_H_INCLUDED */
