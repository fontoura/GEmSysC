/**
 * @file
 * @brief Header file of the RSA module of GEmSysC API.
 * @desc This header file declares all constructs of the RSA module of GEmSysC API.
 */

#ifndef CL_RSA_H_INCLUDED
#define CL_RSA_H_INCLUDED

#include <cl/cl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define clRSADef(name, maxKeyBytes)                                         \
	clRSAInternalDef(name, maxKeyBytes)

#define clRSADecl(name)                                                     \
	clRSAInternalDecl(name)

#define clRSA(name)                                                         \
	clRSAInternal(name)

struct cl_rsa_def_s;

typedef struct cl_rsa_def_s clRSADef_t;

typedef enum
{
	CL_RSA_KEY_ENCODING_DER = 0x01,
	CL_RSA_KEY_ENCODING_PEM = 0x02
} clRSAKeyEncoding_t;

typedef enum
{
	CL_RSA_KEY_FORMAT_PKCS1 = 0x01
} clRSAKeyFormat_t;

typedef enum
{
	CL_RSA_PADDING_MODE_PKCS1v15 = 0x01,
	CL_RSA_PADDING_MODE_OAEP = 0x02
} clRSAPaddingMode_t;

clStatus clRSAPrivateEncryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

clStatus clRSAPrivateDecryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

clStatus clRSAPublicEncryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

clStatus clRSAPublicDecryptCreate(clEngineInstanceId * id, const clRSADef_t * rsa_def, clRSAPaddingMode_t padding_mode, clRSAKeyEncoding_t key_encoding, clRSAKeyFormat_t key_format, const void * key, uint32_t key_len);

clStatus clRSAMinInputLength(clEngineInstanceId id);

clStatus clRSAMaxInputLength(clEngineInstanceId id);

clStatus clRSAMinOutputLength(clEngineInstanceId id);

clStatus clRSAMaxOutputLength(clEngineInstanceId id);

#ifdef __cplusplus
}
#endif

#include "cl/cl-rsa-internal.h"

#endif /* CL_RSA_H_INCLUDED */
