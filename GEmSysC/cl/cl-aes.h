/**
 * @file
 * @brief Header file of the AES module of GEmSysC API.
 * @desc This header file declares all constructs of the AES module of GEmSysC API.
 */

#ifndef CL_AES_H_INCLUDED
#define CL_AES_H_INCLUDED

#include <cl/cl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def clAESDef(name, keyLength)
 * @brief Defines an AES cryptographic engine instance named @c name with key length of @c keyLength.
 * @desc This macro is meant to be used in code files. It translates to one or more actual definitions depending on the underlying implementation.
 */
#define clAESDef(name, keyLength)                                           \
	clAESInternalDef(name, keyLength)

/**
 * @def clAESDecl(name)
 * @brief Declares an AES cryptographic engine instance named @c name.
 * @desc This macro is meant to be used in header files. It actually declares the main structure which defines the AES cryptographic engine instance.
 */
#define clAESDecl(name)                                                     \
	clAESInternalDecl(name)

/**
 * @def clAES(name)
 * @brief References the AES cryptographic engine instance named @c name.
 * @desc This macro is meant to be used in code files.
 */
#define clAES(name)                                                         \
	clAESInternal(name)

struct cl_aes_def_s;

/**
 * @typedef clAESDef_t
 * @brief Main type of an AES cryptographic engine instance.
 * @desc Implementations may use more than one definition to create an instance of the AES cryptographic engine. This is the type used in the main declaration.
 */
typedef struct cl_aes_def_s clAESDef_t;

typedef enum
{
	CL_AES_KEYLENGTH_128 = 16,
	CL_AES_KEYLENGTH_192 = 24,
	CL_AES_KEYLENGTH_256 = 32
} clAESKeyLength_t;

/**
 * @fn clAESEncryptCreate(clEngineInstanceId * id, const clAESDef_t * aes_def, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len);
 * @brief Initializes an AES cryptographic engine instance for encryption.
 * @param aes_def - The engine definition, which should be referenced using @c clAES.
 * @param mode - The block cipher mode. Supported modes depend upon implementation.
 * @returns The engine identifier.
 */
clStatus clAESEncryptCreate(clEngineInstanceId * id, const clAESDef_t * aes_def, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len);

/**
 * @fn clAESDecryptCreate(clEngineInstanceId * id, const clAESDef_t * aes_def, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len);
 * @brief Initializes an AES cryptographic engine instance for decryption.
 * @param aes_def - The engine, which should be referenced using @c clAES.
 * @param mode - The block cipher mode. Supported modes depend upon implementation.
 * @returns The engine identifier.
 */
clStatus clAESDecryptCreate(clEngineInstanceId * id, const clAESDef_t * aes_def, clBlockCipherMode mode, const void * key, uint32_t key_len, const void * iv, uint32_t iv_len);

#ifdef __cplusplus
}
#endif

#include "cl/cl-aes-internal.h"

#endif /* CL_AES_H_INCLUDED */
