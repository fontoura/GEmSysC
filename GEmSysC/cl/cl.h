/** @file
 * @brief Main header file of GEmSysC API.
 * @desc This header file declares all global constructs of GEmSysC API which do not belong to a specific module.
 */

#ifndef CL_H_INCLUDED
#define CL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CL_ENOERR   ( 0 )
#define CL_EPERM    ( 1 )
#define CL_EAGAIN   ( 11 )
#define CL_ENOMEM   ( 12 )
#define CL_EBUSY    ( 16 )
#define CL_EINVAL   ( 22 )
#define CL_ENOSYS   ( 38 )

typedef int32_t clStatus;

typedef enum
{
	CL_BLOCK_CIPHER_MODE_ECB,
	CL_BLOCK_CIPHER_MODE_CBC
} clBlockCipherMode;

typedef const void * clEngineInstanceId;

clStatus clEngineProcess(clEngineInstanceId id, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

clStatus clEngineFinalize(clEngineInstanceId id);

#ifdef __cplusplus
}
#endif

#include "cl/cl-internal.h"

#endif /* CL_H_INCLUDED */
