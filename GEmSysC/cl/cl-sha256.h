/**
 * @file
 * @brief Header file of the SHA-256 module of GEmSysC API.
 * @desc This header file declares all constructs of the SHA-256 module of GEmSysC API.
 */

#ifndef CL_SHA256_H_INCLUDED
#define CL_SHA256_H_INCLUDED

#include <cl/cl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define clSHA256Def(name)                                                   \
	clSHA256InternalDef(name)

#define clSHA256Decl(name)                                                  \
	clSHA256InternalDecl(name)

#define clSHA256(name)                                                      \
	clSHA256Internal(name)

struct cl_sha256_def_s;

typedef struct cl_sha256_def_s clSHA256Def_t;

clStatus clSHA256Create(clEngineInstanceId * id, const clSHA256Def_t * sha256_def);

#ifdef __cplusplus
}
#endif

#include "cl/cl-sha256-internal.h"

#endif /* CL_SHA256_H_INCLUDED */
