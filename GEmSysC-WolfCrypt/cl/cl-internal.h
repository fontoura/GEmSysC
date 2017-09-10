#ifndef CL_INTERNAL_H_INCLUDED
#define CL_INTERNAL_H_INCLUDED

#include <cl/cl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef clStatus (*cl_engine_process) (void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

typedef clStatus (*cl_engine_finalize) (void * alg);

typedef struct
{
	cl_engine_process process;
	cl_engine_finalize finalize;
} cl_engine_vtable_t;

typedef struct
{
	cl_engine_vtable_t vtable;
} cl_engine_def_t;

extern const cl_engine_def_t cl_empty_engine_def;

clStatus cl_dummy_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra);

clStatus cl_dummy_finalize(void * alg);

#ifdef __cplusplus
}
#endif

#endif /* CL_INTERNAL_H_INCLUDED */
