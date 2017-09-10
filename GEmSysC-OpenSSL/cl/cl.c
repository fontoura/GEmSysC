#include <cl/cl.h>

#define ENGINE_DEF_FROM_ID(x)   ( * ( ( const cl_engine_def_t ** ) ( id ) ) )

const cl_engine_def_t cl_empty_engine_def = {
	.vtable = {
		.process = cl_dummy_process,
		.finalize = cl_dummy_finalize
	}
};

clStatus clEngineProcess(clEngineInstanceId id, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	return ENGINE_DEF_FROM_ID(id)->vtable.process((void *)id, in, in_len, out, out_len, extra);
}

clStatus clEngineFinalize(clEngineInstanceId id)
{
	return ENGINE_DEF_FROM_ID(id)->vtable.finalize((void *)id);
}

clStatus cl_dummy_process(void * alg, const void * in, uint32_t in_len, void * out, uint32_t out_len, void * extra)
{
	return -CL_EINVAL;
}

clStatus cl_dummy_finalize(void * alg)
{
	return CL_ENOERR;
}
