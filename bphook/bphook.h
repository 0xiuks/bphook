#ifndef HOOK_UTILS_H
#define HOOK_UTILS_H

#include "bphook_types.h"
#include "bp_image_addr.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool BPInit(void);

bool BPhook(int id, uintptr_t address, void (*callback)(cpu_context_t *));

typedef void (*bp_patch_fn_t)(void);
bool BPpatch(int id, uintptr_t address, bp_patch_fn_t patch_fn,
             uintptr_t resume_addr);

bool BPEnable(int id, bool enable);
bool BPIsActive(int id);
void BPhook_call_original(cpu_context_t *ctx);

#ifdef __cplusplus
}
#endif

// Helper macros
#define GET_ARG(ctx, index)       ((ctx)->x[(index)])
#define SET_ARG(ctx, index, val)  ((ctx)->x[(index)] = (uint64_t)(val))
#define GET_RETVAL(ctx)           ((ctx)->x[0])
#define SET_RETVAL(ctx, val)      ((ctx)->x[0] = (uint64_t)(val))

#define GET_FLOAT_ARG(ctx, index)       (*(float*)&((ctx)->q[(index)]))
#define SET_FLOAT_ARG(ctx, index, val)  (*(float*)&((ctx)->q[(index)]) = (float)(val))
#define GET_DOUBLE_ARG(ctx, index)      (*(double*)&((ctx)->q[(index)]))
#define SET_DOUBLE_ARG(ctx, index, val) (*(double*)&((ctx)->q[(index)]) = (double)(val))

#define BP_PATCH_END() __asm__ volatile("b _patch_exec_resume")

#endif
