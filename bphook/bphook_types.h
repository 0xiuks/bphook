#ifndef BPHOOK_TYPES_H
#define BPHOOK_TYPES_H

#include <stdint.h>

// Layout MUST match trampoline.s
typedef struct __attribute__((aligned(16))) {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t pc;
    uint64_t cpsr;
    uint64_t resume_pc;
    __uint128_t q[32];
} cpu_context_t;

#endif
