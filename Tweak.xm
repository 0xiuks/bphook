#import "bphook/bphook.h"

enum {
    example1,
    example2,
    example3,
    example4,
    example5,
    example6,
    example7,
};

// example1: return immediately (same effect as entry ret patch)　
static void callback_example1(cpu_context_t *ctx) {
    (void)ctx;
}


// example2: force return value to 100 (skip original)
static void callback_example2(cpu_context_t *ctx) {
    SET_RETVAL(ctx, 100);
}

// example3: sub_100003000(__int64 a1, __int64 a2) change a2, call original, multiply return value by 100
static void callback_example3(cpu_context_t *ctx) {
    uint64_t a2 = GET_ARG(ctx, 1);
    SET_ARG(ctx, 1, a2 + 100);
    BPhook_call_original(ctx);
    uint64_t ret = GET_RETVAL(ctx);
    SET_RETVAL(ctx, ret * 100);
}

// Note on arg indexes:
// - int/ptr args use x0-x7 (GET_ARG index counts only int/ptr args)
// - float/double args use q0-q7 (GET_FLOAT/GET_DOUBLE index counts only fp args)
// Example4: sub_100004000(int64 a1, int64 a2, double a3)
//   a1=GET_ARG(ctx, 0), a2=GET_ARG(ctx, 1), a3=GET_DOUBLE_ARG(ctx, 0)
// 
static void callback_example4(cpu_context_t *ctx) {
    double a0 = GET_DOUBLE_ARG(ctx, 0);
    SET_DOUBLE_ARG(ctx, 0, a0 * 0.5);
    BPhook_call_original(ctx);
}




// Note on arg indexes:
// - int/ptr args use x0-x7 (GET_ARG index counts only int/ptr args)
// - float/double args use q0-q7 (GET_FLOAT/GET_DOUBLE index counts only fp args)
// Example5: sub_100005000(int64 a1, int64 a2, float a3)
//   a1=GET_ARG(ctx, 0), a2=GET_ARG(ctx, 1), a3=GET_FLOAT_ARG(ctx, 0)
//  add 100 to a3, then run original
//
static void callback_example5(cpu_context_t *ctx) {
    float a3 = GET_FLOAT_ARG(ctx, 0);
    SET_FLOAT_ARG(ctx, 0, a3 + 100.0f); 
    BPhook_call_original(ctx);
}


// example6　Patch: fmov s0, #0.375
//start0x100006000　resume0x100006008
__attribute__((naked)) static void callback_example6(void) {
    __asm__ volatile(
        
        "fmov s0, #0.375\n"
       
        
        );
    BP_PATCH_END();
}

// example7: 
//start 0x100007000　　resume0x10000700C
__attribute__((naked)) static void callback_example7(void) {
    __asm__ volatile(
        "mov w9, #1\n"
        "add w9, w9, #2\n"
        "eor w10, w9, w9\n"
        "add w10, w10, #5\n"
        "add w9, w9, w10\n"
        "orr w9, w9, #0x10\n"
    );
    BP_PATCH_END();
}

%ctor {
    BPInit(); //first;

    BPhook(example1, getAbsoluteAddress("imagename", 0x100001000), callback_example1);
    BPhook(example2, getAbsoluteAddress("imagename", 0x100002000), callback_example2);
    BPhook(example3, getAbsoluteAddress("imagename", 0x100003000), callback_example3);
    BPhook(example4, getAbsoluteAddress("imagename", 0x100004000), callback_example4);
    BPhook(example5, getAbsoluteAddress("imagename", 0x100005000), callback_example5);
    BPpatch(example6, getAbsoluteAddress("imagename", 0x100006000),
            callback_example6,
            getAbsoluteAddress("imagename", 0x100006008));
    BPpatch(example7, getAbsoluteAddress("imagename", 0x100007000),
            callback_example7,
            getAbsoluteAddress("imagename", 0x10000700C));
    // You can register as many hooks as you like.
    
    BPEnable(example1, true);
    BPEnable(example2, false);
    BPEnable(example6, true);// Only 6 can be enabled at the same time.
}
