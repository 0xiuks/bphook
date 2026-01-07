#include "bphook_types.h"
#include "fishhook.h"
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <mach/mach_port.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <mach/arm/thread_status.h>
#include <ptrauth.h>

#define MAX_HWBP_SLOTS    6
#define MAX_HOOK_REGISTRY 1024
#define BCR_ENABLE        0x1e5
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#if defined(__arm64e__) && defined(__has_feature)
#  if __has_feature(ptrauth_calls)
#    define BP_HAVE_PTRAUTH 1
#  else
#    define BP_HAVE_PTRAUTH 0
#  endif
#else
#  define BP_HAVE_PTRAUTH 0
#endif

typedef void (*hook_callback_t)(cpu_context_t *ctx);
typedef void (*patch_fn_t)(void);

typedef enum {
    MODE_HOOK = 0,
    MODE_PATCH = 1
} hook_mode_t;

typedef struct {
    int id;
    uintptr_t target_addr;
    hook_callback_t callback;
    hook_mode_t mode;
    uintptr_t resume_addr;
    patch_fn_t patch_fn;
    bool registered;
} HookRegistration;

typedef struct {
    uintptr_t target_addr;
    hook_callback_t callback;
    hook_mode_t mode;
    uintptr_t resume_addr;
    patch_fn_t patch_fn;
    atomic_bool active;
    int bound_id;
} HardwareEntry;

static HookRegistration g_hook_registry[MAX_HOOK_REGISTRY];
static HardwareEntry g_hw_slots[MAX_HWBP_SLOTS];

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool g_init_ok = ATOMIC_VAR_INIT(false);
static atomic_bool g_exception_guard_installed = ATOMIC_VAR_INIT(false);
static mach_port_t g_server_port = MACH_PORT_NULL;

static __thread uint32_t g_tls_disabled_mask = 0;

extern void hwbp_trampoline_entry(void);
extern void patch_exec(cpu_context_t *ctx, patch_fn_t patch_fn);

extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

// Public API
bool BPInit(void);
bool BPhook(int id, uintptr_t address, hook_callback_t callback);
bool BPpatch(int id, uintptr_t address, patch_fn_t patch_fn, uintptr_t resume_addr);
bool BPEnable(int id, bool enable);
bool BPIsActive(int id);

// Internal helpers
static void *server_loop(void *arg);
static bool apply_debug_state(int skip_slot);
static void apply_debug_state_for_thread(mach_port_t thread, uint32_t disabled_mask);
static HookRegistration *find_hook_by_id(int id);
static HookRegistration *find_free_hook_slot(void);
static HardwareEntry *find_hw_slot_by_id(int id);
static int find_free_hw_slot_index(void);
static bool is_initialized(void);
static void install_exception_guard_once(void);
static bool register_hook(int id, uintptr_t target_addr,
                          hook_callback_t callback,
                          hook_mode_t mode,
                          patch_fn_t patch_fn,
                          uintptr_t resume_addr);

static kern_return_t (*orig_task_set_exception_ports)(
    task_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) = NULL;
static kern_return_t (*orig_thread_set_exception_ports)(
    thread_act_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) = NULL;

static kern_return_t bphook_task_set_exception_ports(task_t task,
                                                     exception_mask_t exception_mask,
                                                     mach_port_t new_port,
                                                     exception_behavior_t behavior,
                                                     thread_state_flavor_t new_flavor) {
    if (!orig_task_set_exception_ports) {
        return KERN_FAILURE;
    }
    if (g_server_port == MACH_PORT_NULL) {
        return orig_task_set_exception_ports(task, exception_mask, new_port, behavior, new_flavor);
    }
    if ((exception_mask & EXC_MASK_BREAKPOINT) && new_port != g_server_port) {
        exception_mask &= ~EXC_MASK_BREAKPOINT;
        if (exception_mask == 0) {
            return KERN_SUCCESS;
        }
    }
    return orig_task_set_exception_ports(task, exception_mask, new_port, behavior, new_flavor);
}

static kern_return_t bphook_thread_set_exception_ports(thread_act_t thread,
                                                       exception_mask_t exception_mask,
                                                       mach_port_t new_port,
                                                       exception_behavior_t behavior,
                                                       thread_state_flavor_t new_flavor) {
    if (!orig_thread_set_exception_ports) {
        return KERN_FAILURE;
    }
    if (g_server_port == MACH_PORT_NULL) {
        return orig_thread_set_exception_ports(thread, exception_mask, new_port, behavior, new_flavor);
    }
    if ((exception_mask & EXC_MASK_BREAKPOINT) && new_port != g_server_port) {
        exception_mask &= ~EXC_MASK_BREAKPOINT;
        if (exception_mask == 0) {
            return KERN_SUCCESS;
        }
    }
    return orig_thread_set_exception_ports(thread, exception_mask, new_port, behavior, new_flavor);
}

static void install_exception_guard_once(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_exception_guard_installed, &expected, true)) {
        return;
    }
    struct rebinding rebindings[] = {
        {"task_set_exception_ports", (void *)bphook_task_set_exception_ports,
         (void **)&orig_task_set_exception_ports},
        {"thread_set_exception_ports", (void *)bphook_thread_set_exception_ports,
         (void **)&orig_thread_set_exception_ports},
    };
    (void)rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
}

static inline uintptr_t strip_pac(uintptr_t ptr) {
#if BP_HAVE_PTRAUTH
    return (uintptr_t)__builtin_ptrauth_strip((void *)ptr,
                                             ptrauth_key_function_pointer);
#else
    return ptr;
#endif
}

static inline uintptr_t get_thread_pc(const arm_thread_state64_t *state) {
#if BP_HAVE_PTRAUTH
    return (uintptr_t)arm_thread_state64_get_pc(*state);
#else
    return (uintptr_t)state->__pc;
#endif
}

static inline void set_thread_pc(arm_thread_state64_t *state,
                                 void (*pc)(void)) {
#if BP_HAVE_PTRAUTH
    arm_thread_state64_set_pc_fptr(*state, pc);
#else
    state->__pc = (uintptr_t)pc;
#endif
}

static bool is_initialized(void) {
    return atomic_load_explicit(&g_init_ok, memory_order_acquire);
}

static HookRegistration *find_hook_by_id(int id) {
    for (int i = 0; i < MAX_HOOK_REGISTRY; i++) {
        if (g_hook_registry[i].registered && g_hook_registry[i].id == id) {
            return &g_hook_registry[i];
        }
    }
    return NULL;
}

static HookRegistration *find_free_hook_slot(void) {
    for (int i = 0; i < MAX_HOOK_REGISTRY; i++) {
        if (!g_hook_registry[i].registered) {
            return &g_hook_registry[i];
        }
    }
    return NULL;
}

static HardwareEntry *find_hw_slot_by_id(int id) {
    for (int i = 0; i < MAX_HWBP_SLOTS; i++) {
        if (atomic_load_explicit(&g_hw_slots[i].active, memory_order_acquire) &&
            g_hw_slots[i].bound_id == id) {
            return &g_hw_slots[i];
        }
    }
    return NULL;
}

static int find_free_hw_slot_index(void) {
    for (int i = 0; i < MAX_HWBP_SLOTS; i++) {
        if (!atomic_load_explicit(&g_hw_slots[i].active, memory_order_acquire)) {
            return i;
        }
    }
    return -1;
}

static bool register_hook(int id, uintptr_t target_addr,
                          hook_callback_t callback,
                          hook_mode_t mode,
                          patch_fn_t patch_fn,
                          uintptr_t resume_addr) {
    pthread_mutex_lock(&g_mutex);

    HookRegistration *entry = find_hook_by_id(id);
    HookRegistration old_entry;
    bool had_entry = false;
    if (entry) {
        old_entry = *entry;
        had_entry = true;
    } else {
        entry = find_free_hook_slot();
    }

    if (!entry) {
        pthread_mutex_unlock(&g_mutex);
        return false;
    }

    target_addr = strip_pac(target_addr);

    if (mode == MODE_PATCH) {
        if (!patch_fn || resume_addr == 0) {
            pthread_mutex_unlock(&g_mutex);
            return false;
        }
        patch_fn = (patch_fn_t)strip_pac((uintptr_t)patch_fn);
        resume_addr = strip_pac(resume_addr);
        callback = NULL;
    }

    entry->id = id;
    entry->target_addr = target_addr;
    entry->callback = callback;
    entry->mode = mode;
    entry->resume_addr = resume_addr;
    entry->patch_fn = patch_fn;
    entry->registered = true;

    HardwareEntry *hw = find_hw_slot_by_id(id);
    if (hw) {
        int slot = (int)(hw - g_hw_slots);
        HardwareEntry old_hw = *hw;
        bool old_active = atomic_load_explicit(&hw->active, memory_order_acquire);

        if (!apply_debug_state(slot)) {
            (void)apply_debug_state(-1);
            if (had_entry) {
                *entry = old_entry;
            } else {
                memset(entry, 0, sizeof(*entry));
            }
            pthread_mutex_unlock(&g_mutex);
            return false;
        }

        atomic_store_explicit(&hw->active, false, memory_order_release);
        hw->target_addr = entry->target_addr;
        hw->callback = entry->callback;
        hw->mode = entry->mode;
        hw->resume_addr = entry->resume_addr;
        hw->patch_fn = entry->patch_fn;
        hw->bound_id = id;
        atomic_store_explicit(&hw->active, true, memory_order_release);

        if (!apply_debug_state(-1)) {
            atomic_store_explicit(&hw->active, false, memory_order_release);
            hw->target_addr = old_hw.target_addr;
            hw->callback = old_hw.callback;
            hw->mode = old_hw.mode;
            hw->resume_addr = old_hw.resume_addr;
            hw->patch_fn = old_hw.patch_fn;
            hw->bound_id = old_hw.bound_id;
            atomic_store_explicit(&hw->active, old_active, memory_order_release);
            (void)apply_debug_state(-1);
            if (had_entry) {
                *entry = old_entry;
            } else {
                memset(entry, 0, sizeof(*entry));
            }
            pthread_mutex_unlock(&g_mutex);
            return false;
        }
    }

    pthread_mutex_unlock(&g_mutex);
    return true;
}

bool BPInit(void) {
    if (is_initialized()) {
        return true;
    }

    pthread_mutex_lock(&g_init_mutex);
    if (is_initialized()) {
        pthread_mutex_unlock(&g_init_mutex);
        return true;
    }

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr;

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        pthread_mutex_unlock(&g_init_mutex);
        return false;
    }

    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        pthread_mutex_unlock(&g_init_mutex);
        return false;
    }

    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BREAKPOINT,
                                  port,
                                  EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                  ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        pthread_mutex_unlock(&g_init_mutex);
        return false;
    }

    g_server_port = port;

    pthread_t t;
    if (pthread_create(&t, NULL, server_loop, NULL) != 0) {
        g_server_port = MACH_PORT_NULL;
        mach_port_destroy(mach_task_self(), port);
        pthread_mutex_unlock(&g_init_mutex);
        return false;
    }
    pthread_detach(t);
    install_exception_guard_once();

    atomic_store_explicit(&g_init_ok, true, memory_order_release);
    pthread_mutex_unlock(&g_init_mutex);
    return true;
}

bool BPhook(int id, uintptr_t address, hook_callback_t callback) {
    if (!is_initialized()) {
        return false;
    }

    return register_hook(id, address, callback, MODE_HOOK, NULL, 0);
}

bool BPpatch(int id, uintptr_t address,
             patch_fn_t patch_fn, uintptr_t resume_addr) {
    if (!is_initialized()) {
        return false;
    }
    if (!patch_fn || resume_addr == 0) {
        return false;
    }

    return register_hook(id, address, NULL, MODE_PATCH, patch_fn, resume_addr);
}

bool BPEnable(int id, bool enable) {
    if (!is_initialized()) {
        return false;
    }

    pthread_mutex_lock(&g_mutex);

    if (enable) {
        HardwareEntry *existing = find_hw_slot_by_id(id);
        if (existing) {
            pthread_mutex_unlock(&g_mutex);
            return true;
        }

        HookRegistration *entry = find_hook_by_id(id);
        if (!entry) {
            pthread_mutex_unlock(&g_mutex);
            return false;
        }
        if (entry->mode == MODE_PATCH && !entry->patch_fn) {
            pthread_mutex_unlock(&g_mutex);
            return false;
        }

        int slot = find_free_hw_slot_index();
        if (slot < 0) {
            pthread_mutex_unlock(&g_mutex);
            return false;
        }

        g_hw_slots[slot].target_addr = entry->target_addr;
        g_hw_slots[slot].callback = entry->callback;
        g_hw_slots[slot].mode = entry->mode;
        g_hw_slots[slot].resume_addr = entry->resume_addr;
        g_hw_slots[slot].patch_fn = entry->patch_fn;
        g_hw_slots[slot].bound_id = id;
        atomic_store_explicit(&g_hw_slots[slot].active, true, memory_order_release);

        if (!apply_debug_state(-1)) {
            atomic_store_explicit(&g_hw_slots[slot].active, false, memory_order_release);
            (void)apply_debug_state(-1);
            pthread_mutex_unlock(&g_mutex);
            return false;
        }
    } else {
        HardwareEntry *hw = find_hw_slot_by_id(id);
        if (!hw) {
            pthread_mutex_unlock(&g_mutex);
            return false;
        }
        int slot = (int)(hw - g_hw_slots);
        if (!apply_debug_state(slot)) {
            (void)apply_debug_state(-1);
            pthread_mutex_unlock(&g_mutex);
            return false;
        }

        atomic_store_explicit(&hw->active, false, memory_order_release);
    }

    pthread_mutex_unlock(&g_mutex);
    return true;
}

bool BPIsActive(int id) {
    if (!is_initialized()) {
        return false;
    }

    pthread_mutex_lock(&g_mutex);
    bool active = (find_hw_slot_by_id(id) != NULL);
    pthread_mutex_unlock(&g_mutex);
    return active;
}

static void *server_loop(void *arg) {
    (void)arg;

    while (1) {
        union {
            mach_msg_header_t hdr;
            uint8_t           buf[4096];
        } in, out;

        kern_return_t kr = mach_msg(&in.hdr,
                                    MACH_RCV_MSG | MACH_RCV_LARGE,
                                    0,
                                    sizeof(in),
                                    g_server_port,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            continue;
        }

        mach_exc_server(&in.hdr, &out.hdr);

        if (out.hdr.msgh_bits != 0 && out.hdr.msgh_remote_port != MACH_PORT_NULL) {
            mach_msg(&out.hdr,
                     MACH_SEND_MSG,
                     out.hdr.msgh_size,
                     0,
                     MACH_PORT_NULL,
                     MACH_MSG_TIMEOUT_NONE,
                     MACH_PORT_NULL);
        }
    }

    return NULL;
}

static bool apply_debug_state(int skip_slot) {
    arm_debug_state64_t dbg;
    memset(&dbg, 0, sizeof(dbg));

    for (int i = 0; i < MAX_HWBP_SLOTS; i++) {
        if (atomic_load_explicit(&g_hw_slots[i].active, memory_order_acquire)) {
            if (i == skip_slot) {
                continue;
            }
            dbg.__bvr[i] = g_hw_slots[i].target_addr;
            dbg.__bcr[i] = BCR_ENABLE;
        }
    }

    bool ok = true;
    kern_return_t kr;

    kr = task_set_state(mach_task_self(),
                        ARM_DEBUG_STATE64,
                        (thread_state_t)&dbg,
                        ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        ok = false;
    }

    thread_t self = mach_thread_self();
    kr = thread_set_state(self,
                          ARM_DEBUG_STATE64,
                          (thread_state_t)&dbg,
                          ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), self);
    if (kr != KERN_SUCCESS) {
        ok = false;
    }

    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(mach_task_self(), &threads, &thread_count) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
            kern_return_t tkr = thread_set_state(threads[i],
                                                 ARM_DEBUG_STATE64,
                                                 (thread_state_t)&dbg,
                                                 ARM_DEBUG_STATE64_COUNT);
            if (tkr != KERN_SUCCESS) {
                ok = false;
            }
            mach_port_deallocate(mach_task_self(), threads[i]);
        }
        vm_deallocate(mach_task_self(),
                      (vm_address_t)threads,
                      thread_count * sizeof(thread_t));
    } else {
        ok = false;
    }

    return ok;
}

static void apply_debug_state_for_thread(mach_port_t thread, uint32_t disabled_mask) {
    arm_debug_state64_t dbg;
    memset(&dbg, 0, sizeof(dbg));

    for (int i = 0; i < MAX_HWBP_SLOTS; i++) {
        if (!atomic_load_explicit(&g_hw_slots[i].active, memory_order_acquire)) {
            continue;
        }
        if (disabled_mask & (1u << i)) {
            continue;
        }
        dbg.__bvr[i] = g_hw_slots[i].target_addr;
        dbg.__bcr[i] = BCR_ENABLE;
    }

    (void)thread_set_state(thread,
                           ARM_DEBUG_STATE64,
                           (thread_state_t)&dbg,
                           ARM_DEBUG_STATE64_COUNT);
}

void c_suspend_all_hooks(uint64_t slot_idx) {
    if (!is_initialized()) {
        return;
    }

    if (slot_idx >= (uint64_t)MAX_HWBP_SLOTS) {
        return;
    }

    uint32_t bit = (uint32_t)1u << (uint32_t)slot_idx;
    uint32_t old_mask = g_tls_disabled_mask;
    g_tls_disabled_mask |= bit;

    if (old_mask == g_tls_disabled_mask) {
        return;
    }

    thread_t t = mach_thread_self();
    apply_debug_state_for_thread(t, g_tls_disabled_mask);
    mach_port_deallocate(mach_task_self(), t);
}

void c_resume_all_hooks(uint64_t slot_idx) {
    if (!is_initialized()) {
        return;
    }

    if (slot_idx >= (uint64_t)MAX_HWBP_SLOTS) {
        return;
    }

    uint32_t bit = (uint32_t)1u << (uint32_t)slot_idx;
    uint32_t old_mask = g_tls_disabled_mask;
    g_tls_disabled_mask &= ~bit;

    if (old_mask == g_tls_disabled_mask) {
        return;
    }

    thread_t t = mach_thread_self();
    apply_debug_state_for_thread(t, g_tls_disabled_mask);
    mach_port_deallocate(mach_task_self(), t);
}

// Mach exception handler. External breakpoints are not handled.
kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt
) {
    (void)exception_port;
    (void)task;
    (void)codeCnt;

    if (!is_initialized()) {
        return KERN_FAILURE;
    }
    if (UNLIKELY(exception != EXC_BREAKPOINT)) {
        return KERN_FAILURE;
    }
    if (*flavor != ARM_THREAD_STATE64 || old_stateCnt != ARM_THREAD_STATE64_COUNT) {
        return KERN_INVALID_ARGUMENT;
    }

    arm_thread_state64_t *ctx = (arm_thread_state64_t *)new_state;
    *ctx = *(arm_thread_state64_t *)old_state;
    *new_stateCnt = old_stateCnt;

    uintptr_t pc = strip_pac(get_thread_pc(ctx));

    for (int i = 0; i < MAX_HWBP_SLOTS; i++) {
        if (atomic_load_explicit(&g_hw_slots[i].active, memory_order_acquire) &&
            strip_pac(g_hw_slots[i].target_addr) == pc) {
            set_thread_pc(ctx, hwbp_trampoline_entry);
            ctx->__x[15] = (uint64_t)i;
            ctx->__x[16] = g_hw_slots[i].target_addr;
            return KERN_SUCCESS;
        }
    }

    // External breakpoints are not handled.
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise(mach_port_t p, mach_port_t t, mach_port_t k,
                                        exception_type_t e, mach_exception_data_t c,
                                        mach_msg_type_number_t cc) {
    (void)p;
    (void)t;
    (void)k;
    (void)e;
    (void)c;
    (void)cc;
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(mach_port_t p, mach_port_t t, mach_port_t k,
                                              exception_type_t e, mach_exception_data_t c,
                                              mach_msg_type_number_t cc,
                                              int *f, thread_state_t o,
                                              mach_msg_type_number_t oc,
                                              thread_state_t n,
                                              mach_msg_type_number_t *nc) {
    (void)p;
    (void)t;
    (void)k;
    (void)e;
    (void)c;
    (void)cc;
    (void)f;
    (void)o;
    (void)oc;
    (void)n;
    (void)nc;
    return KERN_FAILURE;
}

void c_hwbp_dispatch(cpu_context_t *ctx) {
    ctx->resume_pc = ctx->lr;
    if (!is_initialized()) {
        return;
    }

    uint64_t idx = ctx->x[15];
    if (idx < MAX_HWBP_SLOTS &&
        atomic_load_explicit(&g_hw_slots[idx].active, memory_order_acquire)) {
        uintptr_t t1 = strip_pac(g_hw_slots[idx].target_addr);
        uintptr_t t2 = strip_pac(ctx->x[16]);

        if (t1 == t2) {
            hook_mode_t mode = g_hw_slots[idx].mode;
            uintptr_t resume_addr = g_hw_slots[idx].resume_addr;
            ctx->x[16] = g_hw_slots[idx].target_addr;
            if (mode == MODE_PATCH) {
                patch_fn_t patch_fn = g_hw_slots[idx].patch_fn;
                if (patch_fn && resume_addr != 0) {
                    patch_exec(ctx, patch_fn);
                    ctx->resume_pc = resume_addr;
                }
            } else {
                if (g_hw_slots[idx].callback) {
                    g_hw_slots[idx].callback(ctx);
                }
                ctx->resume_pc = ctx->lr;
            }
        }
    }
}
