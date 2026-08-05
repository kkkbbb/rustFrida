/*
 * hook_engine_art.c - ART method router: table, thunk generation, router hooks
 *
 * Contains: ART router lookup table management, debug functions,
 * FP instruction helpers, generate_art_router_thunk, resolve_art_trampoline,
 * hook_install_art_router, hook_create_art_router_stub.
 */

#include "hook_engine_internal.h"

/* --- ART router lookup table (inline scan from generated thunk) --- */

ArtRouterEntry g_art_router_table[ART_ROUTER_TABLE_MAX];

/* Debug: last X0 seen in not_found path + miss counter */
volatile uint64_t g_art_router_last_x0 = 0;
volatile uint64_t g_art_router_miss_count = 0;
/* Debug: hit counter for found path */
volatile uint64_t g_art_router_hit_count = 0;
volatile uint64_t g_art_router_last_hit_x0 = 0;
volatile uint64_t g_art_router_quick_hit_count = 0;
volatile uint64_t g_art_router_quick_pass_count = 0;
volatile uint64_t g_art_router_quick_callback_count = 0;
volatile uint64_t g_art_router_quick_skip_count = 0;
volatile uint64_t g_art_router_quick_callee_save_frame_count = 0;
volatile uint64_t g_art_router_quick_callee_save_method = 0;
volatile uint64_t g_art_router_quick_top_quick_frame_offset = 0;
volatile uint64_t g_art_router_quick_test_suspend_count = 0;
volatile uint64_t g_art_router_quick_test_suspend_entrypoint = 0;
volatile uint64_t g_art_router_replacement_hit_count = 0;
volatile uint64_t g_art_router_do_call_table_hit_count = 0;
volatile uint64_t g_art_router_last_do_call_x0 = 0;
volatile uint64_t g_art_router_last_do_call_raw_x0 = 0;
volatile uint64_t g_managed_backup_stub_hit_count = 0;
volatile uint64_t g_managed_direct_hit_count = 0;

/* Managed helper reentrancy guard.  Generated managed helpers enter this
 * guard before executing DSL code; ART routing checks it to bypass nested Java
 * calls made from inside the helper on the same thread. */
static __thread uint32_t g_managed_reentry_guard_depth = 0;
volatile uint32_t g_managed_reentry_guard_enabled = 1;
volatile uint64_t g_managed_reentry_guard_enter = 0;
volatile uint64_t g_managed_reentry_guard_bypass = 0;

#define MANAGED_GUARD_SLOTS 64
typedef struct {
    volatile uint64_t thread;
    volatile uint32_t depth;
    uint32_t padding;
} ManagedGuardSlot;
static ManagedGuardSlot g_managed_guard_slots[MANAGED_GUARD_SLOTS] = {{0}};
static volatile uint64_t g_managed_guard_active = 0;
static uint64_t hook_current_tpidr_el0(void);
static void emit_art_router_inc_counter(Arm64Writer* w, volatile uint64_t* counter);

/* Fast $orig bypass state */
OrigBypassState g_orig_bypass[ORIG_BYPASS_SLOTS] = {{0}};
volatile uint64_t g_orig_bypass_active = 0;
volatile uint64_t g_orig_bypass_hit = 0;
volatile uint64_t g_orig_bypass_set_success = 0;
volatile uint64_t g_orig_bypass_set_fail = 0;

/* ============================================================================
 * ART router table management
 * ============================================================================ */

int hook_art_router_table_add(uint64_t original, uint64_t replacement) {
    hook_log("[art_router] table_add: original=%llx, replacement=%llx",
             (unsigned long long)original, (unsigned long long)replacement);
    /* Find first empty slot (original == 0 is sentinel) */
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            /* Already exists — update replacement */
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 0;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = NULL;
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 0;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = NULL;
            __atomic_store_n(&g_art_router_table[i].original, original, __ATOMIC_RELEASE);
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

int hook_art_router_table_add_managed(uint64_t original, uint64_t replacement,
                                      void* sentinel) {
    return hook_art_router_table_add_managed_mode(original, replacement, sentinel, 4);
}

int hook_art_router_table_add_managed_mode(uint64_t original, uint64_t replacement,
                                           void* sentinel, uint64_t mode) {
    hook_log("[art_router] table_add_managed: original=%llx, replacement=%llx, sentinel=%p, mode=%llx",
             (unsigned long long)original, (unsigned long long)replacement, sentinel,
             (unsigned long long)mode);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = sentinel;
            __atomic_store_n(&g_art_router_table[i].mode, mode, __ATOMIC_RELEASE);
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = mode;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = sentinel;
            __atomic_store_n(&g_art_router_table[i].original, original, __ATOMIC_RELEASE);
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

int hook_art_router_table_add_quick(uint64_t original, uint64_t replacement,
                                    HookCallback callback, void* user_data) {
    return hook_art_router_table_add_quick_mode(original, replacement, callback, user_data, 1);
}

int hook_art_router_table_add_quick_mode(uint64_t original, uint64_t replacement,
                                         HookCallback callback, void* user_data,
                                         uint64_t mode) {
    hook_log("[art_router] table_add_quick: original=%llx, replacement=%llx, callback=%p, mode=%llx",
             (unsigned long long)original, (unsigned long long)replacement,
             (void*)callback, (unsigned long long)mode);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].quick_callback = callback;
            g_art_router_table[i].quick_user_data = user_data;
            __atomic_store_n(&g_art_router_table[i].mode, mode, __ATOMIC_RELEASE);
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = mode;
            g_art_router_table[i].quick_callback = callback;
            g_art_router_table[i].quick_user_data = user_data;
            __atomic_store_n(&g_art_router_table[i].original, original, __ATOMIC_RELEASE);
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

void hook_art_router_table_set_mode(uint64_t original, uint64_t mode) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].mode = mode;
            return;
        }
    }
}

void hook_art_router_table_set_user_data(uint64_t original, void* user_data) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].quick_user_data = user_data;
            return;
        }
    }
}

int hook_art_router_table_remove(uint64_t original) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0)
            break; /* hit sentinel — not found */
        if (g_art_router_table[i].original == original) {
            /* Shift remaining entries down to keep table compact */
            int j = i;
            while (j + 1 < ART_ROUTER_TABLE_MAX && g_art_router_table[j + 1].original != 0) {
                g_art_router_table[j] = g_art_router_table[j + 1];
                j++;
            }
            g_art_router_table[j].original = 0;
            g_art_router_table[j].replacement = 0;
            g_art_router_table[j].mode = 0;
            g_art_router_table[j].quick_callback = NULL;
            g_art_router_table[j].quick_user_data = NULL;
            return 0;
        }
    }
    return -1;
}

void hook_art_router_table_clear(void) {
    memset(g_art_router_table, 0, sizeof(g_art_router_table));
}

/* 反查: 给定 replacement，返回对应的 original（callOriginal bypass 用） */
uint64_t hook_art_router_table_lookup_original(uint64_t replacement) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].replacement == replacement)
            return g_art_router_table[i].original;
    }
    return 0;
}

uint64_t hook_art_router_table_lookup_mode_by_replacement(uint64_t replacement) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].replacement == replacement)
            return g_art_router_table[i].mode;
    }
    return 0;
}

int hook_art_router_record_do_call(uint64_t method) {
    __atomic_store_n(&g_art_router_last_do_call_raw_x0, method, __ATOMIC_RELAXED);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].original == method) {
            __atomic_add_fetch(&g_art_router_do_call_table_hit_count, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&g_art_router_last_do_call_x0, method, __ATOMIC_RELAXED);
            return g_art_router_table[i].mode ? (int)g_art_router_table[i].mode : 2;
        }
    }
    return 0;
}

void hook_art_router_table_dump(void) {
    hook_log("[art_router] table dump (addr=%p):", (void*)g_art_router_table);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router]   [%d] <end> (total %d entries)", i, i);
            return;
        }
        hook_log("[art_router]   [%d] original=%llx -> replacement=%llx mode=%llx",
                 i,
                 (unsigned long long)g_art_router_table[i].original,
                 (unsigned long long)g_art_router_table[i].replacement,
                 (unsigned long long)g_art_router_table[i].mode);
    }
    hook_log("[art_router]   table full (%d entries)", ART_ROUTER_TABLE_MAX);
}

int hook_art_router_debug_scan(uint64_t x0) {
    hook_log("[art_router] debug_scan: searching for x0=%llx", (unsigned long long)x0);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router] debug_scan: NOT FOUND after %d entries", i);
            return 0;
        }
        if (g_art_router_table[i].original == x0) {
            hook_log("[art_router] debug_scan: FOUND at [%d] -> replacement=%llx mode=%llx",
                     i, (unsigned long long)g_art_router_table[i].replacement,
                     (unsigned long long)g_art_router_table[i].mode);
            return 1;
        }
    }
    hook_log("[art_router] debug_scan: NOT FOUND (table full)");
    return 0;
}

void hook_dump_code(void* addr, size_t size) {
    if (!addr || size == 0) return;
    hook_log("[dump_code] %p (%zu bytes):", addr, size);

    const uint8_t* p = (const uint8_t*)addr;
    for (size_t i = 0; i < size; i += 4) {
        if (i + 4 <= size) {
            uint32_t insn = *(const uint32_t*)(p + i);
            hook_log("  +%03zx: %08x", i, insn);
        } else {
            /* Partial last word */
            hook_log("  +%03zx: (partial)", i);
        }
    }
}

void hook_art_router_get_debug(uint64_t* last_x0, uint64_t* miss_count) {
    if (last_x0)    *last_x0    = g_art_router_last_x0;
    if (miss_count) *miss_count = g_art_router_miss_count;
}

void hook_art_router_reset_debug(void) {
    g_art_router_last_x0 = 0;
    g_art_router_miss_count = 0;
    g_art_router_hit_count = 0;
    g_art_router_last_hit_x0 = 0;
    g_art_router_quick_hit_count = 0;
    g_art_router_quick_pass_count = 0;
    g_art_router_quick_callback_count = 0;
    g_art_router_quick_skip_count = 0;
    g_art_router_quick_callee_save_frame_count = 0;
    g_art_router_quick_test_suspend_count = 0;
    g_art_router_replacement_hit_count = 0;
    g_art_router_do_call_table_hit_count = 0;
    g_art_router_last_do_call_x0 = 0;
    __atomic_store_n(&g_managed_backup_stub_hit_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_managed_direct_hit_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_managed_reentry_guard_enter, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_managed_reentry_guard_bypass, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_orig_bypass_hit, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_orig_bypass_set_success, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_orig_bypass_set_fail, 0, __ATOMIC_RELAXED);
    hook_oat_patch_reset_stats();
}

uint64_t* hook_managed_backup_stub_hit_counter_addr(void) {
    return (uint64_t*)&g_managed_backup_stub_hit_count;
}

uint64_t hook_managed_backup_stub_hits(void) {
    return __atomic_load_n(&g_managed_backup_stub_hit_count, __ATOMIC_RELAXED);
}

uint64_t hook_managed_direct_hits(void) {
    return __atomic_load_n(&g_managed_direct_hit_count, __ATOMIC_RELAXED);
}

void hook_set_managed_reentry_guard_enabled(int enabled) {
    __atomic_store_n(&g_managed_reentry_guard_enabled, enabled ? 1u : 0u, __ATOMIC_RELEASE);
}

int hook_managed_reentry_guard_enabled(void) {
    return __atomic_load_n(&g_managed_reentry_guard_enabled, __ATOMIC_ACQUIRE) != 0;
}

void hook_managed_reentry_guard_enter(void) {
    if (__atomic_load_n(&g_managed_reentry_guard_enabled, __ATOMIC_RELAXED) == 0) {
        return;
    }
    if (g_managed_reentry_guard_depth != UINT32_MAX) {
        g_managed_reentry_guard_depth++;
    }
    __atomic_add_fetch(&g_managed_reentry_guard_enter, 1, __ATOMIC_RELAXED);

    uint64_t thread = hook_current_tpidr_el0();
    for (int i = 0; i < MANAGED_GUARD_SLOTS; i++) {
        ManagedGuardSlot* slot = &g_managed_guard_slots[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE) == thread) {
            __atomic_add_fetch(&slot->depth, 1, __ATOMIC_ACQ_REL);
            return;
        }
    }
    for (int i = 0; i < MANAGED_GUARD_SLOTS; i++) {
        ManagedGuardSlot* slot = &g_managed_guard_slots[i];
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&slot->thread, &expected, 1,
                                         0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            __atomic_store_n(&slot->depth, 1, __ATOMIC_RELEASE);
            __atomic_thread_fence(__ATOMIC_RELEASE);
            __atomic_store_n(&slot->thread, thread, __ATOMIC_RELEASE);
            __atomic_add_fetch(&g_managed_guard_active, 1, __ATOMIC_RELEASE);
            return;
        }
    }
}

void hook_managed_reentry_guard_leave(void) {
    if (g_managed_reentry_guard_depth > 0) {
        g_managed_reentry_guard_depth--;
    }

    uint64_t thread = hook_current_tpidr_el0();
    for (int i = 0; i < MANAGED_GUARD_SLOTS; i++) {
        ManagedGuardSlot* slot = &g_managed_guard_slots[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE) != thread) {
            continue;
        }
        uint32_t depth = __atomic_load_n(&slot->depth, __ATOMIC_ACQUIRE);
        if (depth > 1) {
            __atomic_sub_fetch(&slot->depth, 1, __ATOMIC_ACQ_REL);
        } else {
            __atomic_store_n(&slot->depth, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_managed_guard_active, 1, __ATOMIC_RELEASE);
        }
        return;
    }
}

int hook_managed_reentry_guard_active(void) {
    if (__atomic_load_n(&g_managed_reentry_guard_enabled, __ATOMIC_RELAXED) == 0) {
        return 0;
    }
    if (g_managed_reentry_guard_depth == 0) {
        return 0;
    }
    __atomic_add_fetch(&g_managed_reentry_guard_bypass, 1, __ATOMIC_RELAXED);
    return 1;
}

uint32_t hook_managed_reentry_guard_depth(void) {
    return g_managed_reentry_guard_depth;
}

uint64_t hook_managed_reentry_guard_enters(void) {
    return __atomic_load_n(&g_managed_reentry_guard_enter, __ATOMIC_RELAXED);
}

uint64_t hook_managed_reentry_guard_bypass_hits(void) {
    return __atomic_load_n(&g_managed_reentry_guard_bypass, __ATOMIC_RELAXED);
}

uint64_t hook_orig_bypass_hits(void) {
    return __atomic_load_n(&g_orig_bypass_hit, __ATOMIC_RELAXED);
}

uint64_t hook_orig_bypass_set_successes(void) {
    return __atomic_load_n(&g_orig_bypass_set_success, __ATOMIC_RELAXED);
}

uint64_t hook_orig_bypass_set_failures(void) {
    return __atomic_load_n(&g_orig_bypass_set_fail, __ATOMIC_RELAXED);
}

uint64_t hook_orig_bypass_active_count(void) {
    return __atomic_load_n(&g_orig_bypass_active, __ATOMIC_RELAXED);
}

void hook_art_router_get_hit_debug(uint64_t* hit_count, uint64_t* last_hit_x0) {
    if (hit_count)    *hit_count    = g_art_router_hit_count;
    if (last_hit_x0)  *last_hit_x0  = g_art_router_last_hit_x0;
}

void hook_art_router_get_route_stats(uint64_t* quick_hits,
                                     uint64_t* replacement_hits,
                                     uint64_t* do_call_table_hits,
                                     uint64_t* last_do_call_x0,
                                     uint64_t* last_do_call_raw_x0,
                                     uint64_t* quick_pass_hits,
                                     uint64_t* quick_callback_calls,
                                     uint64_t* quick_skip_hits,
                                     uint64_t* quick_callee_save_frames,
                                     uint64_t* quick_callee_save_method,
                                     uint64_t* quick_top_quick_frame_offset,
                                     uint64_t* quick_test_suspend_calls,
                                     uint64_t* quick_test_suspend_entrypoint) {
    if (quick_hits)          *quick_hits          = g_art_router_quick_hit_count;
    if (replacement_hits)    *replacement_hits    = g_art_router_replacement_hit_count;
    if (do_call_table_hits)  *do_call_table_hits  = g_art_router_do_call_table_hit_count;
    if (last_do_call_x0)     *last_do_call_x0     = g_art_router_last_do_call_x0;
    if (last_do_call_raw_x0) *last_do_call_raw_x0 = g_art_router_last_do_call_raw_x0;
    if (quick_pass_hits)     *quick_pass_hits     = g_art_router_quick_pass_count;
    if (quick_callback_calls)*quick_callback_calls= g_art_router_quick_callback_count;
    if (quick_skip_hits)     *quick_skip_hits     = g_art_router_quick_skip_count;
    if (quick_callee_save_frames) *quick_callee_save_frames = g_art_router_quick_callee_save_frame_count;
    if (quick_callee_save_method) *quick_callee_save_method = g_art_router_quick_callee_save_method;
    if (quick_top_quick_frame_offset) *quick_top_quick_frame_offset = g_art_router_quick_top_quick_frame_offset;
    if (quick_test_suspend_calls) *quick_test_suspend_calls = g_art_router_quick_test_suspend_count;
    if (quick_test_suspend_entrypoint) *quick_test_suspend_entrypoint = g_art_router_quick_test_suspend_entrypoint;
}

/* ============================================================================
 * ART router thunk helpers — shared code blocks for generate_art_router_thunk
 * and hook_create_art_router_stub.
 * ============================================================================ */

/* ART-visible router frame. Keep this identical in size to ARM64
 * SaveRefsAndArgs (224 bytes): even if our fake OAT header is missed, ART's
 * native GenericJNI fallback advances by the same frame size instead of reading
 * saved registers as the next ArtMethod.
 *
 * Full callback HookContext lives in TLS; this stack frame is only the managed
 * stack-walk frame plus the raw quick-call registers needed to rebuild context.
 */
#define ROUTER_FRAME_SIZE          224
#define ROUTER_FRAME_PADDING_OFF   8
#define ROUTER_FRAME_FP_OFF        16
#define ROUTER_X1_OFF              80
#define ROUTER_SAVED_X20_OFF       136
#define ROUTER_SAVED_X30_OFF       216
#define ROUTER_FRAME_RETURN_PC_OFF 216

#define ART_SAVE_EVERYTHING_FRAME_SIZE 512
#define ART_SAVE_EVERYTHING_OLD_TOP_OFF 8
#define QUICK_PREORIG_RET_REG 16
#define ART_THREAD_STATE_AND_FLAGS_OFF 0

/* TPIDR_EL0 system register encoding */
#define SYSREG_TPIDR_EL0 0xDE82

static void emit_atomic_inc64(Arm64Writer* w, volatile uint64_t* counter);
static void emit_atomic_dec64(Arm64Writer* w, volatile uint64_t* counter);

/* Fast $orig bypass: checked BEFORE prologue (zero register save overhead).
 * Scans g_orig_bypass slots for matching thread+method, jumps to trampoline.
 * Only clobbers X16/X17 (scratch registers). */
static void emit_art_router_fast_bypass(Arm64Writer* w, uint64_t lbl_normal,
                                        int dec_before_trampoline) {
    /* Fast exit: if no bypass active, skip scan */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_orig_bypass_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_normal);

    /* X16 = current thread ID */
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);

    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        uint64_t lbl_next = arm64_writer_new_label_id(w);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_next);
        /* Thread matches — check method */
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->method);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_next);
        /* Match! One-shot clear the slot and jump to trampoline.
         * Preserve x0-x15 exactly; the original quick entry still needs the
         * original ArtMethod and Java arguments. */
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
        emit_atomic_dec64(w, &g_orig_bypass_active);
        emit_atomic_inc64(w, &g_orig_bypass_hit);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 16); /* trampoline */
        if (dec_before_trampoline) {
            emit_thunk_inflight_dec_regs(w, ARM64_REG_X14, ARM64_REG_X15);
        }
        arm64_writer_put_br_reg(w, ARM64_REG_X16);
        arm64_writer_put_label(w, lbl_next);
    }
}

static void emit_atomic_inc64(Arm64Writer* w, volatile uint64_t* counter) {
    uint64_t lbl_retry = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)counter);
    arm64_writer_put_label(w, lbl_retry);
    /* LDXR X17, [X16] */
    arm64_writer_put_insn(w, 0xC85F7C00 | (ARM64_REG_NUM(ARM64_REG_X16) << 5) | ARM64_REG_NUM(ARM64_REG_X17));
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X17, ARM64_REG_X17, 1);
    /* STXR W15, X17, [X16] */
    arm64_writer_put_insn(w, 0xC8007C00
                             | (ARM64_REG_NUM(ARM64_REG_W15) << 16)
                             | (ARM64_REG_NUM(ARM64_REG_X16) << 5)
                             | ARM64_REG_NUM(ARM64_REG_X17));
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_W15, lbl_retry);
}

static void emit_atomic_dec64(Arm64Writer* w, volatile uint64_t* counter) {
    uint64_t lbl_retry = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)counter);
    arm64_writer_put_label(w, lbl_retry);
    /* LDXR X17, [X16] */
    arm64_writer_put_insn(w, 0xC85F7C00 | (ARM64_REG_NUM(ARM64_REG_X16) << 5) | ARM64_REG_NUM(ARM64_REG_X17));
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_X17, ARM64_REG_X17, 1);
    /* STXR W15, X17, [X16] */
    arm64_writer_put_insn(w, 0xC8007C00
                             | (ARM64_REG_NUM(ARM64_REG_W15) << 16)
                             | (ARM64_REG_NUM(ARM64_REG_X16) << 5)
                             | ARM64_REG_NUM(ARM64_REG_X17));
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_W15, lbl_retry);
}

static void emit_managed_direct_set_bypass_from_reg(Arm64Writer* w, Arm64Reg method_reg,
                                                    uint64_t trampoline_target) {
    uint64_t lbl_done = arm64_writer_new_label_id(w);

    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        uint64_t lbl_next = arm64_writer_new_label_id(w);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&slot->thread);
        /* LDXR X17, [X16] */
        arm64_writer_put_insn(w, 0xC85F7C00 | (ARM64_REG_NUM(ARM64_REG_X16) << 5) | ARM64_REG_NUM(ARM64_REG_X17));
        arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X17, lbl_next);
        arm64_writer_put_mov_reg_imm(w, ARM64_REG_X17, 1);
        /* STXR W15, X17, [X16] */
        arm64_writer_put_insn(w, 0xC8007C00
                                 | (ARM64_REG_NUM(ARM64_REG_W15) << 16)
                                 | (ARM64_REG_NUM(ARM64_REG_X16) << 5)
                                 | ARM64_REG_NUM(ARM64_REG_X17));
        arm64_writer_put_cbnz_reg_label(w, ARM64_REG_W15, lbl_next);
        arm64_writer_put_str_reg_reg_offset(w, method_reg, ARM64_REG_X16, 8);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, trampoline_target);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 16);
        arm64_writer_put_insn(w, 0xD5033BBF); /* DMB ISH */
        arm64_writer_put_mrs_reg(w, ARM64_REG_X17, SYSREG_TPIDR_EL0);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
        emit_atomic_inc64(w, &g_orig_bypass_active);
        emit_atomic_inc64(w, &g_orig_bypass_set_success);
        arm64_writer_put_b_label(w, lbl_done);
        arm64_writer_put_label(w, lbl_next);
    }

    emit_atomic_inc64(w, &g_orig_bypass_set_fail);
    arm64_writer_put_label(w, lbl_done);
}

/* --- Fast $orig bypass slot management (called from Rust) --- */

int orig_bypass_set(uint64_t thread, uint64_t method, uint64_t trampoline) {
    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&slot->thread, &expected, (uint64_t)1,
                                         0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            slot->method = method;
            slot->trampoline = trampoline;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            slot->thread = thread;
            __atomic_add_fetch(&g_orig_bypass_active, 1, __ATOMIC_RELEASE);
            __atomic_add_fetch(&g_orig_bypass_set_success, 1, __ATOMIC_RELAXED);
            return 0;
        }
    }
    __atomic_add_fetch(&g_orig_bypass_set_fail, 1, __ATOMIC_RELAXED);
    return -1;
}

static uint64_t hook_current_tpidr_el0(void) {
    uint64_t tpidr;
    __asm__ __volatile__("mrs %0, tpidr_el0" : "=r"(tpidr));
    return tpidr;
}

int orig_bypass_set_current_thread(uint64_t method, uint64_t trampoline) {
    return orig_bypass_set(hook_current_tpidr_el0(), method, trampoline);
}

uint64_t orig_bypass_consume_current_thread(uint64_t method) {
    uint64_t thread = hook_current_tpidr_el0();
    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        uint64_t slot_thread = __atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE);
        if (slot_thread == thread && __atomic_load_n(&slot->method, __ATOMIC_ACQUIRE) == method) {
            uint64_t trampoline = __atomic_load_n(&slot->trampoline, __ATOMIC_ACQUIRE);
            __atomic_store_n(&slot->method, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&slot->trampoline, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_orig_bypass_active, 1, __ATOMIC_RELEASE);
            __atomic_add_fetch(&g_orig_bypass_hit, 1, __ATOMIC_RELAXED);
            return trampoline;
        }
    }
    return 0;
}

void orig_bypass_clear(uint64_t thread) {
    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_RELAXED) == thread) {
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_orig_bypass_active, 1, __ATOMIC_RELEASE);
            return;
        }
    }
}

/* --- BLR fast $orig: post-callback flag (separate from entry bypass) --- */

FastOrigSlot g_fast_orig_slots[FAST_ORIG_SLOTS] = {{0}};
volatile uint64_t g_fast_orig_active = 0;
volatile uint64_t g_fast_orig_frame_thread = 0;
volatile uint64_t g_fast_orig_frame_sp = 0;

static __thread HookContext g_art_router_tls_ctx;

static HookContext* art_router_prepare_quick_context(void* frame_sp, void* save_frame_sp) {
    uint8_t* sp = (uint8_t*)frame_sp;
    HookContext* ctx = &g_art_router_tls_ctx;
    uint64_t thread = 0;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, x19" : "=r"(thread));
#endif
    ctx->x[0] = *(uint64_t*)(sp + 0);
    for (int i = 1; i <= 7; i++) {
        ctx->x[i] = *(uint64_t*)(sp + ROUTER_X1_OFF + (i - 1) * 8);
    }
    for (int i = 8; i < 31; i++) {
        ctx->x[i] = 0;
    }
    ctx->x[19] = thread;
    for (int i = 20; i <= 29; i++) {
        ctx->x[i] = *(uint64_t*)(sp + ROUTER_SAVED_X20_OFF + (i - 20) * 8);
    }
    ctx->x[30] = *(uint64_t*)(sp + ROUTER_SAVED_X30_OFF);
    ctx->sp = (uint64_t)(sp + ROUTER_FRAME_SIZE);
    ctx->pc = 0;
    ctx->nzcv = 0;
    ctx->trampoline = save_frame_sp;
    for (int i = 0; i < 8; i++) {
        ctx->d[i] = *(uint64_t*)(sp + ROUTER_FRAME_FP_OFF + i * 8);
    }
    ctx->intercept_leave = 0;
    return ctx;
}

static HookContext* art_router_prepare_quick_context_preorig(void* frame_sp,
                                                             uint64_t ret_x0,
                                                             double ret_d0) {
    HookContext* ctx = art_router_prepare_quick_context(frame_sp, NULL);
    uint64_t ret_d0_bits = 0;
    memcpy(&ret_d0_bits, &ret_d0, sizeof(ret_d0_bits));
    ctx->x[16] = ret_x0;
    ctx->d[0] = ret_d0_bits;
    return ctx;
}

int fast_orig_set(uint64_t thread, uint64_t method, uint64_t trampoline) {
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&slot->thread, &expected, (uint64_t)1,
                                         0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            slot->method = method;
            slot->trampoline = trampoline;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            slot->thread = thread;
            __atomic_add_fetch(&g_fast_orig_active, 1, __ATOMIC_RELEASE);
            return 0;
        }
    }
    return -1;
}

void fast_orig_clear(uint64_t thread) {
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_RELAXED) == thread) {
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_fast_orig_active, 1, __ATOMIC_RELEASE);
            return;
        }
    }
}

uint64_t fast_orig_current_frame(uint64_t thread) {
    if (__atomic_load_n(&g_fast_orig_frame_thread, __ATOMIC_ACQUIRE) == thread) {
        return __atomic_load_n(&g_fast_orig_frame_sp, __ATOMIC_ACQUIRE);
    }
    return 0;
}

static void emit_set_fast_orig_frame(Arm64Writer* w) {
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_sp);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_SP, ARM64_REG_X17, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_thread);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);
}

static void emit_clear_fast_orig_frame(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_thread);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_sp);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
}

static void emit_art_router_prologue(Arm64Writer* w) {
    /* thunk-level 计数废弃, 见 hook_engine_inline.c emit_save_hook_context 注释.
     * 计数改为只在 Rust java_hook_callback 进出点 inc/dec. */
    /* 分配整个帧 */
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);

    /* Match ART ARM64 SaveRefsAndArgs exactly:
     *   +16..+72  d0-d7
     *   +80..+128 x1-x7
     *   +136..+216 x20-x29, lr
     */
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_X20, ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    /* WalkStack 根治: 在 frame 尾部 (SP + frame_size - 8) 也存一份 caller LR.
     * 这是伪 OatQuickMethodHeader 的 GetReturnPcOffset(). ART StackVisitor::WalkStack
     * advance 到下一帧时, next_pc = *(SP + frame_size - 8). 如不写, GC 在此位置读到
     * 未初始化字节 → 把垃圾 PC 交给下一帧的 GetOatQuickMethodHeader → wild branch SEGV. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_LR, ARM64_REG_SP, ROUTER_FRAME_RETURN_PC_OFF);
    /* Load table pointer for scan */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)g_art_router_table);
}

static void emit_ldar_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg base) {
    arm64_writer_put_insn(w, 0xC8DFFC00
                             | (ARM64_REG_NUM(base) << 5)
                             | ARM64_REG_NUM(dst));
}

/* Emit inline scan loop: LDR/CBZ/CMP/B.EQ/ADD/B.
 * Returns found and not_found label IDs via out-pointers. */
static void emit_art_router_scan_loop(Arm64Writer* w,
                                       uint64_t* lbl_found_out,
                                       uint64_t* lbl_not_found_out) {
    uint64_t lbl_loop = arm64_writer_new_label_id(w);
    uint64_t lbl_found = arm64_writer_new_label_id(w);
    uint64_t lbl_not_found = arm64_writer_new_label_id(w);

    arm64_writer_put_label(w, lbl_loop);
    emit_ldar_reg_reg(w, ARM64_REG_X17, ARM64_REG_X16);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_not_found);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_found);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, sizeof(ArtRouterEntry));
    arm64_writer_put_b_label(w, lbl_loop);

    *lbl_found_out = lbl_found;
    *lbl_not_found_out = lbl_not_found;
}

/* Lightweight guard used for high-frequency shared nterp entrypoints.
 * Misses must not build an ART-visible router frame: nterp/shared internal
 * entries are reached by many unrelated methods, and adding a synthetic frame
 * to every miss can perturb stack walking and signal handling. */
static void emit_art_router_pre_scan_guard(Arm64Writer* w, uint64_t fallback_target,
                                           uint32_t quickcode_offset) {
    uint64_t lbl_loop = arm64_writer_new_label_id(w);
    uint64_t lbl_found = arm64_writer_new_label_id(w);
    uint64_t lbl_next = arm64_writer_new_label_id(w);
    uint64_t lbl_fallback = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_uses_orig = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_no_orig = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_common = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_tail = arm64_writer_new_label_id(w);
    uint64_t lbl_guard_scan_done = arm64_writer_new_label_id(w);

    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)g_art_router_table);
    arm64_writer_put_label(w, lbl_loop);
    emit_ldar_reg_reg(w, ARM64_REG_X17, ARM64_REG_X16);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_fallback);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_found);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, sizeof(ArtRouterEntry));
    arm64_writer_put_b_label(w, lbl_loop);

    arm64_writer_put_label(w, lbl_fallback);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, fallback_target);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    arm64_writer_put_label(w, lbl_found);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X14, 4);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X14);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_managed_uses_orig);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X14, 5);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X14);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_managed_no_orig);
    arm64_writer_put_b_label(w, lbl_next);

    arm64_writer_put_label(w, lbl_managed_uses_orig);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X9, ARM64_REG_X16);
    arm64_writer_put_b_label(w, lbl_managed_common);

    arm64_writer_put_label(w, lbl_managed_no_orig);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X9, ARM64_REG_X16);

    arm64_writer_put_label(w, lbl_managed_common);
    /* If a generated helper calls the hooked method directly (not via orig()),
     * route to the original while its native guard is active. The explicit
     * orig() bypass is checked before this pre-scan by generate_art_router_thunk. */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_managed_guard_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_guard_scan_done);
    arm64_writer_put_mrs_reg(w, ARM64_REG_X14, SYSREG_TPIDR_EL0);
    for (int i = 0; i < MANAGED_GUARD_SLOTS; i++) {
        ManagedGuardSlot* slot = &g_managed_guard_slots[i];
        uint64_t lbl_guard_next = arm64_writer_new_label_id(w);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X15, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X14, ARM64_REG_X17);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_guard_next);
        arm64_writer_put_b_label(w, lbl_fallback);
        arm64_writer_put_label(w, lbl_guard_next);
    }
    arm64_writer_put_label(w, lbl_guard_scan_done);

    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);
    emit_atomic_inc64(w, &g_managed_direct_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X10, ARM64_REG_X9, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X10, ARM64_REG_X17, 0);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X9, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X14, 4);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X14);
    arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_managed_tail);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X10, ARM64_REG_X9, 0);
    emit_managed_direct_set_bypass_from_reg(w, ARM64_REG_X10, fallback_target);

    arm64_writer_put_label(w, lbl_managed_tail);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X9, 8);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X0, quickcode_offset);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    arm64_writer_put_label(w, lbl_next);
}

/* 对标 Frida: 恢复全部寄存器 (prologue 的逆序，使用固定偏移) */
static void emit_art_router_restore_all(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_X20, ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    /* 释放帧 */
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
    /* thunk-level dec 废弃 (见 prologue 注释) */
}

static void emit_art_router_restore_all_with_return_x0(Arm64Writer* w, Arm64Reg return_reg) {
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_X20, ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
    if (return_reg != ARM64_REG_X0) {
        arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, return_reg);
    }
}

/* Debug: store X0 to g_art_router_last_x0, increment g_art_router_miss_count */
static void emit_art_router_debug_counters(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_last_x0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_miss_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X17, ARM64_REG_X17, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
}

static void emit_art_router_inc_counter(Arm64Writer* w, volatile uint64_t* counter) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)counter);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X0, ARM64_REG_X0, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
}

/* Found path: load replacement ArtMethod from table[i].replacement,
 * overwrite saved X0 with replacement, restore all regs, then jump to
 * replacement.entry_point_ (jni_trampoline).
 *
 * 对标 Frida: declaring_class_ 不在 trampoline 里同步。
 * Frida 的 find_replacement_method_from_quick_code 是纯读操作，
 * declaring_class_ 仅通过 GC 回调 (synchronize_replacement_methods) 批量同步。
 * 在 trampoline 里写 malloc 地址会导致 Scudo 堆损坏（spawn 模式已验证）。 */
/* C-callable stack check function (implemented in Rust art_controller.rs).
 * Returns 1 = normal routing, 0 = skip (callOriginal recursion). */
extern int art_router_stack_check(uint64_t replacement);
extern void* art_quick_callee_save_suspend_method(void);
extern void* art_quick_test_suspend_entrypoint(void);
extern uint64_t art_quick_top_quick_frame_offset(void);

static void emit_restore_args_only(Arm64Writer* w);
static void emit_save_args_only(Arm64Writer* w);
static void emit_restore_quick_callee_without_lr(Arm64Writer* w);
static void emit_art_router_call_original_and_return(Arm64Writer* w, uint64_t trampoline_target);
static void emit_art_router_inc_counter(Arm64Writer* w, volatile uint64_t* counter);
static int resolve_art_callee_save_frame_params(uint64_t* method_out, uint64_t* top_quick_off_out);
static int emit_art_quick_callee_save_frame_push(Arm64Writer* w);
static void emit_art_quick_callee_save_frame_patch_router_callees(Arm64Writer* w);
static void emit_art_quick_callee_save_frame_pop(Arm64Writer* w);

static int resolve_art_quick_test_suspend_entrypoint(uint64_t* entrypoint_out) {
    static uint64_t cached_entrypoint = 0;
    static int cached = 0;

    if (!cached) {
        cached = 1;
        cached_entrypoint = (uint64_t)art_quick_test_suspend_entrypoint();
        g_art_router_quick_test_suspend_entrypoint = cached_entrypoint;
        hook_log("[art_router] quick test-suspend entrypoint: %p", (void*)cached_entrypoint);
    }

    if (cached_entrypoint == 0) {
        return 0;
    }
    *entrypoint_out = cached_entrypoint;
    return 1;
}

static void emit_art_quick_test_suspend_poll_ex(Arm64Writer* w, int preserve_router_regs) {
    (void)w;
    (void)preserve_router_regs;
    /* Do not call art_quick_test_suspend from hook-pool code. That entrypoint
     * installs a SaveEverythingForSuspendCheck frame and ART stack walkers then
     * expect the caller PC to belong to valid quick code with an OAT stack map.
     * A hook-pool caller has no such metadata, so GC/checkpoint stack walking
     * can crash while resolving the synthetic caller frame. Suspend/checkpoint
     * requests are instead handled after we tail-call back into real managed
     * code or while executing recompiled original quick code. */
}

static void emit_art_quick_test_suspend_poll(Arm64Writer* w) {
    emit_art_quick_test_suspend_poll_ex(w, 1);
}

static int resolve_art_callee_save_frame_params(uint64_t* method_out, uint64_t* top_quick_off_out) {
    static uint64_t cached_method = 0;
    static uint64_t cached_top_quick_off = 0;
    static int cached = 0;

    if (!cached) {
        cached = 1;
        cached_method = (uint64_t)art_quick_callee_save_suspend_method();
        cached_top_quick_off = art_quick_top_quick_frame_offset();
        g_art_router_quick_callee_save_method = cached_method;
        g_art_router_quick_top_quick_frame_offset = cached_top_quick_off;
        hook_log("[art_router] quick callee-save params: method=%p top_quick_off=0x%llx",
                 (void*)cached_method, (unsigned long long)cached_top_quick_off);
    }

    if (cached_method == 0 || cached_top_quick_off == UINT64_MAX) {
        return 0;
    }
    *method_out = cached_method;
    *top_quick_off_out = cached_top_quick_off;
    return 1;
}

static int emit_art_quick_callee_save_frame_push(Arm64Writer* w) {
    uint64_t method = 0;
    uint64_t top_quick_off = 0;
    if (!resolve_art_callee_save_frame_params(&method, &top_quick_off)) {
        hook_log("[art_router] quick callee-save frame disabled: method/top_quick offset unavailable");
        return 0;
    }

    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ART_SAVE_EVERYTHING_FRAME_SIZE);

    for (int i = 0; i < 32; i += 2) {
        arm64_writer_put_fp_stp_offset(w, (uint32_t)i, (uint32_t)(i + 1),
                                       ARM64_REG_SP, 16 + i * 8);
    }

    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, 272, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_SP, 288, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_SP, 304, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_SP, 320, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_SP, 336, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_SP, 352, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_SP, 368, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X14, ARM64_REG_X15, ARM64_REG_SP, 384, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_SP, 400, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X19, ARM64_REG_X20, ARM64_REG_SP, 416, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 432, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 448, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 464, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 480, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_LR, ARM64_REG_SP, 496, ARM64_INDEX_SIGNED_OFFSET);

    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, method);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X19, top_quick_off);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, ART_SAVE_EVERYTHING_OLD_TOP_OFF);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_SP, ARM64_REG_X16, 0);

    emit_art_router_inc_counter(w, &g_art_router_quick_callee_save_frame_count);
    return 1;
}

/* After pushing the SaveEverything frame, overwrite the ART quick callee-save
 * spill slots with the original caller values saved in the router frame. Keep
 * live x20-x29 untouched because the router uses them for its own state while
 * setting up the native callback.
 */
static void emit_art_quick_callee_save_frame_patch_router_callees(Arm64Writer* w) {
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_SP, ART_SAVE_EVERYTHING_FRAME_SIZE);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 136);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 424);

    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_X16, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_SP, 432, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_X16, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_SP, 448, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_X16, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_SP, 464, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_X16, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X15, ARM64_REG_SP, 480, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 208);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 496);
}

static void emit_art_quick_callee_save_frame_pop(Arm64Writer* w) {
    uint64_t method = 0;
    uint64_t top_quick_off = 0;
    if (!resolve_art_callee_save_frame_params(&method, &top_quick_off)) {
        return;
    }
    (void)method;

    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X19, top_quick_off);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, ART_SAVE_EVERYTHING_OLD_TOP_OFF);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);

    for (int i = 0; i < 32; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, (uint32_t)i, (uint32_t)(i + 1),
                                       ARM64_REG_SP, 16 + i * 8);
    }

    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, 272, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_SP, 288, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_SP, 304, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_SP, 320, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_SP, 336, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_SP, 352, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_SP, 368, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X14, ARM64_REG_X15, ARM64_REG_SP, 384, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_SP, 400, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X19, ARM64_REG_X20, ARM64_REG_SP, 416, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 432, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 448, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 464, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 480, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_LR, ARM64_REG_SP, 496, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ART_SAVE_EVERYTHING_FRAME_SIZE);
}

static void emit_art_router_quick_callback_path(Arm64Writer* w, uint64_t lbl_quick,
                                                 uint64_t lbl_not_found,
                                                 uint64_t trampoline_target) {
    uint64_t lbl_quick_continue = arm64_writer_new_label_id(w);
    uint64_t lbl_call_original = arm64_writer_new_label_id(w);
    uint64_t lbl_return_replacement = arm64_writer_new_label_id(w);
    uint64_t lbl_preorig_callback = arm64_writer_new_label_id(w);

    arm64_writer_put_label(w, lbl_quick);

    emit_art_router_inc_counter(w, &g_art_router_quick_hit_count);

    /* X16 points to matched table entry. Load the native replacement sentinel
     * and publish it at SP+0 while the callback runs so ART StackVisitor treats
     * this router frame as native and does not look for StackMap data for the
     * original method at our generated PC. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* Reuse the existing recursion guard. If this thread is inside $orig,
     * restore original x0 and fall through to the relocated original code. */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_quick_continue);
    emit_art_router_inc_counter(w, &g_art_router_quick_skip_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);

    arm64_writer_put_label(w, lbl_quick_continue);
    emit_art_router_inc_counter(w, &g_art_router_quick_pass_count);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    /* Mode 2: call original first inside the router frame, then run the
     * callback. The callback reads the saved return value instead of
     * crossing JNI or calling quick code from a native callback stack. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 2);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_preorig_callback);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X16, lbl_call_original);
    emit_art_router_inc_counter(w, &g_art_router_quick_callback_count);

    /* Build a real ART kSaveEverythingForSuspendCheck frame around the whole
     * callback. Before pushing it, restore the original quick-call arguments
     * so GC sees the Java object roots in the ART-defined spill slots. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    emit_restore_args_only(w);
    emit_art_quick_test_suspend_poll(w);
    int has_callee_save_frame = emit_art_quick_callee_save_frame_push(w);
    if (has_callee_save_frame) {
        emit_art_quick_callee_save_frame_patch_router_callees(w);
    }
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP,
                                        (has_callee_save_frame ? ART_SAVE_EVERYTHING_FRAME_SIZE : 0) +
                                            ROUTER_FRAME_PADDING_OFF);

    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X0, ARM64_REG_SP,
                                     has_callee_save_frame ? ART_SAVE_EVERYTHING_FRAME_SIZE : 0);
    if (has_callee_save_frame) {
        arm64_writer_put_mov_reg_reg(w, ARM64_REG_X1, ARM64_REG_SP);
    } else {
        arm64_writer_put_mov_reg_reg(w, ARM64_REG_X1, ARM64_REG_XZR);
    }
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)art_router_prepare_quick_context);
    arm64_writer_put_blr_reg(w, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X22, ARM64_REG_X0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X20, 32); /* quick_user_data */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X22, ARM64_REG_SP,
                                        (has_callee_save_frame ? ART_SAVE_EVERYTHING_FRAME_SIZE : 0) +
                                            ROUTER_FRAME_PADDING_OFF);
    if (has_callee_save_frame) {
        emit_art_quick_callee_save_frame_pop(w);
    }

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X22, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 344);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_call_original);
    /* Keep the ART-visible stack method as the native sentinel while the real
     * original quick code runs. The real ArtMethod is passed in x0 only. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    emit_art_router_call_original_and_return(w, trampoline_target);

    arm64_writer_put_label(w, lbl_preorig_callback);
    /* ART quick code is not a C callee for our router. Do not keep router
     * state in x20-x28 across the original quick call. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);

    /* Keep SP+0 as the quick stack sentinel while the original runs.
     * The sentinel is a static native no-object-argument ArtMethod clone whose
     * quick entrypoint points at this generated thunk, so StackVisitor can use
     * our fake header for wwb_hook_pool PCs and ReferenceMapVisitor has no
     * object parameters to scan from the synthetic router frame. */
    emit_restore_args_only(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    emit_art_quick_test_suspend_poll(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_target);
    emit_restore_quick_callee_without_lr(w);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X1, ARM64_REG_X0);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)art_router_prepare_quick_context_preorig);
    arm64_writer_put_blr_reg(w, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X22, ARM64_REG_X0);

    uint64_t lbl_preorig_no_callback = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X16, lbl_preorig_no_callback);
    emit_art_router_inc_counter(w, &g_art_router_quick_callback_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    emit_restore_args_only(w);
    /* Pre-orig object returns live only in the native HookContext until the
     * callback consumes it. Publish the raw return in SaveEverything.x0 so a
     * moving GC can update it while the callback runs. The ArtMethod* for
     * this frame is written directly at [sp], so x0 does not need to hold it. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, QUICK_PREORIG_RET_REG * 8);
    emit_art_quick_test_suspend_poll(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, QUICK_PREORIG_RET_REG * 8);
    int has_preorig_callee_save_frame = emit_art_quick_callee_save_frame_push(w);
    if (has_preorig_callee_save_frame) {
        emit_art_quick_callee_save_frame_patch_router_callees(w);
    }
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP,
                                        (has_preorig_callee_save_frame ? ART_SAVE_EVERYTHING_FRAME_SIZE : 0) +
                                            ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X22);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X20, 32); /* quick_user_data */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X22, ARM64_REG_SP,
                                        (has_preorig_callee_save_frame ? ART_SAVE_EVERYTHING_FRAME_SIZE : 0) +
                                            ROUTER_FRAME_PADDING_OFF);
    if (has_preorig_callee_save_frame) {
        emit_art_quick_callee_save_frame_pop(w);
    }
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X22, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    if (has_preorig_callee_save_frame) {
        uint64_t lbl_preorig_ret_not_orig = arm64_writer_new_label_id(w);
        arm64_writer_put_mov_reg_reg(w, ARM64_REG_X23, ARM64_REG_X0);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X24, ARM64_REG_X22, 0);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X22, QUICK_PREORIG_RET_REG * 8);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X24, ARM64_REG_X25);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_preorig_ret_not_orig);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X22, 0);
        arm64_writer_put_label(w, lbl_preorig_ret_not_orig);
    }
    arm64_writer_put_b_label(w, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_preorig_no_callback);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 128);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 0);
    arm64_writer_put_b_label(w, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_return_replacement);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X22, 0);
    arm64_writer_put_fp_ldp_offset(w, 0, 1, ARM64_REG_X22, 280);
    arm64_writer_put_fp_stp_offset(w, 0, 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF);
    emit_art_router_restore_all_with_return_x0(w, ARM64_REG_X16);
    emit_thunk_inflight_dec(w);
    arm64_writer_put_ret(w);
}

static void emit_art_router_found_path(Arm64Writer* w, uint64_t lbl_found,
                                        uint32_t quickcode_offset,
                                        uint64_t current_pc_hint,
                                        uint64_t lbl_not_found,
                                        uint64_t trampoline_target) {
    (void)current_pc_hint;

    arm64_writer_put_label(w, lbl_found);

    /* Debug: increment hit counter */
    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);

    uint64_t lbl_quick = arm64_writer_new_label_id(w);
    uint64_t lbl_replacement = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_replacement = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_replacement_no_orig = arm64_writer_new_label_id(w);
    uint64_t lbl_managed_replacement_common = arm64_writer_new_label_id(w);
    uint64_t lbl_replacement_loaded = arm64_writer_new_label_id(w);
    uint64_t lbl_skip_declaring_class_sync = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 16);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X0, lbl_replacement);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 4);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_managed_replacement);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 5);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_managed_replacement_no_orig);
    arm64_writer_put_b_label(w, lbl_quick);

    arm64_writer_put_label(w, lbl_replacement);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);

    /* X16 points to matched table entry; load replacement ArtMethod* from offset 8 */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    arm64_writer_put_b_label(w, lbl_replacement_loaded);

    arm64_writer_put_label(w, lbl_managed_replacement);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X22, 1);
    arm64_writer_put_b_label(w, lbl_managed_replacement_common);

    arm64_writer_put_label(w, lbl_managed_replacement_no_orig);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X22, 0);

    arm64_writer_put_label(w, lbl_managed_replacement_common);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);

    /* Managed replacement is a real Java ArtMethod from helper dex. Do not
     * synchronize declaring_class_ from the hooked method; that would corrupt
     * the helper method's dex/class metadata. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    /* Keep a native sentinel in SP+0 while this fake-router PC is visible to
     * ART stack walking. Then return x0=helper ArtMethod after popping the
     * router frame, immediately before branching into helper quick code. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 32);
    uint64_t lbl_managed_has_sentinel = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_managed_has_sentinel);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_label(w, lbl_managed_has_sentinel);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Recursion / callOriginal bypass check. Keep SP+0 as the native sentinel
     * while calling into Rust, but pass the real helper ArtMethod so
     * stack_replacement_source() can map helper -> original and honor the TLS
     * fallback when the fixed-size fast bypass slots are full. */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    uint64_t lbl_managed_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_managed_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_managed_continue);

    /* The managed helper may call the hooked method again to obtain the
     * original result. Use an explicit one-shot TLS bypass for that nested
     * call instead of relying on WalkStack recursion detection. */
    uint64_t lbl_managed_skip_orig_bypass = arm64_writer_new_label_id(w);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X22, lbl_managed_skip_orig_bypass);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X1, trampoline_target);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)orig_bypass_set_current_thread);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_label(w, lbl_managed_skip_orig_bypass);

    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, quickcode_offset);
    emit_art_router_restore_all_with_return_x0(w, ARM64_REG_X17);
    emit_thunk_inflight_dec_regs(w, ARM64_REG_X14, ARM64_REG_X15);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    arm64_writer_put_label(w, lbl_replacement_loaded);

    /* WalkStack 根治: 提前把 replacement 写到 SP+0, 覆盖 prologue 的 original.
     * 这样 ART StackVisitor 在本线程 (或 peer 线程) 读 *cur_quick_frame = *SP
     * 时立即看到 replacement (K_ACC_NATIVE) → GetDexPc 走 native 早退路径.
     * 在 BLR art_router_stack_check 之前执行, 避免 BLR 进入 Rust 后被其他线程
     * suspend 时 SP+0 还是 original (non-native) → 触发 StackMap not found abort. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* --- Stack check: 防止 callOriginal 递归 (对标 Frida) ---
     * 保存 X16(table entry), X17(replacement) 到 callee-saved X20, X21 (已在 prologue 保存)。
     * 调用 art_router_stack_check(replacement): 返回 0 表示递归 → 走 not_found 路径。
     * NOTE: 递归 (not_found) 时 restore_all 会用 SP+0 的值覆盖 x0, 所以要
     * 在 CBZ 后、走 not_found 分支前先把 SP+0 恢复成 original (否则 x0 变 replacement
     * 破坏原方法调用约定). */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    /* 递归路径: 恢复 SP+0 为 original (table entry 的 first u64), 再跳 not_found.
     * X20 仍是 table entry 指针, 读 [X20, 0] 得 original, 写回 SP+0. */
    uint64_t lbl_found_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_found_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_found_continue);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    arm64_writer_put_label(w, lbl_skip_declaring_class_sync);

    /* 同步 declaring_class_ (offset 0, 4 bytes): original → replacement */
    uint64_t lbl_after_declaring_class_sync = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 4);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_after_declaring_class_sync);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);  /* X0 = original */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X0, 0);   /* W0 = original->declaring_class_ */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X17, 0);  /* replacement->declaring_class_ = W0 */
    arm64_writer_put_label(w, lbl_after_declaring_class_sync);

    /* SP+0 已提前置为 replacement (见上). restore_all 从 SP+0 读回 x0 → x0 = replacement. */

    /* Restore all regs — X0 now holds replacement ArtMethod*
     * (dec 在 restore_all 尾部) */
    emit_art_router_restore_all(w);
    emit_thunk_inflight_dec(w);

    /* Load replacement.entry_point_ (= jni_trampoline) 到 x16, BR 出 thunk */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X0, quickcode_offset);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    emit_art_router_quick_callback_path(w, lbl_quick, lbl_not_found, trampoline_target);
}

static void emit_restore_args_only(Arm64Writer* w);
static void emit_restore_quick_callee_without_lr(Arm64Writer* w);
static void emit_restore_callee_and_pop(Arm64Writer* w);

/* Standalone shared-stub variant.
 *
 * The ArtMethod entry_point points directly at this generated stub, so there is
 * no inline trampoline to remove and no relocated quickCode to return through.
 * Keep g_thunk_in_flight held until the JNI replacement returns, otherwise full
 * cleanup can free the replacement ArtMethod or munmap the hook pool while a
 * replacement quick frame is still active.
 */
static void emit_art_router_found_path_standalone(Arm64Writer* w, uint64_t lbl_found,
                                                   uint32_t quickcode_offset,
                                                   uint64_t lbl_not_found) {
    arm64_writer_put_label(w, lbl_found);

    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);

    /* X16 = table entry, X17 = replacement ArtMethod*. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    uint64_t lbl_found_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_found_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_found_continue);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    uint64_t lbl_after_declaring_class_sync = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 4);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_after_declaring_class_sync);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X0, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X17, 0);
    arm64_writer_put_label(w, lbl_after_declaring_class_sync);

    /* Call replacement.entry_point_ with the caller's quick ABI state restored,
     * while keeping the router frame on stack so ART stack walking sees the
     * native replacement at SP+0 during the call. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, quickcode_offset);
    emit_restore_args_only(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    emit_restore_quick_callee_without_lr(w);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);

    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X0);
    emit_restore_callee_and_pop(w);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X16);
    emit_thunk_inflight_dec(w);
    arm64_writer_put_ret(w);
}

/* Not-found path: 对标 Frida — 恢复全部寄存器 → relocated original instructions → jump back.
 * Shared by generate_art_router_thunk and hook_create_art_router_stub. */
static void emit_art_router_not_found_path(Arm64Writer* w, uint64_t lbl_not_found,
                                            uint64_t fallback_target) {
    arm64_writer_put_label(w, lbl_not_found);
    emit_art_router_debug_counters(w);
    emit_art_router_restore_all(w);
    emit_thunk_inflight_dec(w);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, fallback_target);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);
}

/* ============================================================================
 * BLR variant helpers
 * ============================================================================ */

/* Restore quick argument regs from the ART-visible router frame. */
static void emit_restore_args_only(Arm64Writer* w) {
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP,
            ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_SP, 128);
}

/* Save quick argument regs back into the router frame after ART suspend poll.
 * x0 is the ArtMethod*, not a Java object argument; keep SP+0 under caller
 * control because some paths publish a native sentinel method there. */
static void emit_save_args_only(Arm64Writer* w) {
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP,
            ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_SP, 128);
}

/* Restore ART quick callee-save state without touching LR or SP.
 * x20/x21 are special in ART quick code (marking/suspend registers on many
 * builds). They must contain the caller's values when we either run the
 * original quick method or expose a SaveEverything frame to ART stack walking.
 */
static void emit_restore_quick_callee_without_lr(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, 136);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_SP, 208);
}

/* Restore callee-saved regs (x20-x29, LR) from frame + pop frame.
 * Clobbers NO scratch regs (x16/x17 untouched). */
static void emit_restore_callee_and_pop(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, 136);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_LR, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
}

/* Call the relocated original while keeping the router frame alive, then
 * return to the Java caller only after the original method has returned.
 *
 * This is intentionally different from the fast $orig bypass, which tail-calls
 * the original and never comes back. For fallback/slow-orig paths that do come
 * through our router, keep exec_in_flight held across the original execution so
 * cleanup cannot munmap router/recomp memory while ART can still return here.
 *
 * The caller must put a stack-walk-safe native sentinel in SP+0 and the real
 * original ArtMethod in X0 before this helper is emitted. */
static void emit_art_router_call_original_and_return(Arm64Writer* w, uint64_t trampoline_target) {
    emit_restore_args_only(w);
    emit_art_quick_test_suspend_poll(w);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_target);
    emit_restore_quick_callee_without_lr(w);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    emit_restore_callee_and_pop(w);
    emit_thunk_inflight_dec(w);
    arm64_writer_put_ret(w);
}

/* BLR variant of found path for Layer 3 per-method thunks.
 *
 * Key difference from BR variant: keeps frame on stack, uses BLR to call replacement,
 * then post-callback checks if fast $orig was requested.
 *   - If yes: restore original Quick regs from frame, BR trampoline (zero JNI overhead)
 *   - If no: return callback value to caller
 *
 * trampoline_target: relocated original instructions (known at thunk generation time).
 * Stored in the router frame to survive ART quick/JNI trampolines. Do not rely
 * on x20/x22 being preserved across the BLR: ART quick stubs are not ordinary
 * C callees for our purposes. */
static void emit_art_router_found_path_blr(Arm64Writer* w, uint64_t lbl_found,
                                            uint32_t quickcode_offset,
                                            uint64_t lbl_not_found,
                                            uint64_t trampoline_target) {
    arm64_writer_put_label(w, lbl_found);

    /* Debug: increment hit counter */
    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);

    /* Load replacement ArtMethod* from table entry offset 8 */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);

    /* WalkStack: write replacement to SP+0 early (same as BR variant) */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* --- Stack check (identical to BR variant) --- */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    uint64_t lbl_found_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_found_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_found_continue);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    /* Sync declaring_class_ (same as BR variant) */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X0, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X17, 0);

    /* === BLR-specific: prepare frame state for post-callback === */

    /* Load replacement.entry_point_ */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, quickcode_offset);

    /* Restore argument regs from frame (don't pop, don't restore callee-saved) */
    emit_restore_args_only(w);

    /* Expose the router frame to Rust while the replacement callback is active.
     * If callback requests fast orig, Rust patches object slots in this frame
     * from live JNI transition refs before returning to this post-callback code. */
    emit_set_fast_orig_frame(w);

    /* BLR: call replacement, frame stays on stack */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);

    /* === Post-callback: check fast $orig flag ===
     * x0 = callback return value (from JNI)
     * SP → art_router frame (intact, never popped) */

    uint64_t lbl_no_orig = arm64_writer_new_label_id(w);
    uint64_t lbl_do_orig = arm64_writer_new_label_id(w);

    /* Quick check: g_fast_orig_active == 0 → no fast orig */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_no_orig);

    /* Scan slots for current thread match */
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_do_orig);
    }
    arm64_writer_put_b_label(w, lbl_no_orig);

    /* === do_orig: restore original Quick regs, BR trampoline === */
    arm64_writer_put_label(w, lbl_do_orig);

    emit_clear_fast_orig_frame(w);

    /* Clear matched slot: scan and zero (X16 = current TPIDR_EL0) */
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        uint64_t lbl_skip = arm64_writer_new_label_id(w);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X0);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_skip);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_X17, 8);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X17, 16);
        arm64_writer_put_label(w, lbl_skip);
    }
    /* Decrement active */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);

    /* Debug hit counter */
    emit_atomic_inc64(w, &g_orig_bypass_hit);

    emit_restore_args_only(w);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X21);

    /* Restore callee-saved + pop frame */
    emit_restore_callee_and_pop(w);

    /* BR trampoline → original method → RET to caller */
    emit_thunk_inflight_dec_regs(w, ARM64_REG_X14, ARM64_REG_X15);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    /* === no_orig: return callback value === */
    arm64_writer_put_label(w, lbl_no_orig);

    /* Save callback return value (x0) to X16 */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X0);

    emit_clear_fast_orig_frame(w);

    /* Restore callee-saved + pop frame */
    emit_restore_callee_and_pop(w);

    /* Restore callback return value */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X16);

    /* RET to caller */
    emit_thunk_inflight_dec(w);
    arm64_writer_put_ret(w);
}

/* ============================================================================
 * 伪 OatQuickMethodHeader 前置 (WalkStack 根治)
 *
 * Android 16 (API 36) OatQuickMethodHeader 布局 (libart_base_commit):
 *   class PACKED(4) OatQuickMethodHeader {
 *       uint32_t code_info_offset_;     // offset from code_ back to CodeInfo
 *       uint8_t  code_[0];              // actual method code starts here
 *   };
 *
 * ART 的 GetOatQuickMethodHeader(pc) 逻辑:
 *   header = FromEntryPoint(entry_point) = entry_point - sizeof(header) = entry_point - 4
 *   if (header->Contains(pc))  // code <= pc <= code + GetCodeSize()
 *     return header
 *
 * GetDexPc 在 method->IsNative() 时直接 return kDexNoIndex, 不访问 StackMap.
 * 所以我们:
 *   1. 在 thunk 前放 CodeInfo 字节 + 4B 伪 header
 *   2. code_info_offset_ = 距 code_ 前的 CodeInfo 字节数
 *   3. code_size_ 写 thunk 实际字节数 (body_size)
 *   4. thunk 一开头就把 replacement (native ArtMethod*) 写到 SP+0
 *      → WalkStack 读 *SP = replacement → IsNative=true → ToDexPc 走 native 早退路径
 *
 * The fake CodeInfo must describe the same callee-save layout as ART ARM64
 * SaveRefsAndArgs. If the spill masks are zero, StackVisitor advances by the
 * right frame size but does not refill caller context registers, so the next
 * compiled Java frame can treat stale scalar registers (for example 0x1) as
 * object roots during GC.
 * ============================================================================ */

#define FAKE_OAT_CODEINFO_BYTES 16
#define FAKE_OAT_PREFIX_SIZE (FAKE_OAT_CODEINFO_BYTES + 4)

/* router thunk frame_size (SUB SP, #0xE0 -> 224) / kStackAlignment (16) = 14 */
#define FAKE_PACKED_FRAME_SIZE 14
#define FAKE_CORE_SPILL_MASK \
    ((1u << 30) | \
     (1u << 29) | (1u << 28) | (1u << 27) | (1u << 26) | (1u << 25) | \
     (1u << 24) | (1u << 23) | (1u << 22) | (1u << 21) | (1u << 20) | \
     (1u << 7)  | (1u << 6)  | (1u << 5)  | (1u << 4)  | (1u << 3)  | \
     (1u << 2)  | (1u << 1))
#define FAKE_FP_SPILL_MASK 0xffu

static void fake_codeinfo_write_bits(uint8_t* buf, size_t* bit_offset,
                                     uint32_t value, size_t bit_count) {
    for (size_t i = 0; i < bit_count; i++) {
        if ((value >> i) & 1u) {
            size_t bit = *bit_offset + i;
            buf[bit >> 3] |= (uint8_t)(1u << (bit & 7));
        }
    }
    *bit_offset += bit_count;
}

static void fake_codeinfo_write_interleaved_varints(uint8_t* buf,
                                                    const uint32_t values[7],
                                                    const uint8_t widths[7]) {
    size_t bit_offset = 0;
    for (int i = 0; i < 7; i++) {
        uint32_t value = values[i];
        uint32_t marker = value <= 11u ? value : (11u + widths[i]);
        fake_codeinfo_write_bits(buf, &bit_offset, marker, 4);
    }
    for (int i = 0; i < 7; i++) {
        if (values[i] > 11u) {
            fake_codeinfo_write_bits(buf, &bit_offset, values[i], (size_t)widths[i] * 8u);
        }
    }
}

/* CodeInfo 编码: 7 个 interleaved 4-bit varint + 追加 32-bit 值 (当 nibble >= 12).
 * 字段顺序与 art::CodeInfo::ForEachHeaderField 一致:
 *   flags, code_size, packed_frame_size, core_spill_mask, fp_spill_mask,
 *   number_of_dex_registers, bit_table_flags.
 */
static void encode_fake_codeinfo_v2(uint8_t buf[FAKE_OAT_CODEINFO_BYTES],
                                     uint32_t code_size, uint32_t frame_packed) {
    memset(buf, 0, FAKE_OAT_CODEINFO_BYTES);
    uint32_t values[7] = {
        0,
        code_size,
        frame_packed,
        FAKE_CORE_SPILL_MASK,
        FAKE_FP_SPILL_MASK,
        0,
        0,
    };
    uint8_t widths[7] = {
        0,
        4, /* code_size */
        1, /* packed_frame_size = 14 */
        4, /* core_spill_mask */
        1, /* fp_spill_mask = 0xff */
        0,
        0,
    };
    fake_codeinfo_write_interleaved_varints(buf, values, widths);
}

/* 填充 thunk 前 16 字节: [CodeInfo 12B][OatQuickMethodHeader 4B].
 * code_size covers the whole executable body allocation, not just the current
 * writer offset. If ART fails Contains(pc) for a router return PC, native
 * sentinel frames fall back to GenericJNI frame size. The router frame is kept
 * at the same 224-byte size so both paths advance identically. */
static void backfill_fake_oat_header(void* thunk_mem, uint32_t code_size) {
    uint8_t* p = (uint8_t*)thunk_mem;
    encode_fake_codeinfo_v2(p, code_size, FAKE_PACKED_FRAME_SIZE);
    /* code_info_offset_ is measured from code_ (body start) back to CodeInfo,
     * so it includes both the CodeInfo bytes and the 4-byte header. */
    uint32_t header_data = FAKE_OAT_PREFIX_SIZE;
    memcpy(p + FAKE_OAT_CODEINFO_BYTES, &header_data, sizeof(uint32_t));
}

/* ============================================================================
 * ART router thunk generation (uses helpers above)
 *
 * not_found path: jump to trampoline_target (relocated original instructions).
 * X16/X17 are NOT restored (clobbered by thunk, caller uses X17 for jump-back).
 *
 * 布局: [12B 伪 OAT header/CodeInfo] [thunk body]
 * entry_point 指向 thunk + 12 (body start).
 * ============================================================================ */

static size_t generate_art_router_thunk(void* thunk_mem, size_t thunk_alloc,
                                         void* trampoline_target,
                                         uint32_t quickcode_offset,
                                         uint64_t current_pc_hint,
                                         int use_blr,
                                         int pre_scan) {
    /* 前 12 字节是 CodeInfo+header 占位, 最后 backfill.
     * Arm64Writer 初始化到 body 起点 (thunk_mem + 12). */
    if (thunk_alloc < FAKE_OAT_PREFIX_SIZE + 64) {
        hook_log("[art_router] thunk_alloc %zu too small for fake header", thunk_alloc);
        return 0;
    }
    void* body_mem = (uint8_t*)thunk_mem + FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = thunk_alloc - FAKE_OAT_PREFIX_SIZE;

    Arm64Writer w;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    if (pre_scan) {
        uint64_t lbl_after_pre_bypass = arm64_writer_new_label_id(&w);
        emit_art_router_fast_bypass(&w, lbl_after_pre_bypass, 0);
        arm64_writer_put_label(&w, lbl_after_pre_bypass);
        emit_art_router_pre_scan_guard(&w, (uint64_t)trampoline_target, quickcode_offset);
    }

    /* Fast $orig bypass — checked BEFORE prologue (zero register save overhead).
     * This handles the JNI-path $orig re-entry (orig_bypass_set from Rust). */
    uint64_t lbl_normal_path = arm64_writer_new_label_id(&w);
    emit_thunk_inflight_inc(&w);
    emit_art_router_fast_bypass(&w, lbl_normal_path, 1);
    arm64_writer_put_label(&w, lbl_normal_path);

    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);

    if (use_blr) {
        /* BLR variant: keeps frame on stack, calls trampoline post-callback if $orig set */
        emit_art_router_found_path_blr(&w, lbl_found, quickcode_offset, lbl_not_found,
                                        (uint64_t)trampoline_target);
    } else {
        emit_art_router_found_path(&w, lbl_found, quickcode_offset, current_pc_hint,
                                   lbl_not_found, (uint64_t)trampoline_target);
    }

    /* === not_found path: fall through to trampoline === */
    emit_art_router_not_found_path(&w, lbl_not_found, (uint64_t)trampoline_target);

    arm64_writer_flush(&w);
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    hook_log("[art_router] thunk body_size=%zu body_alloc=%zu (alloc=%zu, use_blr=%d, pre_scan=%d)",
             body_size, body_alloc, thunk_alloc, use_blr, pre_scan);

    /* 回填伪 OAT header + CodeInfo (Contains(pc) 覆盖整个 thunk body allocation) */
    backfill_fake_oat_header(thunk_mem, (uint32_t)body_alloc);

    /* 返回总字节数 (含 12B 前缀), 调用方用于 hook_flush_cache */
    return FAKE_OAT_PREFIX_SIZE + body_size;
}

/* ============================================================================
 * Tiny ART trampoline resolver
 *
 * Some ART entry points (e.g. quick_generic_jni_trampoline) are tiny 8-byte
 * trampolines:
 *   LDR Xt, [X19, #imm]
 *   BR Xt
 *
 * X19 holds the Thread* pointer (current ART thread).  We resolve the actual
 * target by reading Thread*->field at the given offset.
 *
 * jni_env: JNIEnv* pointer.  On Android, JNIEnv* == Thread* + some offset.
 *          Typically Thread* = JNIEnv* - 0 (JNIEnv is the first field).
 * ============================================================================ */

void* resolve_art_trampoline(void* target, void* jni_env) {
    if (!target || !jni_env) return target;

    /* Read first two instructions */
    uint8_t buf[8];
    if (read_target_safe(target, buf, 8) != 0)
        return target;

    uint32_t insn0 = *(uint32_t*)buf;
    uint32_t insn1 = *(uint32_t*)(buf + 4);

    /* Check pattern: LDR Xt, [X19, #imm]  = 1111 1001 01 imm12 10011 Rt
     * Mask: 0xFFC003E0, expect: 0xF9400260 (base=X19, any Rt, any imm12) */
    if ((insn0 & 0xFFC003E0) != 0xF9400260)
        return target;

    /* Check: BR Xt — 1101 0110 0001 1111 0000 00 Rn 00000
     * Mask: 0xFFFFFC1F, expect: 0xD61F0000 */
    uint32_t rt_ldr = insn0 & 0x1F;
    uint32_t rn_br  = (insn1 >> 5) & 0x1F;
    if ((insn1 & 0xFFFFFC1F) != 0xD61F0000)
        return target;
    if (rt_ldr != rn_br)
        return target;

    /* Extract unsigned imm12 (scaled by 8 for 64-bit LDR) */
    uint32_t imm12 = (insn0 >> 10) & 0xFFF;
    uint64_t offset = (uint64_t)imm12 * 8;

    /* JNIEnvExt layout: [0]=JNINativeInterface*, [8]=self_ (Thread*)
     * We need Thread*, not JNIEnv* itself. */
    uint64_t thread = *(uint64_t*)((uint64_t)jni_env + 8);
    uint64_t resolved = *(uint64_t*)(thread + offset);

    hook_log("[art_router] resolve_art_trampoline: %p → LDR X%d,[X19,#%llu]; BR X%d → %llx",
             target, rt_ldr, (unsigned long long)offset, rn_br,
             (unsigned long long)resolved);

    return (void*)resolved;
}

static void emit_managed_direct_set_bypass(Arm64Writer* w, uint64_t original_method,
                                           uint64_t trampoline_target) {
    uint64_t lbl_done = arm64_writer_new_label_id(w);
    uint64_t lbl_fail = arm64_writer_new_label_id(w);

    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        uint64_t lbl_next = arm64_writer_new_label_id(w);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&slot->thread);
        /* LDXR X17, [X16] */
        arm64_writer_put_insn(w, 0xC85F7C00 | (ARM64_REG_NUM(ARM64_REG_X16) << 5) | ARM64_REG_NUM(ARM64_REG_X17));
        arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X17, lbl_next);
        arm64_writer_put_mov_reg_imm(w, ARM64_REG_X17, 1);
        /* Claim the slot with STXR. A racing writer just falls through to the
         * next slot; the final visible thread value is written only after
         * method/trampoline are initialized. */
        arm64_writer_put_insn(w, 0xC8007C00
                                 | (ARM64_REG_NUM(ARM64_REG_W15) << 16)
                                 | (ARM64_REG_NUM(ARM64_REG_X16) << 5)
                                 | ARM64_REG_NUM(ARM64_REG_X17));
        arm64_writer_put_cbnz_reg_label(w, ARM64_REG_W15, lbl_next);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, original_method);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, trampoline_target);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 16);
        /* DMB ISH: publish method/trampoline before replacing the sentinel
         * thread value with the real TPIDR_EL0. */
        arm64_writer_put_insn(w, 0xD5033BBF);
        arm64_writer_put_mrs_reg(w, ARM64_REG_X17, SYSREG_TPIDR_EL0);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
        emit_atomic_inc64(w, &g_orig_bypass_active);
        emit_atomic_inc64(w, &g_orig_bypass_set_success);
        arm64_writer_put_b_label(w, lbl_done);
        arm64_writer_put_label(w, lbl_next);
    }

    arm64_writer_put_label(w, lbl_fail);
    emit_atomic_inc64(w, &g_orig_bypass_set_fail);
    arm64_writer_put_label(w, lbl_done);
}

static void emit_managed_direct_reentry_guard(Arm64Writer* w, uint64_t trampoline_target) {
    uint64_t lbl_continue = arm64_writer_new_label_id(w);

    /* Preserve the quick-call argument registers around the C guard check.  The
     * direct thunk may be entered from compiled Java with primitive args in
     * x0-x7/d0-d7, and a guard hit must tail-call the original trampoline with
     * those registers untouched. */
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 80);
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP, i * 8);
    }
    arm64_writer_put_push_all_regs(w);
    arm64_writer_put_call_address(w, (uint64_t)hook_managed_reentry_guard_active);
    /* Current SP is 256 bytes below the FP save area; store the C return value
     * into the extra 16-byte slot at FP-save+64. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 320);
    arm64_writer_put_pop_all_regs(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP, 64);
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, i * 8);
    }
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 80);

    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X16, lbl_continue);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_target);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);
    arm64_writer_put_label(w, lbl_continue);
}

static size_t generate_managed_direct_thunk(void* thunk_mem, size_t thunk_alloc,
                                            void* trampoline_target,
                                            uint64_t helper_method,
                                            uint64_t helper_entry,
                                            uint64_t original_method,
                                            int set_orig_bypass,
                                            int bypass_dec_before_trampoline) {
    if (thunk_alloc < 2048) return 0;

    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, thunk_alloc);

    uint64_t lbl_normal_path = arm64_writer_new_label_id(&w);
    /* The managed helper's orig() re-entry is an extremely hot path. Do not
     * put the global cleanup counter on that bypass path; one extra atomic op
     * per HashMap.put orig() is enough for JD's crash monitor to hit
     * SuspendThreadByPeer timeouts under startup load. The short trampoline
     * window is covered by the later all-thread PC/LR safepoint before munmap.
    */
    emit_art_router_fast_bypass(&w, lbl_normal_path, bypass_dec_before_trampoline);
    arm64_writer_put_label(&w, lbl_normal_path);

    emit_managed_direct_reentry_guard(&w, (uint64_t)trampoline_target);

    emit_thunk_inflight_inc(&w);
    emit_art_quick_test_suspend_poll_ex(&w, 0);
    emit_atomic_inc64(&w, &g_managed_direct_hit_count);

    if (set_orig_bypass) {
        emit_managed_direct_set_bypass(&w, original_method, (uint64_t)trampoline_target);
    }

    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X0, helper_method);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, helper_entry);
    /* Tail-call the generated managed helper. Keeping LR unchanged makes the
     * helper return to the original Java caller, so no hook-pool return PC is
     * exposed to ART stack walking during allocation/GC.
     *
     * Cleanup must not rely on g_thunk_in_flight alone for managed-direct DSL:
     * once we decrement here, the generated helper and its orig() call may
     * still be executing. A separate helper-side active counter is needed for
     * exact cut -> drain -> free semantics without exposing hook-pool LR.
    */
    emit_thunk_inflight_dec_regs(&w, ARM64_REG_X14, ARM64_REG_X15);
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    if (arm64_writer_flush(&w) != 0) {
        hook_log("[managed_direct] label resolution failed");
        return 0;
    }
    size_t size = arm64_writer_offset(&w);
    hook_flush_cache(thunk_mem, size);
    hook_log("[managed_direct] thunk size=%zu helper=%llx entry=%llx original=%llx trampoline=%p",
             size, (unsigned long long)helper_method, (unsigned long long)helper_entry,
             (unsigned long long)original_method, trampoline_target);
    return size;
}

void* hook_install_managed_direct_router(void* target,
                                         int stealth,
                                         void* jni_env,
                                         void** out_hooked_target,
                                         uint64_t helper_method,
                                         uint64_t helper_entry,
                                         uint64_t original_method,
                                         int set_orig_bypass) {
    if (!g_engine.initialized || !target || !helper_method || !helper_entry || !original_method) {
        return NULL;
    }

    void* resolved = resolve_art_trampoline(target, jni_env);
    if (resolved != target) {
        target = resolved;
    }
    if (out_hooked_target) {
        *out_hooked_target = target;
    }

    hook_lock(&g_engine.lock);

    HookEntry* existing = find_hook(target);
    if (existing) {
        void* trampoline = existing->trampoline;
        hook_unlock(&g_engine.lock);
        return trampoline;
    }

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_alloc = 16384;
    if (!entry->thunk || entry->thunk_alloc < thunk_alloc) {
        entry->thunk = hook_alloc_near(thunk_alloc, target);
        entry->thunk_alloc = thunk_alloc;
    }
    if (!entry->thunk) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = generate_managed_direct_thunk(
        entry->thunk, thunk_alloc, entry->trampoline, helper_method, helper_entry, original_method, set_orig_bypass, 0);
    if (thunk_size == 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (patch_target(target, entry->thunk, stealth, entry) != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, entry->thunk, thunk_size);
    hook_unlock(&g_engine.lock);
    return entry->trampoline;
}

static size_t generate_count_orig_thunk(void* thunk_mem, size_t thunk_alloc,
                                        void* trampoline_target,
                                        volatile uint64_t** counters,
                                        uint32_t counter_count) {
    if (thunk_alloc < FAKE_OAT_PREFIX_SIZE + 512 || !trampoline_target || !counters || counter_count == 0) return 0;

    void* body_mem = (uint8_t*)thunk_mem + FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = thunk_alloc - FAKE_OAT_PREFIX_SIZE;

    Arm64Writer w;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    /* Use the same ART-visible frame layout as the generic router. The fake
     * OAT CodeInfo below describes ROUTER_FRAME_SIZE and its spill masks; a
     * smaller private scratch frame makes suspend/GC stack walking decode the
     * count thunk with the wrong SP and can crash when the counter is read. */
    emit_art_router_prologue(&w);

    for (uint32_t i = 0; i < counter_count; i++) {
        if (counters[i]) {
            emit_atomic_inc64(&w, counters[i]);
        }
    }

    emit_art_router_restore_all(&w);

    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)trampoline_target);
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    if (arm64_writer_flush(&w) != 0) {
        hook_log("[count_orig] label resolution failed");
        return 0;
    }
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    backfill_fake_oat_header(thunk_mem, (uint32_t)body_alloc);
    hook_flush_cache(thunk_mem, FAKE_OAT_PREFIX_SIZE + body_size);
    hook_log("[count_orig] thunk body_size=%zu counters=%u trampoline=%p",
             body_size, counter_count, trampoline_target);
    return FAKE_OAT_PREFIX_SIZE + body_size;
}

void* hook_install_count_orig_router(void* target,
                                     int stealth,
                                     void* jni_env,
                                     void** out_hooked_target,
                                     volatile uint64_t** counters,
                                     uint32_t counter_count) {
    if (!g_engine.initialized || !target || !counters || counter_count == 0) {
        return NULL;
    }

    void* resolved = resolve_art_trampoline(target, jni_env);
    if (resolved != target) {
        target = resolved;
    }
    if (out_hooked_target) {
        *out_hooked_target = target;
    }

    hook_lock(&g_engine.lock);

    HookEntry* existing = find_hook(target);
    if (existing) {
        void* trampoline = existing->trampoline;
        hook_unlock(&g_engine.lock);
        return trampoline;
    }

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_alloc = 4096;
    if (!entry->thunk || entry->thunk_alloc < thunk_alloc) {
        entry->thunk = hook_alloc_near(thunk_alloc, target);
        entry->thunk_alloc = thunk_alloc;
    }
    if (!entry->thunk) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = generate_count_orig_thunk(
        entry->thunk, thunk_alloc, entry->trampoline, counters, counter_count);
    if (thunk_size == 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    void* patch_dest = (uint8_t*)entry->thunk + FAKE_OAT_PREFIX_SIZE;
    if (patch_target(target, patch_dest, stealth, entry) != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, entry->thunk, thunk_size);
    hook_unlock(&g_engine.lock);
    return entry->trampoline;
}

void* hook_create_count_orig_stub(uint64_t fallback_target,
                                  volatile uint64_t** counters,
                                  uint32_t counter_count) {
    if (!g_engine.initialized || !fallback_target || !counters || counter_count == 0) {
        return NULL;
    }

    hook_lock(&g_engine.lock);

    size_t stub_alloc = 4096;
    void* stub_mem = hook_alloc(stub_alloc);
    if (!stub_mem) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = generate_count_orig_thunk(
        stub_mem, stub_alloc, (void*)fallback_target, counters, counter_count);
    if (thunk_size == 0) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    hook_unlock(&g_engine.lock);
    return (uint8_t*)stub_mem + FAKE_OAT_PREFIX_SIZE;
}

void* hook_create_managed_orig_stub(uint64_t original_method,
                                    void* trampoline) {
    if (!g_engine.initialized || !original_method || !trampoline) {
        return NULL;
    }

    hook_lock(&g_engine.lock);
    void* stub = hook_alloc(128);
    if (!stub) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    Arm64Writer w;
    arm64_writer_init(&w, stub, (uint64_t)stub, 128);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X0, original_method);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)trampoline);
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);
    if (arm64_writer_flush(&w) != 0) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t size = arm64_writer_offset(&w);
    hook_flush_cache(stub, size);
    hook_unlock(&g_engine.lock);
    hook_log("[managed_orig] stub size=%zu original=%llx trampoline=%p stub=%p",
             size, (unsigned long long)original_method, trampoline, stub);
    return stub;
}

void* hook_install_managed_direct_entrypoint(void* target,
                                             void* jni_env,
                                             void** out_resolved_target,
                                             uint64_t helper_method,
                                             uint64_t helper_entry,
                                             uint64_t original_method,
                                             int set_orig_bypass) {
    if (!g_engine.initialized || !target || !helper_method || !helper_entry || !original_method) {
        return NULL;
    }

    void* resolved = resolve_art_trampoline(target, jni_env);
    if (resolved != target) {
        target = resolved;
    }
    if (out_resolved_target) {
        *out_resolved_target = target;
    }

    hook_lock(&g_engine.lock);

    size_t thunk_alloc = 16384;
    void* thunk = hook_alloc_near(thunk_alloc, target);
    if (!thunk) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = generate_managed_direct_thunk(
        thunk, thunk_alloc, target, helper_method, helper_entry, original_method, set_orig_bypass, 0);
    if (thunk_size == 0) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    hook_flush_cache(thunk, thunk_size);
    hook_unlock(&g_engine.lock);

    hook_log("[managed_direct_ep] thunk size=%zu helper=%llx entry=%llx original=%llx original_entry=%p thunk=%p",
             thunk_size, (unsigned long long)helper_method, (unsigned long long)helper_entry,
             (unsigned long long)original_method, target, thunk);
    return thunk;
}

/* ============================================================================
 * hook_install_art_router — inline hook with ART router thunk
 *
 * Similar to hook_install() but instead of a simple replacement, installs a
 * router thunk that scans g_art_router_table inline.
 * ============================================================================ */

void* hook_install_art_router(void* target, uint32_t quickcode_offset,
                               int stealth, void* jni_env,
                               void** out_hooked_target,
                               int skip_resolve,
                               uint64_t current_pc_hint,
                               int use_blr,
                               int pre_scan) {
    if (!g_engine.initialized || !target) {
        return NULL;
    }

    /* Resolve tiny ART trampolines (LDR+BR 8 bytes) to actual target */
    if (!skip_resolve) {
        void* resolved = resolve_art_trampoline(target, jni_env);
        if (resolved != target) {
            hook_log("[art_router] resolved %p → %p", target, resolved);
            target = resolved;
        }
    }

    /* Report the actual hooked address back to the caller for cleanup */
    if (out_hooked_target) {
        *out_hooked_target = target;
    }

    hook_lock(&g_engine.lock);

    /* Check if already hooked — return existing trampoline */
    HookEntry* existing = find_hook(target);
    if (existing) {
        void* trampoline = existing->trampoline;
        hook_unlock(&g_engine.lock);
        return trampoline;
    }

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate thunk (router code — larger than default).
     * hook_alloc_near 按 ±128MB → ±4GB → 任意 三层分配。 */
    /* pre_scan nterp thunks include two one-shot $orig bypass scanners plus
     * the managed guard fast path, so they are larger than the generic router.
     * Keep enough headroom to avoid Arm64Writer's overflow abort in-app. */
    size_t art_thunk_alloc = pre_scan ? 32768 : 16384;
    if (!entry->thunk || entry->thunk_alloc < art_thunk_alloc) {
        entry->thunk = hook_alloc_near(art_thunk_alloc, target);
        entry->thunk_alloc = art_thunk_alloc;
    }
    if (!entry->thunk) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    /* Generate router thunk — not_found path jumps to trampoline.
     * Thunk 布局: [12B 伪 OAT header/CodeInfo] [thunk body].
     * thunk_size 返回值含 12B 前缀. entry_point/patch_target 指向 body start. */
    size_t thunk_size = generate_art_router_thunk(
        entry->thunk, art_thunk_alloc,
        entry->trampoline, quickcode_offset, current_pc_hint, use_blr, pre_scan);
    if (thunk_size == 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    /* Patch target to jump to router thunk body (跳过 12B 伪 header) */
    void* patch_dest = (uint8_t*)entry->thunk + FAKE_OAT_PREFIX_SIZE;
    if (patch_target(target, patch_dest, stealth, entry) != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, entry->thunk, thunk_size);

    void* trampoline = entry->trampoline;
    hook_unlock(&g_engine.lock);

    hook_log("[art_router] installed: target=%p, thunk=%p, trampoline=%p",
             target, entry->thunk, trampoline);

    return trampoline;
}

void* hook_art_router_get_thunk_body(void* target) {
    if (!g_engine.initialized || !target) {
        return NULL;
    }

    hook_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    void* body = NULL;
    if (entry && entry->thunk) {
        body = (uint8_t*)entry->thunk + FAKE_OAT_PREFIX_SIZE;
    }
    hook_unlock(&g_engine.lock);
    return body;
}

/* ============================================================================
 * hook_create_art_router_stub — standalone ART router (no inline patching)
 *
 * Creates a thunk that scans g_art_router_table for X0, and if not found,
 * jumps to fallback_target.  The caller writes the returned address into
 * ArtMethod.entry_point_ directly.
 * ============================================================================ */

void* hook_create_art_router_stub(uint64_t fallback_target,
                                   uint32_t quickcode_offset) {
    if (!g_engine.initialized || !fallback_target) {
        return NULL;
    }

    hook_lock(&g_engine.lock);

    /* stub 通过 ArtMethod.entry_point_ 指针间接调用，不需要 near.
     * 布局: [12B 伪 OAT header/CodeInfo] [stub body]. 返回 body 起点. */
    size_t stub_alloc = 16384;
    void* stub_mem = hook_alloc(stub_alloc);
    if (!stub_mem) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    void* body_mem = (uint8_t*)stub_mem + FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = stub_alloc - FAKE_OAT_PREFIX_SIZE;

    Arm64Writer w;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    /* Fast $orig bypass */
    uint64_t lbl_normal_path = arm64_writer_new_label_id(&w);
    emit_thunk_inflight_inc(&w);
    emit_art_router_fast_bypass(&w, lbl_normal_path, 1);
    arm64_writer_put_label(&w, lbl_normal_path);

    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);
    emit_art_router_found_path_standalone(&w, lbl_found, quickcode_offset,
                                          lbl_not_found);

    /* === not_found path: jump to fallback === */
    emit_art_router_not_found_path(&w, lbl_not_found, fallback_target);

    arm64_writer_flush(&w);
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    /* 回填 16B 伪 OAT header + CodeInfo */
    backfill_fake_oat_header(stub_mem, (uint32_t)body_alloc);

    hook_flush_cache(stub_mem, FAKE_OAT_PREFIX_SIZE + body_size);

    hook_unlock(&g_engine.lock);

    hook_log("[art_router] stub created: %p (body=%p, fallback=%llx, body_size=%zu)",
             stub_mem, body_mem, (unsigned long long)fallback_target, body_size);

    return body_mem;  /* entry_point 指向 body, 前 12B 是伪 OAT header */
}

/* ============================================================================
 * C-side GC synchronization — 对标 Frida synchronize_replacement_methods
 *
 * 遍历 g_art_router_table，对每个 original/replacement 对:
 * 1. 复制 declaring_class_ (offset 0, 4B) from original → replacement
 * 2. 如果 original.quickCode == nterp → 降级为 interpreter_bridge
 * ============================================================================ */
void hook_art_synchronize_replacement_methods(
    uint32_t quickcode_offset,
    uint64_t nterp_entrypoint,
    uint64_t interp_bridge) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        uint64_t original = g_art_router_table[i].original;
        uint64_t replacement = g_art_router_table[i].replacement;
        if (original == 0) break;
        if (replacement == 0) continue;

        /* 1. declaring_class_ 同步.
         * Quick callback entries use a standalone native sentinel ArtMethod.
         * Its dex/method metadata must stay paired with its original declaring
         * class; copying the hooked method's class makes ART PrettyMethod read
         * unrelated dex data during stack dumps. */
        if (g_art_router_table[i].mode == 0) {
            uint32_t declaring_class = *(volatile uint32_t*)(uintptr_t)original;
            *(volatile uint32_t*)(uintptr_t)replacement = declaring_class;
        }

        /* 2. Plain JS replacements follow Frida's nterp downgrade. Managed DSL
         * entries are high-frequency and route the shared nterp entry directly,
         * so GC/fixup synchronization must not rewrite their original entrypoint. */
        if (g_art_router_table[i].mode == 0 && nterp_entrypoint != 0 && quickcode_offset != 0) {
            volatile uint64_t* ep = (volatile uint64_t*)((uintptr_t)original + quickcode_offset);
            if (*ep == nterp_entrypoint && interp_bridge != 0) {
                *ep = interp_bridge;
            }
        }
    }
}
