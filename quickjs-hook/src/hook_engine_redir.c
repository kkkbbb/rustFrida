/*
 * hook_engine_redir.c - Redirect thunks and native hook trampolines
 *
 * Contains: generate_redirect_thunk, hook_create_redirect,
 * hook_remove_redirect, generate_native_hook_thunk,
 * hook_create_native_trampoline.
 */

#include "hook_engine_internal.h"

/* Generate a redirect thunk (pointer-based hooking, no inline patching).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore registers →
 * BR x16 (tail-call to original_entry, preserving caller's LR).
 */
static void* generate_redirect_thunk(void* original_entry,
                                      HookCallback on_enter,
                                      void* user_data,
                                      void* thunk_mem,
                                      size_t* thunk_size_out) {
    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    uint64_t stack_size = 352;

    /* Save HookContext (no trampoline for redirect mode) */
    emit_save_hook_context(&w, (uint64_t)original_entry, 0);

    /* Call on_enter(ctx, user_data) */
    emit_callback_call(&w, on_enter, user_data);

    /* Restore x0-x15 from context (callback may have modified arguments) */
    emit_restore_caller_regs(&w);

    /* Load original_entry into x16 for tail-call */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)original_entry);

    /* Restore x17-x18 (saved earlier by STP) */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);

    /* Restore x30 (LR) — critical: tail-call via BR preserves caller's LR */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 264);
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X19);
    /* Restore x19 from context (we clobbered it for NZCV restore) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 152);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Tail-call to original entry: BR x16 (NOT BLR — preserves caller's LR) */
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* --- Shared redirect entry helpers --- */

/* Prepare a redirect entry: dup check + pool writable + alloc entry + alloc thunk_mem.
 * Caller must hold g_engine.lock. On failure: unlocks mutex and returns NULL.
 * On success: *out_entry is set and thunk_mem is returned (pool is writable). */
static void* prepare_redirect_entry(uint64_t key, HookRedirectEntry** out_entry) {
    /* Check for duplicate */
    HookRedirectEntry* cur = g_engine.redirects;
    while (cur) {
        if (cur->key == key) {
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        cur = cur->next;
    }

    /* Allocate entry in pool */
    HookRedirectEntry* entry = (HookRedirectEntry*)hook_alloc(sizeof(HookRedirectEntry));
    if (!entry) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }
    memset(entry, 0, sizeof(HookRedirectEntry));

    /* redirect/native thunk 通过指针间接调用，不需要近距离分配 */
    void* thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
    if (!thunk_mem) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    *out_entry = entry;
    return thunk_mem;
}

/* Finalize a redirect entry: fill fields, flush cache, make executable, unlock.
 * Returns thunk address on success. */
static void* finalize_redirect_entry(HookRedirectEntry* entry, uint64_t key,
                                      void* original_entry, void* thunk, size_t thunk_size) {
    entry->key = key;
    entry->original_entry = original_entry;
    entry->thunk = thunk;
    entry->thunk_alloc = THUNK_ALLOC_SIZE;
    entry->next = g_engine.redirects;
    g_engine.redirects = entry;

    hook_flush_cache(thunk, thunk_size);

    pthread_mutex_unlock(&g_engine.lock);
    return thunk;
}

/* Create a redirect hook — returns thunk address, caller writes it to the pointer slot */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data) {
    if (!g_engine.initialized || !original_entry || !on_enter)
        return NULL;

    pthread_mutex_lock(&g_engine.lock);

    HookRedirectEntry* entry;
    void* thunk_mem = prepare_redirect_entry(key, &entry);
    if (!thunk_mem) return NULL;

    size_t thunk_size = 0;
    void* thunk = generate_redirect_thunk(original_entry, on_enter, user_data,
                                           thunk_mem, &thunk_size);
    if (!thunk) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    return finalize_redirect_entry(entry, key, original_entry, thunk, thunk_size);
}

/* Remove a redirect hook — returns original entry point (caller restores the pointer) */
void* hook_remove_redirect(uint64_t key) {
    if (!g_engine.initialized) return NULL;

    pthread_mutex_lock(&g_engine.lock);

    HookRedirectEntry* prev = NULL;
    HookRedirectEntry* entry = g_engine.redirects;

    while (entry) {
        if (entry->key == key) {
            void* original = entry->original_entry;

            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.redirects = entry->next;
            }

            pthread_mutex_unlock(&g_engine.lock);
            return original;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&g_engine.lock);
    return NULL;
}

/* Generate a native hook thunk (for replace-with-native approach).
 *
 * Similar to redirect thunk but ends with RET instead of BR to original.
 * Used when a Java method is converted to native and this thunk serves
 * as the native function implementation (stored in ArtMethod.data_).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore x0 → RET
 */
static void* generate_native_hook_thunk(HookCallback on_enter,
                                         void* user_data,
                                         uint64_t current_pc_hint,
                                         void* thunk_mem,
                                         size_t* thunk_size_out) {
    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    uint64_t stack_size = 352;

    /* Save HookContext.
     * current_pc_hint != 0 时，表示这是从 compiled+router Java hook 进入的
     * native thunk；此时 HookContext.pc 也暴露为原始方法内的可见 PC。 */
    emit_save_hook_context(&w, current_pc_hint, 0);

    /* Call on_enter(ctx, user_data) */
    emit_callback_call(&w, on_enter, user_data);

    /* Restore x0 */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* 统一从 saved LR 恢复 (= jni_trampoline 内的返回地址)。
     * 不再区分 compiled/shared_stub 路径。让 RET 回到 jni_trampoline epilogue，
     * 由 GenericJniMethodEnd 正常清理 JNI transition frame，避免 frame 泄漏。 */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240); /* saved LR */

    /* Restore x18 (platform register) before returning */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X18, ARM64_REG_SP, 144);

    /* Deallocate stack and return */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);
    arm64_writer_put_ret(&w);

    arm64_writer_flush(&w);
    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* Create a native hook trampoline — called by ART's JNI trampoline as a native function.
 * Returns the thunk address to be stored in ArtMethod.data_ field.
 * Uses the redirect entry list for tracking (shares hook_remove_redirect for cleanup). */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data,
                                    uint64_t current_pc_hint) {
    if (!g_engine.initialized || !on_enter)
        return NULL;

    pthread_mutex_lock(&g_engine.lock);

    HookRedirectEntry* entry;
    /* native trampoline 通过 ArtMethod.data_ 间接调用，不需要 ADRP 近距离 */
    void* thunk_mem = prepare_redirect_entry(key, &entry);
    if (!thunk_mem) return NULL;

    size_t thunk_size = 0;
    void* thunk = generate_native_hook_thunk(on_enter, user_data, current_pc_hint, thunk_mem, &thunk_size);
    if (!thunk) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    return finalize_redirect_entry(entry, key, NULL, thunk, thunk_size);
}
