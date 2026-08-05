/*
 * hook_engine_internal.h - Internal declarations shared between hook_engine*.c files
 *
 * NOT a public API header — only included by the hook_engine implementation files.
 */

#ifndef HOOK_ENGINE_INTERNAL_H
#define HOOK_ENGINE_INTERNAL_H

#include "hook_engine.h"
#include "arm64_writer.h"
#include "arm64_relocator.h"
#include <string.h>
#include <sys/mman.h>
#ifdef __ANDROID__
#include <sys/prctl.h>
#endif
#include <sys/uio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

static inline void hook_lock_init(HookLock* lock) {
    __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
}

static inline void hook_lock(HookLock* lock) {
    while (__atomic_exchange_n(&lock->state, 1, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&lock->state, __ATOMIC_RELAXED) != 0) {
            __asm__ __volatile__("yield" ::: "memory");
        }
    }
}

static inline void hook_unlock(HookLock* lock) {
    __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
}

static inline void hook_lock_destroy(HookLock* lock) {
    __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
}

/* wxshadow prctl operations - two-step shadow page patching:
 *   1. PATCH: create shadow + write data + activate (--x) in one step
 *   2. RELEASE: restore the exact patch identified by its patch start address
 *
 * PATCH: prctl(op, pid, addr, buf, len) where pid=0 means current process.
 * RELEASE: prctl(op, pid, patch_addr) where patch_addr must exactly match the
 * address passed to PATCH.
 */
#ifndef PR_WXSHADOW_PATCH
#define PR_WXSHADOW_PATCH   0x57580006  /* prctl(0x57580006, pid, addr, buf, len) — one-step patch */
#endif
#ifndef PR_WXSHADOW_RELEASE
#define PR_WXSHADOW_RELEASE 0x57580008  /* prctl(0x57580008, pid, addr) — restore original */
#endif

/* Minimum instructions to relocate for our jump sequence.
 * arm64_writer_put_branch_address uses MOVZ/MOVK + BR:
 * - Up to 4 MOV instructions (16 bytes) for 64-bit address
 * - 1 BR instruction (4 bytes)
 * Total: 20 bytes = 5 instructions
 */
#define MIN_HOOK_SIZE 20

/* ARM64 instruction size */
#define INSN_SIZE 4

/* Default allocation sizes */
#define TRAMPOLINE_ALLOC_SIZE 256
#define THUNK_ALLOC_SIZE 512

/* --- Shared state (defined in hook_engine.c) --- */
extern HookEngine g_engine;
extern HookLogFn g_log_fn;
extern ExecPoolRange g_retained_pool_ranges[MAX_EXEC_POOLS];
extern int g_retained_pool_range_count;
/* --- ART router globals (defined in hook_engine_art.c) --- */
extern ArtRouterEntry g_art_router_table[ART_ROUTER_TABLE_MAX];
extern volatile uint64_t g_art_router_last_x0;
extern volatile uint64_t g_art_router_miss_count;

/* --- Diagnostic log (hook_engine.c) --- */
void hook_log(const char* fmt, ...);

/* --- Thunk in-flight counter helpers (hook_engine.c) ---
 * 所有 thunk 入口/出口都应调用这两个 helper，覆盖整个 thunk 生命周期。
 * cleanup drain 轮询 g_thunk_in_flight==0 即可安全 munmap pool。 */
void emit_thunk_inflight_inc(Arm64Writer* w);
void emit_thunk_inflight_dec(Arm64Writer* w);
void emit_thunk_inflight_dec_regs(Arm64Writer* w, Arm64Reg addr_reg, Arm64Reg val_reg);

/* 同步 munmap 所有 pool。仅在 drain 到 0 后由 orchestrator 调用（无 in-flight）。
 * drain 失败路径不应调用，让 pool 泄漏到进程退出。 */
void hook_engine_munmap_pools_direct(void);

/* --- Memory management (hook_engine_mem.c) --- */
int page_has_read_perm(uintptr_t addr);
int page_prot_flags(uintptr_t addr);
int read_target_safe(void* target, void* buf, size_t len);
int mprotect_range_pages(void* target, size_t len, int prot);
void restore_range_prot_pages(void* target, size_t len, const int* prot_flags, size_t prot_count);
size_t save_range_prot_pages(void* target, size_t len, int* prot_flags, size_t prot_cap);
void restore_page_rx(uintptr_t page_start);
void restore_page_prot_span(uintptr_t page_start, int first_prot, int second_prot);
HookEntry* alloc_entry(void);
void free_entry(HookEntry* entry);
int wxshadow_patch(void* addr, const void* buf, size_t len);
int wxshadow_release(void* addr);
/* 写 trampoline 尾 "mov scratch, target; br scratch".
 * emit_dec_before_jump=1: 在 mov 前插入 emit_thunk_inflight_dec，
 * 用于 art_router 的 not_found 路径（thunk 已 tail-BR 到 trampoline, 需要
 * 在真正离开 pool 前才 dec counter）。其他 caller 传 0 保持原有语义。 */
int write_jump_back(void* dst, void* target, uint32_t written_regs,
                    int emit_dec_before_jump);
int hook_write_jump_at(void* dst, uint64_t exec_pc, void* target);
void* hook_alloc_near_range(size_t size, void* target, int64_t max_range);

/* --- Core (hook_engine.c) --- */
HookEntry* find_hook(void* target);

/* --- Hook installation helpers (hook_engine_mem.c) --- */

/*
 * Allocate and set up a HookEntry with trampoline.
 *
 * Caller must hold g_engine.lock. On success: entry is allocated
 * with trampoline + original_bytes ready. On failure: returns NULL, lock is still held.
 *
 * @param target    Address to hook
 * @return          HookEntry* or NULL on failure
 */
HookEntry* setup_hook_entry(void* target);

/*
 * Relocate original instructions to the entry's trampoline and write jump-back.
 *
 * @param entry     HookEntry with target, original_bytes, trampoline set
 * @param emit_dec_before_jumpback  1=trampoline 尾 dec thunk_in_flight 后再 BR
 *                                   (art_router not_found 路径用)
 *                                   0=正常，不 dec (attach 模式，counter 由 thunk RET 管)
 * @return          0 on success, negative error code on failure
 */
int build_trampoline(HookEntry* entry, int emit_dec_before_jumpback);

/*
 * Patch the target address to jump to jump_dest.
 *
 * @param target        Address to patch
 * @param jump_dest     Destination to jump to
 * @param stealth       1 for wxshadow, 0 for mprotect
 * @param entry         HookEntry (sets entry->stealth)
 * @return              0 on success, negative error code on failure
 */
int patch_target(void* target, void* jump_dest, int stealth, HookEntry* entry);

/* 查找 target 所在 VMA 的同 inode rw-s 兄弟映射, 返回对应 writable 地址 (无则 NULL).
 * len: 需要可写的字节数, 用于校验 sibling VMA 能容纳整段 patch (防跨 VMA memcpy SEGV).
 * 用于 ART JIT cache dual-view patch (绕 VM_MAYWRITE). */
void* find_rw_sibling(void* target, size_t len);

/*
 * Finalize the hook: flush caches, add to hook list.
 *
 * @param entry         HookEntry to finalize
 * @param thunk         Thunk pointer (may be NULL for simple replacement)
 * @param thunk_size    Thunk size in bytes (0 if no thunk)
 */
void finalize_hook(HookEntry* entry, void* thunk, size_t thunk_size);

/* --- Thunk emit helpers (hook_engine_inline.c) --- */

/*
 * Emit the shared HookContext save prologue (352-byte stack frame).
 *
 * Generates: SUB SP, #352 → STP x0-x29 → STR x30 →
 *            save original SP → save target_pc → save NZCV →
 *            optionally save trampoline_ptr → STP d0-d7
 *
 * @param w               Writer instance
 * @param target_pc       Value to store in context.pc (original function address)
 * @param trampoline_ptr  Trampoline address to store in context.trampoline;
 *                        0 to skip (not all thunks need a trampoline)
 */
void emit_save_hook_context(Arm64Writer* w, uint64_t target_pc, uint64_t trampoline_ptr);

/*
 * Emit callback invocation: set up args and BLR.
 *
 * Generates: MOV X0, SP → LDR X1, =user_data → LDR X16, =callback → BLR X16
 *
 * @param w           Writer instance
 * @param callback    Callback function address
 * @param user_data   User data to pass as second argument
 */
void emit_callback_call(Arm64Writer* w, HookCallback callback, void* user_data);

/*
 * Emit replace-mode epilogue: restore x0 + LR, deallocate 352-byte stack, RET.
 *
 * Shared by generate_replace_thunk (inline hook) and generate_native_hook_thunk (Java hook).
 */
void emit_replace_epilogue(Arm64Writer* w);

/*
 * Emit x0-x15 + d0-d7 restore from HookContext on stack.
 *
 * Restores caller-saved registers (x0-x15, d0-d7) from the 352-byte HookContext frame.
 * Does NOT restore x16-x18 — caller handles those after loading addresses into x16.
 *
 * Shared by generate_attach_thunk (inline hook) and generate_redirect_thunk (Java hook).
 */
void emit_restore_caller_regs(Arm64Writer* w);

/* --- Inline hook thunks (hook_engine_inline.c) --- */
void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
                             HookCallback on_leave, void* user_data,
                             size_t* thunk_size_out);

#endif /* HOOK_ENGINE_INTERNAL_H */
