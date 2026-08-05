/*
 * hook_engine.h - ARM64 Inline Hook Engine
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses MOVZ/MOVK + BR X16 jump sequences (up to 20 bytes).
 */

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define HOOK_OK                     0
#define HOOK_ERROR_NOT_INITIALIZED  -1
#define HOOK_ERROR_INVALID_PARAM    -2
#define HOOK_ERROR_ALREADY_HOOKED   -3
#define HOOK_ERROR_ALLOC_FAILED     -4
#define HOOK_ERROR_MPROTECT_FAILED  -5
#define HOOK_ERROR_NOT_FOUND        -6
#define HOOK_ERROR_BUFFER_TOO_SMALL -7
#define HOOK_ERROR_WXSHADOW_FAILED  -8

/* Hook context - contains all ARM64 registers */
typedef struct {
    uint64_t x[31];         /* x0-x30: 0-247 */
    uint64_t sp;            /* Stack pointer: 248 */
    uint64_t pc;            /* Program counter (original): 256 */
    uint64_t nzcv;          /* Condition flags: 264 */
    void* trampoline;       /* Trampoline for callOriginal (NULL if N/A): 272 */
    uint64_t d[8];          /* d0-d7 FP registers: 280-343 */
    uint64_t intercept_leave; /* 344: attach 模式下 on_enter 返回前可改写.
                               * 仅当 hook 安装了 on_leave 时有效: 1=wrap, 0=tail-jump.
                               * 无 on_leave 时 hook engine 必然 tail-jump, 写 1 无效. */
} HookContext;              /* 352 bytes, 16-byte aligned */

/* Callback function types */
typedef void (*HookCallback)(HookContext* ctx, void* user_data);

/* Hook entry structure */
typedef struct HookEntry {
    void* target;                   /* Original function address */
    void* trampoline;               /* Trampoline to call original */
    void* replacement;              /* Replacement function (for replace mode) */
    HookCallback on_enter;          /* Enter callback (for attach mode) */
    HookCallback on_leave;          /* Leave callback (for attach mode) */
    void* user_data;                /* User data for callbacks */
    uint8_t original_bytes[24];     /* Saved original bytes (up to 20 needed) */
    size_t original_size;           /* Number of bytes saved */
    int stealth;                    /* 1 if installed via wxshadow stealth mode */
    void* thunk;                    /* Thunk code pointer (attach mode) */
    size_t trampoline_alloc;        /* Trampoline allocated size */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookEntry* next;         /* Next entry in list */
} HookEntry;

/* Redirect entry — replaces a function pointer (e.g. ArtMethod entry_point)
 * rather than patching inline code.  No instruction relocation needed. */
typedef struct HookRedirectEntry {
    uint64_t key;                   /* Unique identifier (e.g. ArtMethod* address) */
    void* original_entry;           /* Original entry point (for restore on unhook) */
    void* thunk;                    /* Generated redirect thunk */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookRedirectEntry* next; /* Next entry in list */
} HookRedirectEntry;

/* 可执行内存 pool（多个，按需靠近 hook 目标分配） */
#define MAX_EXEC_POOLS 64
#define EXEC_POOL_SIZE (64 * 1024)  /* 每个 pool 64KB */

typedef struct {
    volatile int state;             /* 0=unlocked, 1=locked */
} HookLock;

typedef struct {
    void* base;
    size_t size;
    size_t used;
} ExecPool;

/* Global hook engine state */
typedef struct {
    void* exec_mem;                 /* 初始 pool（向后兼容） */
    size_t exec_mem_size;           /* 初始 pool 总大小 */
    size_t exec_mem_used;           /* 初始 pool 已用 */
    ExecPool pools[MAX_EXEC_POOLS]; /* 多 pool（含初始 pool） */
    int pool_count;                 /* 已分配 pool 数 */
    HookEntry* hooks;               /* Linked list of hooks */
    HookEntry* free_list;           /* Freed entries for reuse */
    HookRedirectEntry* redirects;   /* Linked list of redirect hooks */
    HookLock lock;                  /* Thread safety lock without libc pthread */
    size_t exec_mem_page_size;      /* Page size for mprotect */
    int initialized;                /* Initialization flag */
} HookEngine;

/*
 * Initialize the hook engine
 *
 * @param exec_mem      Pointer to executable memory region (RWX)
 * @param size          Size of the memory region
 * @return              0 on success, -1 on failure
 */
int hook_engine_init(void* exec_mem, size_t size);

/*
 * Install a simple replacement hook
 *
 * @param target        Address to hook
 * @param replacement   Replacement function address
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              Pointer to trampoline (to call original), NULL on failure
 */
void* hook_install(void* target, void* replacement, int stealth);

/*
 * Install a Frida-style hook with callbacks
 *
 * @param target        Address to hook
 * @param on_enter      Callback called before the function (can be NULL)
 * @param on_leave      Callback called after the function (can be NULL)
 * @param user_data     User data passed to callbacks
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              0 on success, -1 on failure
 */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth);

/*
 * Remove a hook
 *
 * @param target        Address that was hooked
 * @return              0 on success, -1 on failure
 */
int hook_remove(void* target);

/*
 * Get the trampoline for a hooked function
 *
 * @param target        Original function address
 * @return              Trampoline address, NULL if not found
 */
void* hook_get_trampoline(void* target);

/*
 * Mark an already-installed hook as recomp-backed.
 *
 * The hook target is an anonymous recomp slot; removal/cleanup must not
 * restore it as a normal inline patch because the recomp layer owns route
 * activation and rollback.
 */
int hook_mark_recomp_hook(void* target);

/* Same as hook_mark_recomp_hook(), but finds the hook by its trampoline.
 * Useful for recomp callers that receive the trampoline after hook_install. */
int hook_mark_recomp_hook_by_trampoline(void* trampoline);

/*
 * Cleanup and free all hooks
 */
void hook_engine_cleanup(void);

/* 扩展 pool 的地址区间描述。供 Rust 侧 safepoint 校验 + munmap 使用。 */
typedef struct {
    uint64_t base;
    uint64_t size;
} ExecPoolRange;

/*
 * 读取最近一次 hook_engine_cleanup 快照的扩展 pool 范围。
 *
 * hook_engine_cleanup 仅快照范围到内部表、重置 metadata，**不** munmap。
 * Rust 侧拿到范围后做"全线程 PC/LR safepoint"检查，确认无线程驻留再 munmap。
 *
 * @param out 输出数组
 * @param cap 数组容量
 * @return 实际写入 out 的条数（可能小于内部总数，调用者应保证 cap >= MAX_EXEC_POOLS）
 */
int hook_engine_get_pool_ranges(ExecPoolRange* out, int cap);

/* 读取当前仍可能出现在 ART 栈上的 hook engine 可执行范围：
 * 初始 exec_mem + 当前扩展 pool + cleanup 后 retained pool。 */
int hook_engine_get_exec_ranges(ExecPoolRange* out, int cap);

/* 清空快照（Rust 在 munmap 完成后调用，防止跨次 cleanup 误认） */
void hook_engine_clear_pool_ranges(void);

/*
 * Returns non-zero if pc belongs to any executable memory pool owned by the
 * hook engine. Used by ART stack-walk diagnostics to detect managed frames
 * whose return PC points into generated router code.
 */
int hook_is_in_exec_pool(uint64_t pc);

/* Thunk 在途计数。由 thunk 入口 LDADDAL inc, 出口 LDADDAL dec 直接配对。
 * cleanup 侧：
 *   1. 先反装所有 hook (切断新入口)
 *   2. 轮询此值 → 0 表示无 in-flight thunk
 *   3. 若归零：Rust 调 hook_engine_munmap_pools_direct 同步清
 *   4. 若超时：放弃同步清，pool/walkstack guards 泄漏到进程退出 */
extern volatile uint64_t g_thunk_in_flight;
uint64_t hook_thunk_in_flight_count(void);

/* 同步 munmap 所有扩展 pool。仅在 g_thunk_in_flight == 0 时调用才安全。
 * drain 超时不应调用此函数，让 pool 泄漏到进程退出。 */
void hook_engine_munmap_pools_direct(void);

/* Internal functions - exposed for advanced use */

/*
 * Allocate memory from the executable pool
 *
 * @param size          Number of bytes to allocate
 * @return              Pointer to allocated memory, NULL on failure
 */
/* 注册外部分配的 RWX 内存为 ExecPool（供 hook_alloc_near_range 使用）。
 * recomp 页在 mmap 时附带分配 hook slot 区，注册后 hook engine 可直接使用，
 * 避免二次 near-range 分配失败。
 * 返回 0 成功，-1 失败（pool 数量已满）。 */
int hook_register_pool(void* base, size_t size);

/* 重建 trampoline: 将 orig_bytes (4字节) 从 orig_pc 重定位到 trampoline，
 * 然后追加绝对跳转到 jump_back_target。
 * 用途: stealth2 slot 模式下修复 hook engine 自动生成的错误 trampoline。
 * 返回 trampoline 写入的总字节数，<0 失败。 */
int hook_rebuild_trampoline(void* trampoline, size_t trampoline_size,
                            const void* orig_bytes, uint64_t orig_pc,
                            void* jump_back_target);

/* Allocate from any pool (legacy, no locality guarantee) */
void* hook_alloc(size_t size);

/* Allocate from a pool near `target` (within ±4GB for ADRP).
 * Creates a new pool via maps gap scan if no existing pool is in range. */
void* hook_alloc_near(size_t size, void* target);

/* mmap RWX 内存，扫描 /proc/self/maps 在 target ±4GB 内找空隙。
 * target=NULL 时退化为普通 mmap(NULL)。
 * 返回 mmap 指针，MAP_FAILED 表示失败。调用方负责 munmap。 */
void* hook_mmap_near(void* target, size_t alloc_size);

/* 参数化版本: 指定搜索范围 max_range（如 ±128MB = 1<<27）。
 * recomp 页用此确保紧邻原始代码。 */
void* hook_mmap_near_range(void* target, size_t alloc_size, int64_t max_range);

/*
 * Relocate ARM64 instruction(s) to dst.
 *
 * src_buf  - pointer to a pre-read copy of the original bytes (may differ from
 *            the live address; typically entry->original_bytes read via
 *            /proc/self/mem to bypass XOM pages)
 * src_pc   - original PC of the first instruction (used for PC-relative fixups)
 * dst      - destination address in the executable pool
 * min_bytes - number of bytes to relocate
 * out_written_regs - if non-NULL, receives bitmask of GPRs written by
 *                    relocated instructions (bit N = XN written)
 *
 * Returns number of bytes written to dst.
 */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc,
                                   void* dst, size_t min_bytes,
                                   uint32_t* out_written_regs);

/*
 * Generate an absolute jump (MOVZ/MOVK + BR, up to 20 bytes)
 *
 * @param dst           Where to write the jump
 * @param target        Jump target address
 * @return              Number of bytes written on success, or negative error code
 */
int hook_write_jump(void* dst, void* target);

/*
 * Clear instruction cache for modified code
 *
 * @param start         Start address
 * @param size          Size of region
 */
void hook_flush_cache(void* start, size_t size);

/*
 * Log function type: receives a null-terminated message string.
 * Set via hook_engine_set_log_fn() to route diagnostic output to Rust/socket.
 */
typedef void (*HookLogFn)(const char* msg);

/*
 * Set the log callback.  Call after hook_engine_init().
 * Pass NULL to disable logging.
 */
void hook_engine_set_log_fn(HookLogFn fn);

/*
 * Create a redirect thunk for pointer-based hooking (e.g. ArtMethod entry_point).
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores registers → tail-calls original_entry via BR x16.
 *
 * Unlike hook_attach(), this does NOT patch target code or create a trampoline.
 * The caller is responsible for writing the returned thunk address to the
 * function pointer slot (e.g. ArtMethod->entry_point_from_quick_compiled_code_).
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param original_entry Original function entry point (for tail-call after callback)
 * @param on_enter       Callback called before the original function
 * @param user_data      User data passed to callback
 * @return               Thunk address on success, NULL on failure
 */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data);

/*
 * Remove a redirect hook and return the original entry point.
 *
 * @param key            The key used when creating the redirect
 * @return               Original entry point, NULL if not found
 */
void* hook_remove_redirect(uint64_t key);

/*
 * Create a native hook trampoline for ART "replace with native" hooking.
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores x0 (return value) → returns to caller (RET).
 *
 * This thunk is designed to be called by ART's JNI trampoline as a native
 * method implementation. The callback receives x0=JNIEnv*, x1=jobject/jclass,
 * x2-x7=Java args via HookContext.
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param on_enter       Callback invoked when the method is called
 * @param user_data      User data passed to callback
 * @return               Thunk address (to store in ArtMethod.data_), NULL on failure
 */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data,
                                    uint64_t current_pc_hint);

/*
 * ART router lookup table — inline C-side table for O(N) scan in generated thunk.
 * Eliminates per-call Mutex+HashMap overhead: thunk reads table directly via LDR,
 * no BLR/function call needed.
 */
#define ART_ROUTER_TABLE_MAX 256
typedef struct {
    uint64_t original;      /* Original ArtMethod* (0 = sentinel / end marker) */
    uint64_t replacement;   /* Replacement ArtMethod* */
    uint64_t mode;          /* 0 = replacement, 1/2 = quick callback, 4/5 = managed helper */
    HookCallback quick_callback;
    void* quick_user_data;
} ArtRouterEntry;

/*
 * Add an entry to the ART router lookup table.
 * Thread safety: caller must hold g_engine.lock (called during hook setup).
 *
 * @param original      Original ArtMethod* address
 * @param replacement   Replacement ArtMethod* address
 * @return              0 on success, -1 if table full
 */
int hook_art_router_table_add(uint64_t original, uint64_t replacement);

/*
 * Add an entry routed to a managed helper ArtMethod. Mode 4/5 is published
 * atomically with the table entry so high-frequency shared entrypoints never
 * observe a temporary mode-0 helper replacement.
 */
int hook_art_router_table_add_managed(uint64_t original, uint64_t replacement,
                                      void* sentinel);
int hook_art_router_table_add_managed_mode(uint64_t original, uint64_t replacement,
                                           void* sentinel, uint64_t mode);

/*
 * Add an entry routed directly to a native quick callback.
 * The replacement ArtMethod is still used as a native stack-walk sentinel
 * while the callback runs, but execution does not go through ART's JNI
 * trampoline. The callback receives (HookContext*, user_data).
 */
int hook_art_router_table_add_quick(uint64_t original, uint64_t replacement,
                                    HookCallback callback, void* user_data);
int hook_art_router_table_add_quick_mode(uint64_t original, uint64_t replacement,
                                         HookCallback callback, void* user_data,
                                         uint64_t mode);

void hook_art_router_table_set_mode(uint64_t original, uint64_t mode);
void hook_art_router_table_set_user_data(uint64_t original, void* user_data);

/*
 * Remove an entry from the ART router lookup table.
 *
 * @param original      Original ArtMethod* address to remove
 * @return              0 on success, -1 if not found
 */
int hook_art_router_table_remove(uint64_t original);

/*
 * Clear all entries from the ART router lookup table.
 */
void hook_art_router_table_clear(void);

/*
 * Reverse lookup: given replacement ArtMethod*, return the original ArtMethod*.
 * Used by callOriginal TLS bypass to match art_router entries.
 * Returns 0 if not found.
 */
uint64_t hook_art_router_table_lookup_original(uint64_t replacement);
uint64_t hook_art_router_table_lookup_mode_by_replacement(uint64_t replacement);

/*
 * Debug/statistics: called from ART DoCall hook to record whether an interpreted
 * call targets an ArtMethod currently present in the C router table.
 * Returns the non-zero router mode for quick/managed entries, 2 for plain
 * replacement entries, 0 if absent.
 */
int hook_art_router_record_do_call(uint64_t method);

/* Fast $orig bypass — skip art_router prologue+scan when callOriginal is in progress.
 * Array of per-thread slots checked at thunk entry BEFORE register save.
 * Each slot: {thread_id, method(ArtMethod*), trampoline, pad} = 32 bytes. */
#define ORIG_BYPASS_SLOTS 32

typedef struct {
    volatile uint64_t thread;       /* thread ID (TPIDR_EL0), 0 = free slot */
    volatile uint64_t method;       /* original ArtMethod* to match x0 */
    volatile uint64_t trampoline;   /* trampoline to jump to on match */
    uint64_t _pad;
} OrigBypassState;

extern OrigBypassState g_orig_bypass[ORIG_BYPASS_SLOTS];
extern volatile uint64_t g_orig_bypass_active;  /* >0 when any slot in use */
extern volatile uint64_t g_orig_bypass_hit;     /* debug counter */
extern volatile uint64_t g_orig_bypass_set_success; /* debug counter */
extern volatile uint64_t g_orig_bypass_set_fail;    /* debug counter */

/* Set/clear a fast $orig bypass slot (entry-level: thunk skips prologue+scan).
 * orig_bypass_set: atomically claim a free slot, write thread+method+trampoline.
 *   Returns 0 on success, -1 if all slots are busy (fallback to TLS bypass).
 * orig_bypass_clear: release the slot for the given thread. */
int orig_bypass_set(uint64_t thread, uint64_t method, uint64_t trampoline);
uint64_t orig_bypass_consume_current_thread(uint64_t method);
void orig_bypass_clear(uint64_t thread);

/* BLR fast $orig: post-callback flag slots (separate from entry bypass).
 * Set by Rust $orig to signal thunk should call trampoline after callback. */
#define FAST_ORIG_SLOTS 4
typedef struct {
    volatile uint64_t thread;   /* TPIDR_EL0, 0 = free slot */
    volatile uint64_t method;   /* original ArtMethod* for post-callback orig */
    volatile uint64_t trampoline; /* relocated original entry */
    uint64_t _pad;
} FastOrigSlot;

extern FastOrigSlot g_fast_orig_slots[FAST_ORIG_SLOTS];
extern volatile uint64_t g_fast_orig_active;

int fast_orig_set(uint64_t thread, uint64_t method, uint64_t trampoline);
void fast_orig_clear(uint64_t thread);
uint64_t fast_orig_current_frame(uint64_t thread);

/*
 * Dump all entries in the ART router lookup table (via hook_log).
 */
void hook_art_router_table_dump(void);

/*
 * Debug: simulate the thunk's table scan for a given ArtMethod* address.
 * Returns 1 if found, 0 if not found. Logs the result via hook_log.
 */
int hook_art_router_debug_scan(uint64_t x0);

/*
 * Debug: hex dump code at given address (via hook_log).
 */
void hook_dump_code(void* addr, size_t size);

/*
 * Debug: get last X0 seen in not_found path and miss count.
 * The ART router thunk stores X0 to a global on every not_found scan.
 */
void hook_art_router_get_debug(uint64_t* last_x0, uint64_t* miss_count);

/*
 * Get hit counter for found path + last matched X0.
 */
void hook_art_router_get_hit_debug(uint64_t* hit_count, uint64_t* last_hit_x0);

/*
 * Debug: split route counters for quick/replacement router hits and DoCall hits.
 */
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
                                     uint64_t* quick_test_suspend_entrypoint);

/*
 * Debug: reset the not_found X0 capture and miss counter.
 */
void hook_art_router_reset_debug(void);

/*
 * Debug: managed Java helper backup tail-stub hit counter.
 */
uint64_t* hook_managed_backup_stub_hit_counter_addr(void);
uint64_t hook_managed_backup_stub_hits(void);
uint64_t hook_managed_direct_hits(void);
void hook_set_managed_reentry_guard_enabled(int enabled);
int hook_managed_reentry_guard_enabled(void);
void hook_managed_reentry_guard_enter(void);
void hook_managed_reentry_guard_leave(void);
int hook_managed_reentry_guard_active(void);
uint32_t hook_managed_reentry_guard_depth(void);
uint64_t hook_managed_reentry_guard_enters(void);
uint64_t hook_managed_reentry_guard_bypass_hits(void);
uint64_t hook_orig_bypass_hits(void);
uint64_t hook_orig_bypass_set_successes(void);
uint64_t hook_orig_bypass_set_failures(void);
uint64_t hook_orig_bypass_active_count(void);
uint64_t hook_oat_inline_patch_count(void);
uint64_t hook_oat_pc_pool_bypass_hits(void);
uint64_t hook_oat_replacement_bypass_hits(void);
void hook_oat_patch_reset_stats(void);
uint64_t hook_oat_pc_pool_bypass_check(uint64_t pc);

/*
 * Install an ART method router hook with inline table lookup.
 *
 * Generates a routing trampoline that:
 *   1. Saves X16/X17 (IPC scratch registers)
 *   2. Scans g_art_router_table inline (no function call)
 *   3. If found: x0 = replacement, jump to replacement.quickCode
 *   4. If not found: restore, execute relocated original, jump back
 *
 * Uses the HookEntry infrastructure (inline patches target with MOVZ/MOVK+BR).
 *
 * @param target            Address to hook (quickCode entry point)
 * @param quickcode_offset  Offset of entry_point_from_quick_compiled_code_ in ArtMethod
 * @param stealth           1 to use wxshadow stealth mode, 0 for normal mode
 * @param jni_env           JNIEnv* for resolving tiny ART trampolines
 * @param out_hooked_target If non-NULL, receives the actual hooked address (may differ
 *                          from target if resolve_art_trampoline resolved a tiny trampoline)
 * @param skip_resolve      1 to skip resolve_art_trampoline (caller already resolved)
 * @return                  Trampoline address (relocated original instructions), NULL on failure
 */
void* hook_install_art_router(void* target, uint32_t quickcode_offset,
                               int stealth, void* jni_env,
                               void** out_hooked_target,
                               int skip_resolve,
                               uint64_t current_pc_hint,
                               int use_blr,
                               int pre_scan);

void* hook_install_managed_direct_router(void* target,
                                         int stealth,
                                         void* jni_env,
                                         void** out_hooked_target,
                                         uint64_t helper_method,
                                         uint64_t helper_entry,
                                         uint64_t original_method,
                                         int set_orig_bypass);

void* hook_install_count_orig_router(void* target,
                                     int stealth,
                                     void* jni_env,
                                     void** out_hooked_target,
                                     volatile uint64_t** counters,
                                     uint32_t counter_count);

/*
 * Create a standalone count+orig stub for methods whose entry_point_ is a
 * shared ART bridge and therefore cannot be safely inline-patched.
 */
void* hook_create_count_orig_stub(uint64_t fallback_target,
                                  volatile uint64_t** counters,
                                  uint32_t counter_count);

void* hook_install_managed_direct_entrypoint(void* target,
                                             void* jni_env,
                                             void** out_resolved_target,
                                             uint64_t helper_method,
                                             uint64_t helper_entry,
                                             uint64_t original_method,
                                             int set_orig_bypass);

void* hook_create_managed_orig_stub(uint64_t original_method,
                                    void* trampoline);

/*
 * Return the generated ART router thunk body for a hooked quickCode target.
 * The returned address is entry_point compatible (fake OAT header lives
 * immediately before it). Returns NULL if target is not currently hooked.
 */
void* hook_art_router_get_thunk_body(void* target);

/*
 * Resolve tiny ART trampolines (LDR Xt,[X19,#imm]; BR Xt) to actual target.
 * Returns the resolved address, or target unchanged if not a trampoline.
 */
void* resolve_art_trampoline(void* target, void* jni_env);

/*
 * Create a standalone ART method router stub (no inline patching).
 *
 * Allocates executable memory and generates a thunk that:
 *   1. Saves X16/X17 (IPC scratch registers)
 *   2. Scans g_art_router_table inline for X0 match
 *   3. If found: X0 = replacement, jump to replacement.quickCode
 *   4. If not found: restore scratch, jump to fallback_target
 *
 * Unlike hook_install_art_router(), this does NOT patch any existing code.
 * The caller should set ArtMethod.entry_point_ to the returned address.
 * This avoids the interpreter-to-interpreter fast path that bypasses
 * inline-hooked assembly bridges.
 *
 * Thread-safe: the stub is shared across all hooked methods that use the
 * same fallback_target.
 *
 * @param fallback_target   Address to jump to when X0 is not in table
 *                          (e.g., original interpreter_bridge address)
 * @param quickcode_offset  Offset of entry_point_ in ArtMethod
 * @return                  Stub address, NULL on failure
 */
void* hook_create_art_router_stub(uint64_t fallback_target,
                                   uint32_t quickcode_offset);

/* C-side GC synchronization — 对标 Frida synchronize_replacement_methods.
 * 遍历 router table 同步 declaring_class_ + nterp 降级。
 * 由 Rust 侧 GC 回调调用。 */
void hook_art_synchronize_replacement_methods(
    uint32_t quickcode_offset,
    uint64_t nterp_entrypoint,
    uint64_t interp_bridge);

/*
 * Install a replace-mode hook (save ctx → callback → restore x0 → RET)
 *
 * Unlike hook_attach(), the thunk does NOT automatically call the original
 * function. The callback can invoke the original via hook_invoke_trampoline().
 *
 * @param target        Address to hook
 * @param on_enter      Callback called when the function is entered
 * @param user_data     User data passed to callback
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              Trampoline address (for callOriginal), NULL on failure
 */
void* hook_replace(void* target, HookCallback on_enter, void* user_data, int stealth);

/*
 * Restore registers from HookContext and call trampoline (original function).
 * Returns x0 (the original function's return value).
 *
 * Implemented in assembly. Restores x0-x15 from ctx, calls trampoline via BLR,
 * and returns the result. For float/double returns, d0 is NOT captured.
 *
 * @param ctx           Pointer to HookContext with saved registers
 * @param trampoline    Trampoline address (relocated original instructions)
 * @return              x0 result from the original function
 */
uint64_t hook_invoke_trampoline(HookContext* ctx, void* trampoline);

/*
 * Patch inlined GetOatQuickMethodHeader copies in WalkStack (API 31+).
 *
 * Scans libart.so executable segments for the inlined pattern and binary-patches
 * each copy with a trampoline that checks if the method is a replacement (via
 * g_art_router_table). Replacement methods skip the OAT lookup to prevent
 * NULL+0x18 SIGSEGV in WalkStack.
 *
 * @param exclude_addr  Function body address to exclude from the pattern scan
 *                      (usually ArtMethod::GetOatQuickMethodHeader itself), or 0.
 * @return  Number of patterns patched (>=0), or negative error code
 */
int hook_patch_inlined_oat_header_checks(uint64_t exclude_addr);

/*
 * Restore all inlined OAT header patches applied by hook_patch_inlined_oat_header_checks().
 *
 * @return  Number of patches restored
 */
int hook_restore_inlined_oat_header_patches(void);

/*
 * Recomp translate callback: 将原始地址翻译为 recomp 页地址。
 * 返回 recomp 地址 (>0) 表示成功，0 表示失败。
 */
typedef uintptr_t (*recomp_translate_fn)(uintptr_t orig_addr);
typedef uintptr_t (*recomp_reverse_translate_fn)(uintptr_t recomp_addr);

/*
 * 注册 recomp 翻译回调。设置后，oat_patch 等写入会在 recomp 页上操作。
 */
void hook_set_recomp_translate(recomp_translate_fn fn);
void hook_set_recomp_existing_translate(recomp_translate_fn fn);
void hook_set_recomp_reverse_translate(recomp_reverse_translate_fn fn);

/*
 * 设置 OAT patch 的 stealth 模式: 0=normal(mprotect), 1=wxshadow, 2=recomp
 * hook_set_recomp_translate 会自动设为 2，此函数用于单独设 wxshadow。
 */
void hook_set_stealth_mode(int mode);

/*
 * Stealth-write `len` bytes of `buf` to `addr` via the kernel wxshadow
 * facility. Creates a shadow page, writes the bytes, and activates it as
 * --x without ever exposing the target page as writable in /proc/self/maps.
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure (kernel does
 * not support wxshadow, target VMA is not 4KB-mapped after PMD-split COW
 * retry, etc.).
 */
int wxshadow_patch(void* addr, const void* buf, size_t len);

/*
 * Release a wxshadow patch by its exact patch start address (must match the
 * `addr` previously passed to wxshadow_patch). Returns 0 on success.
 */
int wxshadow_release(void* addr);

/*
 * Diagnostic: 测试 hook_alloc_near 对给定 target 的有效性。
 * 打印 pool 状态、分配结果、ADRP 可达性。
 */
void hook_diag_alloc_near(void* target);

#ifdef __cplusplus
}
#endif

#endif /* HOOK_ENGINE_H */
