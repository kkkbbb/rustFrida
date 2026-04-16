/*
 * hook_engine.c - ARM64 Inline Hook Engine — Core
 *
 * Global state, logging, initialization, find_hook, cleanup.
 * Implementation details are split across:
 *   hook_engine_mem.c    — memory pool, alloc, wxshadow, relocate
 *   hook_engine_inline.c — inline hook install/attach/replace/remove
 *   hook_engine_redir.c  — redirect and native thunks
 *   hook_engine_art.c    — ART method router
 */

#include "hook_engine_internal.h"

/* Global engine state */
HookEngine g_engine = {0};

/* --- Diagnostic log infrastructure --- */

HookLogFn g_log_fn = NULL;

void hook_engine_set_log_fn(HookLogFn fn) {
    g_log_fn = fn;
}

void hook_log(const char* fmt, ...) {
    if (!g_log_fn) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_fn(buf);
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    if (g_engine.initialized) {
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.pool_count = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_init(&g_engine.lock, NULL);
    g_engine.initialized = 1;

    return 0;
}

/* Find hook entry by target address */
HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

/* Cleanup all hooks */
void hook_engine_cleanup(void) {
    if (!g_engine.initialized) return;

    pthread_mutex_lock(&g_engine.lock);

    /* Count hooks on both lists for diagnostics */
    int hooks_count = 0, free_count = 0, stealth_hooks = 0, stealth_free = 0;
    for (HookEntry* e = g_engine.hooks; e; e = e->next) {
        hooks_count++;
        if (e->stealth) stealth_hooks++;
    }
    for (HookEntry* e = g_engine.free_list; e; e = e->next) {
        free_count++;
        if (e->stealth) stealth_free++;
    }
    hook_log("hook_engine_cleanup: hooks=%d (stealth=%d), free_list=%d (stealth=%d)",
             hooks_count, stealth_hooks, free_count, stealth_free);

    /* Restore each live hook individually.
     * stealth==1 (wxshadow): must use prctl release.
     * stealth==2 (recomp): was installed via mprotect+write, restore same way.
     * stealth==0 (normal): restore via mprotect+memcpy. */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->stealth == 1) {
            int rc = wxshadow_release(entry->target);
            if (rc != 0) {
                hook_log("hook_engine_cleanup: wxshadow_release failed for %p", entry->target);
            }
        } else {
            /* stealth==0 (mprotect) and stealth==2 (recomp) both use mprotect+memcpy */
            uintptr_t page_start = (uintptr_t)entry->target & ~0xFFF;
            mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(entry->target, entry->original_bytes, entry->original_size);
            restore_page_rx(page_start);
            hook_flush_cache(entry->target, entry->original_size);
        }
        entry = entry->next;
    }

    /* HookEntry lifetime note:
     * All HookEntry structs (including trampoline and thunk memory) live in one of
     * two executable pool regions:
     *   1. 初始 pool (exec_mem)  — 由 Rust 侧 ExecMemory 拥有，调用方负责 munmap
     *   2. 扩展 pool (pools[])   — 由 create_pool_near_range_sized 经 mmap 创建，
     *                              本次 cleanup 负责 munmap，否则会作为隐藏 VMA
     *                              残留进程地址空间（wwb_hook_pool，KPM 隐藏）
     *
     * WARNING: Do NOT add malloc()/free() fallback paths for alloc_entry(). If pool
     * allocations ever fall back to malloc, those pointers would be invalid after a
     * munmap and would require explicit free() here. Keep all hook memory in the pool.
     *
     * 调用方必须已 wait_for_in_flight_*_hook_callbacks，否则 munmap 时可能有线程
     * 仍在 trampoline 内执行 → SIGSEGV。 */

    /* 释放所有扩展 pool（保留初始 exec_mem 由调用方处理） */
    int freed_pools = 0;
    size_t freed_bytes = 0;
    for (int i = 0; i < g_engine.pool_count; i++) {
        if (g_engine.pools[i].base && g_engine.pools[i].size) {
            munmap(g_engine.pools[i].base, g_engine.pools[i].size);
            freed_bytes += g_engine.pools[i].size;
            freed_pools++;
        }
        g_engine.pools[i].base = NULL;
        g_engine.pools[i].size = 0;
        g_engine.pools[i].used = 0;
    }
    if (freed_pools > 0) {
        hook_log("hook_engine_cleanup: released %d pool(s), %zu bytes", freed_pools, freed_bytes);
    }
    g_engine.pool_count = 0;

    /* Reset state — the list pointers are now dangling (pool memory unmapped) */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.initialized = 0;

    pthread_mutex_unlock(&g_engine.lock);
    pthread_mutex_destroy(&g_engine.lock);
}
