/*
 * hook_engine_mem.c - Memory pool management, XOM-safe read, wxshadow, cache flush
 *
 * Contains: pool permission management, entry allocation/free, wxshadow patching,
 * write_jump_back, hook_write_jump, hook_alloc, hook_relocate_instructions,
 * hook_flush_cache.
 */

#include "hook_engine_internal.h"

/* --- Page permission helpers --- */

/*
 * Check if the page containing addr has read permission.
 * Parses /proc/self/maps to find the VMA and check perms[0] == 'r'.
 * Returns 1 if readable, 0 otherwise.
 */
int page_has_read_perm(uintptr_t addr) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int readable = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                readable = (perms[0] == 'r');
                break;
            }
        }
    }
    fclose(f);
    return readable;
}

/*
 * Safely read bytes from a target address.
 *
 * Strategy:
 *   1. Check VMA permission — if readable, direct memcpy.
 *   2. Otherwise read via /proc/self/mem (no permission change).
 *
 * Returns 0 on success, -1 on failure.
 */
int read_target_safe(void* target, void* buf, size_t len) {
    /* If page is already readable, just memcpy */
    if (page_has_read_perm((uintptr_t)target)) {
        memcpy(buf, target, len);
        return 0;
    }

    /* Page not readable (XOM / --x) — mprotect to add read, then memcpy */
    uintptr_t page_start = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) == 0) {
        memcpy(buf, target, len);
        /* mprotect already set r-x, no need to restore */
        return 0;
    }

    hook_log("read_target_safe: mprotect failed errno=%d", errno);
    return -1;
}

/* --- Pool permission management --- */

/*
 * Restore a target code page to R-X after patching.
 * Try 0x2000 (two pages) first in case the hook spans a page boundary.
 * Fall back to two separate 0x1000 calls when the range crosses a VMA
 * boundary (mprotect returns EINVAL for the 2-page span but succeeds per page).
 */
void restore_page_rx(uintptr_t page_start) {
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) != 0) {
        mprotect((void*)page_start, 0x1000, PROT_READ | PROT_EXEC);
        mprotect((void*)(page_start + 0x1000), 0x1000, PROT_READ | PROT_EXEC);
    }
}

/* --- Entry free list management --- */

HookEntry* alloc_entry(void) {
    HookEntry* entry = NULL;

    if (g_engine.free_list) {
        /* Reuse from free list, preserving pool memory allocations */
        entry = g_engine.free_list;
        g_engine.free_list = entry->next;

        void* saved_trampoline = entry->trampoline;
        size_t saved_trampoline_alloc = entry->trampoline_alloc;
        void* saved_thunk = entry->thunk;
        size_t saved_thunk_alloc = entry->thunk_alloc;

        memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)hook_alloc(sizeof(HookEntry));
        if (entry) memset(entry, 0, sizeof(HookEntry));
    }

    return entry;
}

void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* --- Cache flush --- */

void hook_flush_cache(void* start, size_t size) {
    __builtin___clear_cache((char*)start, (char*)start + size);
}

/* --- wxshadow (two-step shadow page patching) --- */

/*
 * Find the VMA containing addr by parsing /proc/self/maps.
 * Returns 0 on success, -1 if not found.
 */
static int find_containing_vma(uintptr_t addr, uintptr_t* vma_start, size_t* vma_size) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                *vma_start = start;
                *vma_size = end - start;
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/*
 * Split PMD block / contiguous PTE group by mprotect on the ENTIRE
 * containing VMA + COW write.  Operating on the full VMA boundary
 * avoids VMA fragmentation in /proc/self/maps.
 *
 * The transient RWX window is unavoidable but:
 *   - wxshadow itself causes VMA splits (more detectable than RWX)
 *   - The window is microseconds (single volatile write)
 *   - Without this, wxshadow fails on contiguous PTE pages
 *
 * Returns 0 on success, -1 on failure.
 */
static int pmd_split_cow(void* addr) {
    uintptr_t vma_start = 0;
    size_t vma_size = 0;

    if (find_containing_vma((uintptr_t)addr, &vma_start, &vma_size) != 0) {
        hook_log("pmd_split_cow: VMA not found for addr=%p", addr);
        return -1;
    }

    /* mprotect the entire VMA to rwx — no VMA split */
    if (mprotect((void*)vma_start, vma_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        hook_log("pmd_split_cow: mprotect(rwx) failed errno=%d", errno);
        return -1;
    }

    /* Write original byte back to trigger COW + split contiguous PTE group.
     * The write fault handler splits PMD block entries AND clears the
     * contiguous bit on ARM64 PTE groups before creating the COW copy. */
    *(volatile uint8_t*)addr = *(volatile uint8_t*)addr;

    /* Restore entire VMA to r-x — no VMA split */
    mprotect((void*)vma_start, vma_size, PROT_READ | PROT_EXEC);

    hook_log("pmd_split_cow: COW triggered for addr=%p (VMA=%p-%p)",
             addr, (void*)vma_start, (void*)(vma_start + vma_size));
    return 0;
}

/*
 * Stealth-patch target address using wxshadow shadow pages:
 *   PATCH — one-step: create shadow + write buf + activate (--x)
 *
 * prctl(PR_WXSHADOW_PATCH, pid, addr, buf, len)
 * Tries pid=0 first, then getpid() as fallback.
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
int wxshadow_patch(void* addr, const void* buf, size_t len) {
    int ret;

    ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
    }

    if (ret != 0) {
        /* PATCH failed — likely 2MB section (PMD) mapping.
         * wxshadow only supports 4KB PTE-mapped pages.
         *
         * Split the PMD by triggering COW on the target page.  We must
         * mprotect the ENTIRE containing VMA (not just the target page)
         * to avoid creating a VMA split visible in /proc/self/maps.
         * V-OS detection scans /proc/self/maps for unexpected VMA splits
         * in libart.so — mprotecting a sub-range would fragment the VMA. */
        hook_log("wxshadow PATCH failed (errno=%d), trying PMD split + COW for addr=%p", errno, addr);

        if (pmd_split_cow(addr) == 0) {
            ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
            if (ret != 0) {
                ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
            }
        }

        if (ret != 0) {
            hook_log("wxshadow PATCH failed after COW: addr=%p errno=%d", addr, errno);
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        hook_log("wxshadow PATCH succeeded after PMD split: addr=%p", addr);
    }

    hook_log("wxshadow stealth patch OK: addr=%p len=%zu", addr, len);
    return 0;
}

/*
 * Release a wxshadow patch by its exact patch start address.
 * The supplied address must match the addr argument previously passed to PATCH.
 */
int wxshadow_release(void* addr) {
    int ret = prctl(PR_WXSHADOW_RELEASE, 0, (uintptr_t)addr, 0, 0);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_RELEASE, getpid(), (uintptr_t)addr, 0, 0);
    }
    if (ret != 0) {
        hook_log("wxshadow_release: failed for addr=%p (errno=%d)", addr, errno);
        return HOOK_ERROR_WXSHADOW_FAILED;
    }
    return 0;
}

/*
 * wxshadow 同页 LDR literal livelock 修复
 *
 * wxshadow 通过 R/X PTE 互斥保护页面。如果同页上有 PC-relative literal load
 * (LDR Rt, #imm)，该指令的 fetch(X) 和 data read(R) 都在同一保护页上，
 * 导致无限 page fault 循环 (livelock)。
 *
 * 修复: 将同页 LDR literal 替换为 B → trampoline，trampoline 里嵌入常量值。
 * B 指令只需 X(fetch)，不读数据，不触发 R/X 切换。
 */

/* ARM64 LDR literal 编码检测:
 * LDR Wt:  opc=00 V=0 → 0x18000000 mask 0xFF000000
 * LDR Xt:  opc=01 V=0 → 0x58000000 mask 0xFF000000
 * LDR St:  opc=00 V=1 → 0x1C000000 mask 0xFF000000
 * LDR Dt:  opc=01 V=1 → 0x5C000000 mask 0xFF000000
 * LDR Qt:  opc=10 V=1 → 0x9C000000 mask 0xFF000000
 * PRFM:    opc=11 V=0 → 0xD8000000 (prefetch, 不需要修复)
 */
static int is_ldr_literal(uint32_t insn) {
    uint32_t top8 = insn & 0xFF000000;
    return top8 == 0x18000000 || top8 == 0x58000000 ||
           top8 == 0x1C000000 || top8 == 0x5C000000 ||
           top8 == 0x9C000000;
}

/* 从 LDR literal 指令中提取 PC-relative 目标地址 */
static uint64_t ldr_literal_target(uint64_t pc, uint32_t insn) {
    int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
    if (imm19 & (1 << 18)) imm19 -= (1 << 19);  /* sign extend */
    return pc + (int64_t)imm19 * 4;
}

/* LDR literal 加载的数据大小 (bytes) */
static int ldr_literal_size(uint32_t insn) {
    uint32_t top8 = insn & 0xFF000000;
    if (top8 == 0x18000000 || top8 == 0x1C000000) return 4;  /* W/S */
    if (top8 == 0x58000000 || top8 == 0x5C000000) return 8;  /* X/D */
    if (top8 == 0x9C000000) return 16; /* Q */
    return 0;
}

/* 是否为 SIMD/FP LDR literal (V=1) */
static int ldr_literal_is_simd(uint32_t insn) {
    return (insn & 0x04000000) != 0;  /* bit 26 = V */
}

/*
 * 扫描 wxshadow 保护页上的同页 LDR literal 指令并修复。
 * 对每条同页 LDR literal: 读取常量值 → 分配 trampoline → 嵌入常量 + 跳回 →
 * wxshadow patch 原始 LDR 为 B trampoline。
 *
 * patch_addr: wxshadow patch 的目标地址
 * patch_len: patch 覆盖的字节数 (这些字节内的 LDR 不需要修复)
 */
void wxshadow_relocate_same_page_ldr_literals(void* patch_addr, int patch_len) {
    uintptr_t page_start = (uintptr_t)patch_addr & ~0xFFFUL;
    uintptr_t page_end = page_start + 0x1000;
    uintptr_t patch_start = (uintptr_t)patch_addr;
    uintptr_t patch_end = patch_start + patch_len;
    int fixed = 0;
    int scanned = 0;

    hook_log("[stealth_ldr_reloc] scanning page %#lx for patch at %p len=%d",
             (unsigned long)page_start, patch_addr, patch_len);

    for (uintptr_t pc = page_start; pc < page_end; pc += 4) {
        scanned++;
        /* 跳过被 patch 覆盖的区域 */
        if (pc >= patch_start && pc < patch_end) continue;

        uint32_t insn = *(uint32_t*)pc;
        if (!is_ldr_literal(insn)) continue;

        uint64_t target = ldr_literal_target(pc, insn);
        uintptr_t target_page = target & ~0xFFFUL;
        if (target_page != page_start) continue;

        /* 同页 LDR literal — 需要修复 */
        int data_size = ldr_literal_size(insn);
        int is_simd = ldr_literal_is_simd(insn);
        uint32_t rt = insn & 0x1F;

        /* 读取原始常量值 */
        uint8_t literal_data[16];
        memcpy(literal_data, (void*)target, data_size);

        /* 分配 trampoline (48 bytes 足够: 加载常量 + 跳回)
         * B 指令范围 ±128MB，必须用 hook_alloc_near_range 严格限制。
         * 分配失败意味着该 LDR 无法修复 → wxshadow 会 livelock → 必须警告。 */
        void* tramp = hook_alloc_near_range(48, (void*)pc, 0x8000000 /* ±128MB */);
        if (!tramp) {
            hook_log("\033[31m[stealth_ldr_reloc] CRITICAL: alloc trampoline FAILED for LDR at %#lx "
                     "(no memory within ±128MB). This LDR will livelock under wxshadow!\033[0m",
                     (unsigned long)pc);
            continue;
        }

        Arm64Writer w;
        arm64_writer_init(&w, tramp, (uint64_t)tramp, 48);

        if (is_simd) {
            /* SIMD: LDR St/Dt/Qt, [PC, #8] → skip over embedded data → B back
             * 编码: opc[31:30] 0 11 100 imm19 Rt
             * imm19 = (data_offset) / 4, data 紧跟在 B 指令后面 */
            /* LDR Vt, #data (PC+8 = skip B insn) */
            uint32_t opc = (insn >> 30) & 3;
            uint32_t ldr_enc = (opc << 30) | 0x1C000000 | (2 << 5) | rt;  /* imm19=2 → PC+8 */
            arm64_writer_put_insn(&w, ldr_enc);
            /* B back to pc+4 */
            int64_t back_offset = (int64_t)(pc + 4) - (int64_t)((uint64_t)tramp + 4);
            arm64_writer_put_b_imm(&w, (uint64_t)tramp + 4 + back_offset);
            /* 嵌入常量 */
            for (int i = 0; i < data_size; i += 4) {
                arm64_writer_put_insn(&w, *(uint32_t*)(literal_data + i));
            }
        } else {
            /* GPR: 用 LDR Xt/Wt, [PC, #8] 同样的方式 */
            uint32_t opc = (insn >> 30) & 3;
            uint32_t ldr_enc = (opc << 30) | 0x18000000 | (2 << 5) | rt;  /* imm19=2 → PC+8 */
            arm64_writer_put_insn(&w, ldr_enc);
            /* B back */
            int64_t back_offset = (int64_t)(pc + 4) - (int64_t)((uint64_t)tramp + 4);
            arm64_writer_put_b_imm(&w, (uint64_t)tramp + 4 + back_offset);
            /* 嵌入常量 (4 or 8 bytes, padding to 4-byte align) */
            for (int i = 0; i < data_size; i += 4) {
                arm64_writer_put_insn(&w, *(uint32_t*)(literal_data + i));
            }
        }

        arm64_writer_flush(&w);
        arm64_writer_clear(&w);

        /* 构造 B 指令跳到 trampoline */
        int64_t b_offset = (int64_t)(uint64_t)tramp - (int64_t)pc;
        if (b_offset < -0x8000000 || b_offset > 0x7FFFFFC) {
            hook_log("[stealth_ldr_reloc] B range exceeded for LDR at %#lx → tramp %p",
                     (unsigned long)pc, tramp);
            continue;
        }
        uint32_t b_insn = 0x14000000 | (((uint32_t)(b_offset >> 2)) & 0x03FFFFFF);

        /* wxshadow patch: 替换 LDR literal 为 B trampoline */
        if (wxshadow_patch((void*)pc, &b_insn, 4) != 0) {
            hook_log("[stealth_ldr_reloc] wxshadow_patch failed for LDR at %#lx", (unsigned long)pc);
            continue;
        }

        fixed++;
        hook_log("[stealth_ldr_reloc] fixed LDR at %#lx → tramp %p (data_size=%d, %s, rt=%d)",
                 (unsigned long)pc, tramp, data_size, is_simd ? "SIMD" : "GPR", rt);
    }

    if (fixed > 0) {
        hook_log("[stealth_ldr_reloc] fixed %d same-page LDR literals on page %#lx",
                 fixed, (unsigned long)page_start);
    }
}

/* --- Jump writing and allocation --- */

/* BRK 填充 + 清理 writer，返回写入字节数 */
static int finalize_jump_writer(Arm64Writer* w) {
    while (arm64_writer_offset(w) < MIN_HOOK_SIZE && arm64_writer_can_write(w, 4)) {
        arm64_writer_put_brk_imm(w, 0xFFFF);
    }
    int bytes_written = (int)arm64_writer_offset(w);
    arm64_writer_clear(w);
    return bytes_written;
}

/*
 * Write a trampoline jump-back using a dynamically chosen scratch register.
 *
 * Analyzes which GPRs are written by the relocated instructions (via
 * written_regs bitmask) and picks a scratch register that won't be
 * clobbered:
 *   - Prefer X17 (IP1, intra-procedure-call scratch)
 *   - Fall back to X16 (IP0) if X17 is written
 *   - If both are written, still use X17 (extremely rare edge case)
 */
int write_jump_back(void* dst, void* target, uint32_t written_regs) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Reg scratch;
    if (!(written_regs & (1u << 17))) {
        scratch = ARM64_REG_X17;    /* Prefer X17 */
    } else if (!(written_regs & (1u << 16))) {
        scratch = ARM64_REG_X16;    /* Fall back to X16 */
    } else {
        scratch = ARM64_REG_X17;    /* Both written — use X17, log warning */
        hook_log("[hook] WARNING: both X16 and X17 written by relocated code, "
                 "X17 may be clobbered");
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_mov_reg_imm(&w, scratch, (uint64_t)target);
    arm64_writer_put_br_reg(&w, scratch);

    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    return finalize_jump_writer(&w);
}

/* Write a jump to target at the given execution PC.
 * 优先 ADRP+ADD+BR (12B, wxshadow 安全, 需 ±4GB),
 * fallback 到 MOVZ+MOVK+BR (16B, 无限制)。
 *
 * exec_pc: the address where this code will actually execute.
 *   - For direct patching (stealth=0): exec_pc == dst
 *   - For wxshadow (stealth=1): exec_pc == hook target addr (not the tmp buffer)
 *   This ensures ADRP offsets are correct for the actual execution context. */
int hook_write_jump_at(void* dst, uint64_t exec_pc, void* target) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, exec_pc, MIN_HOOK_SIZE);

    int64_t pc_rel = (int64_t)(uint64_t)target - (int64_t)exec_pc;
    int64_t b_range = (int64_t)128 << 20;  /* ±128MB */
    int64_t adrp_range = (int64_t)1 << 32; /* ±4GB */

    if (pc_rel > -b_range && pc_rel < b_range && (pc_rel & 3) == 0) {
        /* B (4 字节, ±128MB) — 最小 patch，只覆盖 1 条指令 */
        arm64_writer_put_b_imm(&w, (uint64_t)target);
    } else if (pc_rel > -adrp_range && pc_rel < adrp_range) {
        /* ADRP+ADD+BR (12 字节, ±4GB) */
        arm64_writer_put_adrp_add_br(&w, ARM64_REG_X16, (uint64_t)target);
    } else {
        /* Fallback: MOVZ+MOVK+BR (16+ 字节) */
        arm64_writer_put_branch_address(&w, (uint64_t)target);
    }

    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    /* 不 pad BRK — 返回实际字节数 (B=4, ADRP=12, MOVZ=16)。
     * 调用方（patch_target/OAT）按返回值决定 overwrite 大小。 */
    int bytes_written = (int)arm64_writer_offset(&w);
    arm64_writer_clear(&w);
    return bytes_written;
}

/* Backward-compatible wrapper: exec_pc == dst (for direct patching). */
int hook_write_jump(void* dst, void* target) {
    return hook_write_jump_at(dst, (uint64_t)dst, target);
}

/* Allocate from executable memory pool */
/* 从指定 pool 分配 */
static void* alloc_from_pool(ExecPool* pool, size_t size) {
    if (pool->used + size > pool->size) return NULL;
    void* ptr = (uint8_t*)pool->base + pool->used;
    pool->used += size;
    return ptr;
}

/* 参数化版本: 搜索 target ±max_range 范围内的 maps 空隙，mmap RWX 内存。
 * target=NULL 时退化为普通 mmap(NULL)。
 * 返回 mmap 得到的指针，MAP_FAILED 表示失败。
 *
 * 设计要点：/proc/self/maps 可能被 KPM 隐藏部分 VMA（如 wwb_hook_pool）。
 * 因此扫 gap 只是缩范围避开系统 VMA，真正判定空位交给 MAP_FIXED_NOREPLACE
 * ——该 flag 走内核 VMA 树，绕过 /proc 层过滤。EEXIST → 在同 gap 内按
 * alloc_size 步进跳过隐藏占用，而不是 fallback 到任意地址（会飞出 ±range）。 */
void* hook_mmap_near_range(void* target, size_t alloc_size, int64_t max_range) {
    if (!target) {
        return mmap(NULL, alloc_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    long page_size_l = sysconf(_SC_PAGESIZE);
    size_t page_size = page_size_l > 0 ? (size_t)page_size_l : 4096u;

    uintptr_t target_addr = (uintptr_t)target;

    /* 搜索区间 [search_lo, search_hi) */
    uintptr_t search_lo = 0;
    if (target_addr > (uintptr_t)max_range)
        search_lo = (target_addr - (uintptr_t)max_range + page_size - 1) & ~(page_size - 1);
    else
        search_lo = page_size;
    uintptr_t search_hi = target_addr + (uintptr_t)max_range;
    if (search_hi < target_addr) search_hi = UINTPTR_MAX;

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) {
        hook_log("hook_mmap_near_range: failed to open /proc/self/maps");
        return MAP_FAILED;
    }

    #define MAX_GAPS 64
    struct { uintptr_t start; uintptr_t end; int64_t dist; } gaps[MAX_GAPS];
    int num_gaps = 0;

    char line[512];
    uintptr_t prev_end = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t vma_start = 0, vma_end = 0;
        if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) < 2) continue;

        if (prev_end > 0 && vma_start > prev_end) {
            uintptr_t gs = prev_end;
            uintptr_t ge = vma_start;

            if (gs < search_hi && ge > search_lo) {
                if (gs < search_lo) gs = search_lo;
                if (ge > search_hi) ge = search_hi;
                gs = (gs + page_size - 1) & ~(page_size - 1);
                ge = ge & ~(page_size - 1);

                if (ge > gs && (ge - gs) >= alloc_size) {
                    int64_t d;
                    if (target_addr >= gs && target_addr < ge) d = 0;
                    else if (target_addr < gs) d = (int64_t)(gs - target_addr);
                    else d = (int64_t)(target_addr - ge);

                    if (num_gaps < MAX_GAPS) {
                        gaps[num_gaps].start = gs;
                        gaps[num_gaps].end = ge;
                        gaps[num_gaps].dist = d;
                        num_gaps++;
                    }
                }
            }
        }
        prev_end = vma_end;
    }
    fclose(f);

    /* 按离 target 的距离排序，近的 gap 先扫 */
    for (int i = 1; i < num_gaps; i++) {
        __typeof__(gaps[0]) tmp = gaps[i];
        int j = i - 1;
        while (j >= 0 && gaps[j].dist > tmp.dist) {
            gaps[j + 1] = gaps[j];
            j--;
        }
        gaps[j + 1] = tmp;
    }

    #ifndef MAP_FIXED_NOREPLACE
    #define MAP_FIXED_NOREPLACE 0x100000
    #endif

    /* 单 gap 探测上限：每次步进 alloc_size，64 步 × 64KB = 4MB 覆盖，足够跨过
     * 隐藏的老 pool。更大的 gap 也会被系统 VMA 切断，不用担心单 gap 过大。 */
    const int MAX_STEPS_PER_GAP = 64;

    for (int i = 0; i < num_gaps; i++) {
        uintptr_t gs = gaps[i].start;
        uintptr_t ge = gaps[i].end;
        uintptr_t gap_last = (ge - alloc_size) & ~(page_size - 1);
        if (gap_last < gs) continue;

        /* 起点：gap 内离 target 最近的对齐页 */
        uintptr_t origin;
        if (target_addr >= gs && target_addr <= gap_last)
            origin = target_addr & ~(page_size - 1);
        else if (target_addr < gs)
            origin = gs;
        else
            origin = gap_last;

        int had_unsupported = 0;
        int steps = 0;
        /* 以 origin 为中心，按 alloc_size 步长交替向 +/- 方向扫 */
        for (int step = 0; step < MAX_STEPS_PER_GAP * 2; step++) {
            int64_t off_steps;
            if (step == 0) off_steps = 0;
            else if (step & 1) off_steps = (step + 1) / 2;
            else off_steps = -(step / 2);

            uintptr_t cand;
            if (off_steps >= 0) {
                uintptr_t absoff = (uintptr_t)off_steps * (uintptr_t)alloc_size;
                if (origin > gap_last || absoff > gap_last - origin) continue;
                cand = origin + absoff;
            } else {
                uintptr_t absoff = (uintptr_t)(-off_steps) * (uintptr_t)alloc_size;
                if (origin < gs || absoff > origin - gs) continue;
                cand = origin - absoff;
            }
            cand &= ~(page_size - 1);
            if (cand < gs || cand > gap_last) continue;

            if (++steps > MAX_STEPS_PER_GAP) break;

            errno = 0;
            void* ptr = mmap((void*)cand, alloc_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (ptr != MAP_FAILED) {
                /* 内核不认 MAP_FIXED_NOREPLACE 时会忽略该 flag，返回别的地址 */
                if (ptr != (void*)cand) {
                    munmap(ptr, alloc_size);
                    had_unsupported = 1;
                    break;
                }
                hook_log("hook_mmap_near_range: OK at %p for target %p (range=±%lld, gap#%d step=%d)",
                         ptr, target, (long long)max_range, i, steps);
                return ptr;
            }
            if (errno == EEXIST) continue;  /* 隐藏 VMA 或已占用，步进跳过 */
            if (errno == ENOSYS || errno == EINVAL) {
                had_unsupported = 1;
                break;
            }
            break;  /* ENOMEM 等其他错误，换下一个 gap */
        }

        /* 老内核 fallback：hint mmap + 距离校验（保留原行为） */
        if (had_unsupported) {
            void* ptr = mmap((void*)origin, alloc_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (ptr != MAP_FAILED) {
                int64_t d = (int64_t)((uint8_t*)ptr - (uint8_t*)target);
                if (d >= -max_range && d < max_range) {
                    hook_log("hook_mmap_near_range: OK (hint) at %p for target %p (range=±%lld)",
                             ptr, target, (long long)max_range);
                    return ptr;
                }
                munmap(ptr, alloc_size);
            }
        }
    }

    hook_log("hook_mmap_near_range: all %d gaps exhausted for target %p (range=±%lld)",
             num_gaps, target, (long long)max_range);
    return MAP_FAILED;
    #undef MAX_GAPS
}

/* 公共函数: 默认 ±4GB (ADRP range) 的 wrapper，保持 ABI 兼容 */
void* hook_mmap_near(void* target, size_t alloc_size) {
    return hook_mmap_near_range(target, alloc_size, (int64_t)1 << 32);
}

/* 创建新 pool，限定 ±max_range 范围，pool 大小 pool_size 字节。
 * pool_size 必须是 page_size 的整数倍。传 0 时退化为 EXEC_POOL_SIZE。 */
static ExecPool* create_pool_near_range_sized(void* target, int64_t max_range, size_t pool_size) {
    if (g_engine.pool_count >= MAX_EXEC_POOLS) {
        hook_log("create_pool_near_range_sized: pool count %d reached MAX_EXEC_POOLS", g_engine.pool_count);
        return NULL;
    }
    if (pool_size == 0) pool_size = EXEC_POOL_SIZE;

    void* ptr = hook_mmap_near_range(target, pool_size, max_range);
    if (ptr == MAP_FAILED) return NULL;

    /* 标记 VMA 名称便于 /proc/self/maps 识别 */
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)ptr, pool_size,
          (unsigned long)"wwb_hook_pool");

    ExecPool* pool = &g_engine.pools[g_engine.pool_count++];
    pool->base = ptr;
    pool->size = pool_size;
    pool->used = 0;
    return pool;
}

/* 创建新 pool，限定 ±max_range 范围，使用默认 EXEC_POOL_SIZE */
static ExecPool* create_pool_near_range(void* target, int64_t max_range) {
    return create_pool_near_range_sized(target, max_range, EXEC_POOL_SIZE);
}

/* 创建新 pool（默认 ±4GB）— 保持现有调用方兼容 */
static ExecPool* create_pool_near(void* target) {
    return create_pool_near_range(target, (int64_t)1 << 32);
}


/* 判断 pool 是否在 target 的 ADRP 范围内 (±4GB) */
static int pool_in_adrp_range(ExecPool* pool, void* target) {
    int64_t dist = (int64_t)((uint8_t*)pool->base - (uint8_t*)target);
    int64_t range = (int64_t)1 << 32;
    return dist > -range && dist < range;
}

/* 判断 pool 是否在 target 的指定范围内 */
static int pool_in_range(ExecPool* pool, void* target, int64_t range) {
    int64_t dist = (int64_t)((uint8_t*)pool->base - (uint8_t*)target);
    return dist > -range && dist < range;
}


int hook_rebuild_trampoline(void* trampoline, size_t trampoline_size,
                            const void* orig_bytes, uint64_t orig_pc,
                            void* jump_back_target) {
    if (!trampoline || !orig_bytes || !jump_back_target) return -1;

    uint32_t written_regs = 0;
    size_t relocated_size = hook_relocate_instructions(
        orig_bytes, orig_pc, trampoline, 4, &written_regs);

    int jump_len = write_jump_back(
        (uint8_t*)trampoline + relocated_size,
        jump_back_target, written_regs);
    if (jump_len < 0) return jump_len;

    size_t total = relocated_size + (size_t)jump_len;
    hook_flush_cache(trampoline, total);
    return (int)total;
}

int hook_register_pool(void* base, size_t size) {
    if (!g_engine.initialized || !base || size == 0) return -1;
    if (g_engine.pool_count >= MAX_EXEC_POOLS) {
        hook_log("hook_register_pool: pool slots exhausted (%d)", g_engine.pool_count);
        return -1;
    }
    ExecPool* pool = &g_engine.pools[g_engine.pool_count++];
    pool->base = base;
    pool->size = size;
    pool->used = 0;
    hook_log("hook_register_pool: base=%p size=%zu (pool #%d)", base, size, g_engine.pool_count - 1);
    return 0;
}

void* hook_alloc(size_t size) {
    if (!g_engine.initialized) return NULL;
    size = (size + 7) & ~7;

    /* 先试初始 pool */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
        g_engine.exec_mem_used += size;
        return ptr;
    }

    /* 试其他 pool */
    for (int i = 0; i < g_engine.pool_count; i++) {
        void* ptr = alloc_from_pool(&g_engine.pools[i], size);
        if (ptr) return ptr;
    }

    /* 创建新 pool（无 hint） */
    ExecPool* pool = create_pool_near(NULL);
    return pool ? alloc_from_pool(pool, size) : NULL;
}

void* hook_alloc_near(size_t size, void* target) {
    if (!g_engine.initialized) return NULL;
    size = (size + 7) & ~7;

    int64_t b_range = (int64_t)128 << 20;     /* ±128MB — B 指令 4B patch */
    int64_t adrp_range = (int64_t)1 << 32;    /* ±4GB  — ADRP 12B patch */

    /* ── Tier 1: ±128MB (B 指令, 4B patch) ── */

    /* 1a: 现有 pool 中找 ±128MB 内有空间的 */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        int64_t dist = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        if (dist > -b_range && dist < b_range) {
            void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
            g_engine.exec_mem_used += size;
            return ptr;
        }
    }
    for (int i = 0; i < g_engine.pool_count; i++) {
        if (pool_in_range(&g_engine.pools[i], target, b_range)) {
            void* ptr = alloc_from_pool(&g_engine.pools[i], size);
            if (ptr) return ptr;
        }
    }

    /* 1b: 现有 pool 全部不在 ±128MB 或已满 → 创建 ±128MB 新 pool */
    {
        ExecPool* pool = create_pool_near_range(target, b_range);
        if (pool) {
            void* ptr = alloc_from_pool(pool, size);
            if (ptr) return ptr;
        }
    }

    /* ── Tier 2: ±4GB (ADRP, 12B patch) ── */

    /* 2a: 现有 pool 中找 ±4GB 内有空间的 */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        int64_t dist = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        if (dist > -adrp_range && dist < adrp_range) {
            void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
            g_engine.exec_mem_used += size;
            return ptr;
        }
    }
    for (int i = 0; i < g_engine.pool_count; i++) {
        if (pool_in_range(&g_engine.pools[i], target, adrp_range)) {
            void* ptr = alloc_from_pool(&g_engine.pools[i], size);
            if (ptr) return ptr;
        }
    }

    /* 2b: 现有 pool 全部不在 ±4GB → 创建 ±4GB 新 pool */
    {
        ExecPool* pool = create_pool_near_range(target, adrp_range);
        if (pool) {
            void* ptr = alloc_from_pool(pool, size);
            if (ptr) return ptr;
        }
    }

    /* ── Tier 3: 任意距离 (MOVZ 16~20B patch) ── */
    void* fallback = hook_alloc(size);
    if (fallback) return fallback;

    /* 所有 pool 全满且无法创建新 pool */
    ExecPool* any_pool = create_pool_near(NULL);
    return any_pool ? alloc_from_pool(any_pool, size) : NULL;
}

/* 在 target ±max_range 范围内分配可执行内存。
 * 与 hook_alloc_near 不同: 不会 fallback 到远距离 generic pool。
 * 用途: stealth2 B 指令 ±128MB / stealth1 wxshadow ADRP ±4GB。
 *
 * Phase 2 采用分级池大小策略：优先尝试 64KB (EXEC_POOL_SIZE) 以摊薄后续调用成本，
 * 失败则逐级降级到 16KB、单页，只要能装下本次请求的 size 就行。
 * 这能应对 mapping 紧凑的进程（ART JIT/boot image 堆叠时 ±128MB 内可能连一个 64KB
 * 空隙都没有，但 4KB~16KB 的小空隙往往存在）。 */
void* hook_alloc_near_range(size_t size, void* target, int64_t max_range) {
    if (!g_engine.initialized || !target) return NULL;
    size = (size + 7) & ~7;

    /* Phase 1: 初始 pool */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        int64_t dist = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        if (dist > -max_range && dist < max_range) {
            void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
            g_engine.exec_mem_used += size;
            return ptr;
        }
    }

    /* Phase 1b: 额外 pool */
    for (int i = 0; i < g_engine.pool_count; i++) {
        ExecPool* pool = &g_engine.pools[i];
        if (pool_in_range(pool, target, max_range) && pool->used + size <= pool->size) {
            return alloc_from_pool(pool, size);
        }
    }

    /* Phase 2: 分级创建 pool — 64KB → 16KB → 单页 */
    long page_size_l = sysconf(_SC_PAGESIZE);
    size_t page_size = page_size_l > 0 ? (size_t)page_size_l : 4096u;
    /* 本次请求 size 的 page 对齐下界，低于这个值的 pool size 不用尝试 */
    size_t min_pool = (size + page_size - 1) & ~(page_size - 1);

    const size_t pool_sizes[] = {
        EXEC_POOL_SIZE,        /* 64KB: 首选，可摊薄后续小请求 */
        16u * 1024u,           /* 16KB: 空隙较小时退路 */
        page_size,             /* 单页: 最后兜底 */
    };
    for (size_t i = 0; i < sizeof(pool_sizes) / sizeof(pool_sizes[0]); i++) {
        size_t ps = pool_sizes[i];
        if (ps < min_pool) continue;
        /* 避免重复尝试相同 size（例如 page_size==16KB 时前两档退化同值） */
        int duplicate = 0;
        for (size_t j = 0; j < i; j++) {
            if (pool_sizes[j] == ps) { duplicate = 1; break; }
        }
        if (duplicate) continue;

        ExecPool* pool = create_pool_near_range_sized(target, max_range, ps);
        if (pool) {
            void* ptr = alloc_from_pool(pool, size);
            if (ptr) return ptr;
        }
    }

    /* 不 fallback 到远距离 — 调用方需要保证距离 */
    hook_log("hook_alloc_near_range: FAILED for target %p within ±%lld (request size=%zu, min_pool=%zu)",
             target, (long long)max_range, size, min_pool);
    return NULL;
}


/* --- Instruction relocation --- */

/* Relocate instructions from a pre-read buffer (src_buf) to dst, using
 * src_pc as the original PC for PC-relative fixups.
 *
 * Separating src_buf from src_pc lets the caller read the original bytes
 * safely (e.g., via /proc/self/mem to bypass XOM) and then pass that buffer
 * here, while still computing correct relocations against the real address.
 *
 * Within-region branch fix: before the write loop we pre-create one writer
 * label per source instruction and record them in the relocator's region_labels
 * table.  Just before writing each instruction we place its label at the current
 * writer PC.  This allows arm64_relocator_write_one() to emit label-based
 * branches (rather than absolute branches to the now-overwritten original code)
 * for any PC-relative branch whose target lies inside [src_pc, src_pc+min_bytes). */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc, void* dst, size_t min_bytes, uint32_t* out_written_regs) {
    Arm64Writer w;
    Arm64Relocator r;

    arm64_writer_init(&w, dst, (uint64_t)dst, 256);
    arm64_relocator_init(&r, src_buf, src_pc, &w);
    if (min_bytes == INSN_SIZE) {
        r.preserve_call_return_to_original = 1;
        r.original_call_return_pc = src_pc + INSN_SIZE;
    }

    /* Pre-create one label per source instruction in the hook region. */
    int n = (int)(min_bytes / INSN_SIZE);
    if (n > ARM64_RELOC_MAX_REGION) n = ARM64_RELOC_MAX_REGION;
    r.region_end = src_pc + min_bytes;
    r.region_label_count = n;
    for (int i = 0; i < n; i++) {
        r.region_labels[i].src_pc = src_pc + (uint64_t)(i * INSN_SIZE);
        r.region_labels[i].label_id = arm64_writer_new_label_id(&w);
    }

    size_t src_offset = 0;
    int insn_idx = 0;
    while (src_offset < min_bytes) {
        /* Place this instruction's label at the current write position BEFORE
         * emitting the instruction so that backward references work immediately
         * and forward references are resolved during flush. */
        if (insn_idx < n)
            arm64_writer_put_label(&w, r.region_labels[insn_idx].label_id);

        if (arm64_relocator_read_one(&r) == 0) break;
        arm64_relocator_write_one(&r);
        src_offset += INSN_SIZE;
        insn_idx++;
    }

    /* Place labels for any instructions that were not reached (e.g. early EOI)
     * so that forward label references created before the loop exits are always
     * resolved to a valid (if imprecise) position. */
    for (int i = insn_idx; i < n; i++)
        arm64_writer_put_label(&w, r.region_labels[i].label_id);

    /* Flush pending label references (CBZ forward refs etc.) */
    arm64_writer_flush(&w);

    size_t written = arm64_writer_offset(&w);

    if (out_written_regs)
        *out_written_regs = r.written_regs;

    arm64_writer_clear(&w);
    arm64_relocator_clear(&r);

    return written;
}

/* --- Hook installation helpers --- */

HookEntry* setup_hook_entry(void* target) {
    /* Caller must hold g_engine.lock */

    /* Check if already hooked */
    if (find_hook(target)) {
        return NULL;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        return NULL;
    }

    entry->target = target;

    /* trampoline 不需要 near: jump-back 用 MOVZ+MOVK 绝对跳转，
     * thunk 也通过 MOVZ+MOVK 加载 trampoline 地址。节省 nearby pool 空间。 */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        return NULL;
    }

    /* Save original bytes — use XOM-safe read */
    if (read_target_safe(target, entry->original_bytes, MIN_HOOK_SIZE) != 0) {
        hook_log("setup_hook_entry: target %p is not readable, aborting", target);
        free_entry(entry);
        return NULL;
    }
    entry->original_size = MIN_HOOK_SIZE;

    return entry;
}

int build_trampoline(HookEntry* entry) {
    /* Relocate original instructions to trampoline.
     * 用 original_size（= 实际 patch 大小，ADRP=12 或 MOVZ=16），不用 MIN_HOOK_SIZE。 */
    uint32_t written_regs = 0;
    size_t overwrite = entry->original_size;
    size_t relocated_size = hook_relocate_instructions(
        entry->original_bytes, (uint64_t)entry->target,
        entry->trampoline, overwrite, &written_regs);

    /* Write jump back to original code after the relocated instructions */
    void* jump_back_target = (uint8_t*)entry->target + overwrite;
    int jump_result = write_jump_back(
        (uint8_t*)entry->trampoline + relocated_size,
        jump_back_target, written_regs);

    return jump_result;
}

/* 查找同 inode + offset 覆盖 target 的 rw- 兄弟映射 (ART JIT cache dual-view).
 * 返回 target 对应的 writable 地址, 无则 NULL.
 * len: 要写入的字节数, 用于校验整段都在兄弟 VMA 内. */
void* find_rw_sibling(void* target, size_t len) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return NULL;

    uintptr_t t = (uintptr_t)target;
    uintptr_t rx_base = 0, rx_off = 0;
    unsigned long rx_inode = 0;
    int found_rx = 0;
    char line[512];

    int target_shared = 0;
    uintptr_t rx_end = 0;

    /* Pass 1: 找包含 target 的 VMA, 记 inode + file offset + shared 标志 */
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        unsigned long off, inode;
        char perms[8];
        int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %lu",
                       &start, &end, perms, &off, &inode);
        if (n == 5 && t >= start && t < end && inode != 0) {
            rx_base = start;
            rx_end = end;
            rx_off = off;
            rx_inode = inode;
            target_shared = (perms[3] == 's');
            found_rx = 1;
            break;
        }
    }
    if (!found_rx) {
        fclose(fp);
        return NULL;
    }

    /* 只对 shared 映射启用 rw-sibling 直写:
     * private 映射的 rw 段 (如 .data) 是独立 CoW 物理页, 写入不影响 r-x 段。
     * shared 映射 (如 ART JIT cache dual-view memfd) 两侧共享物理页, 才可直写。 */
    if (!target_shared) {
        fclose(fp);
        return NULL;
    }

    /* target..target+len 必须全部在当前 VMA 内 (跨 VMA memcpy 会 SEGV 或写错数据) */
    if (t + len > rx_end) {
        fclose(fp);
        return NULL;
    }

    uintptr_t file_off = rx_off + (t - rx_base);

    /* Pass 2: 找同 inode 且 perms='w' + 's' (shared write) 的 VMA, 覆盖 file_off */
    rewind(fp);
    void* result = NULL;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        unsigned long off, inode;
        char perms[8];
        int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %lu",
                       &start, &end, perms, &off, &inode);
        if (n != 5) continue;
        if (inode != rx_inode) continue;
        if (perms[1] != 'w') continue;
        if (perms[3] != 's') continue;
        uintptr_t v_file_start = off;
        uintptr_t v_file_end = off + (end - start);
        /* 整段 patch 都要在兄弟 VMA 内 */
        if (file_off >= v_file_start && file_off + len <= v_file_end) {
            result = (void*)(start + (file_off - off));
            break;
        }
    }
    fclose(fp);
    return result;
}

int patch_target(void* target, void* jump_dest, int stealth, HookEntry* entry) {
    int jump_result;

    if (stealth == 1) {
        /* wxshadow 模式: shadow 页写入.
         * 1. aligned(32) 防止 buf 跨页 (copy_from_user_via_pte 不支持跨页)
         * 2. hook_write_jump_at 用 target 的 PC 算 ADRP，而非 buf 的栈地址，
         *    使 target↔thunk 在 ±4GB 时走 ADRP+ADD+BR (12B) 而非 MOVZ (16B) */
        uint8_t jump_buf[MIN_HOOK_SIZE] __attribute__((aligned(32)));
        jump_result = hook_write_jump_at(jump_buf, (uint64_t)target, jump_dest);
        if (jump_result < 0) {
            return jump_result;
        }

        uintptr_t t = (uintptr_t)target;
        int ok = 0;

        if ((t & 0xFFF) + (uintptr_t)jump_result > 0x1000) {
            /* target 跨页: KPM copy_from_user_via_pte 单页限制. 分两段写, 顺序很关键:
             *   1. 先写第二页 (jump 尾部): target 首指令未变, CPU 继续原流程, 安全
             *   2. 再写第一页 (含 target 首指令 ADRP): 首指令 4B 原子写, CPU 一旦取到 ADRP
             *      整条 jump 序列已就位 (第二页的 BR 已先写好), 无半 jump 执行窗口
             * 失败回滚: 已写的第二页 wxshadow_release.
             * jump_result 最多 20B (MOVZ 4×4+BR), 最多跨 2 页. */
            size_t first_len = 0x1000 - (t & 0xFFF);
            size_t second_len = (size_t)jump_result - first_len;
            void* second_addr = (void*)(t + first_len);

            if (wxshadow_patch(second_addr, jump_buf + first_len, second_len) != 0) {
                hook_log("[STEALTH1] cross-page second segment failed target=%p", target);
                return HOOK_ERROR_WXSHADOW_FAILED;
            }
            if (wxshadow_patch(target, jump_buf, first_len) != 0) {
                hook_log("[STEALTH1] cross-page first segment failed target=%p, rolling back second", target);
                wxshadow_release(second_addr);
                return HOOK_ERROR_WXSHADOW_FAILED;
            }
            /* LDR literal relocate: 两页各扫一次 (shadow 页 R/X 互斥按页生效) */
            wxshadow_relocate_same_page_ldr_literals(target, (int)first_len);
            wxshadow_relocate_same_page_ldr_literals(second_addr, (int)second_len);
            ok = 1;
            hook_log("[STEALTH1] cross-page patch OK target=%p split=%zu+%zu", target, first_len, second_len);
        } else {
            if (wxshadow_patch(target, jump_buf, jump_result) == 0) {
                wxshadow_relocate_same_page_ldr_literals(target, jump_result);
                ok = 1;
            }
        }

        if (ok) {
            entry->stealth = 1;
            entry->original_size = jump_result;
            return 0;
        }
        /* stealth1 严格模式: wxshadow 失败拒绝降级到 mprotect。
         * 降级会直接修改原始内存字节 + RWX 权限变更，
         * CRC 校验 / /proc/self/maps 扫描均可检测。 */
        hook_log("\033[31m[STEALTH] wxshadow 失败 %p，拒绝降级 mprotect\033[0m", target);
        return HOOK_ERROR_WXSHADOW_FAILED;
    }

    /* Normal mode (stealth=0):
     * 先尝试找同 inode 的 rw-s 兄弟映射直写（ART JIT cache dual-view 场景）:
     *   - 执行侧 r-xs 无 VM_MAYWRITE, mprotect/FOLL_FORCE 都不可行
     *   - ART 自己持有同 memfd 的 rw-s 映射, 物理页共享
     *   - 直接 memcpy 到 rw 地址, 再 flush icache 到 rx 地址
     *   - 完全绕开 VMA 权限 / SELinux execmod / FOLL_FORCE 限制
     * 失败 fallback 到传统 mprotect+memcpy (对普通 file-backed VMA 有效)。 */
    uint8_t jump_buf[MIN_HOOK_SIZE] __attribute__((aligned(32)));
    jump_result = hook_write_jump_at(jump_buf, (uint64_t)target, jump_dest);
    if (jump_result < 0) {
        return jump_result;
    }

    {
        void* writable = find_rw_sibling(target, (size_t)jump_result);
        if (writable) {
            memcpy(writable, jump_buf, (size_t)jump_result);
            /* flush icache 在 target 侧 (CPU 执行地址) — 虚拟地址不同但物理页同 */
            __builtin___clear_cache((char*)target, (char*)target + jump_result);
            __builtin___clear_cache((char*)writable, (char*)writable + jump_result);
            entry->stealth = 0;
            entry->original_size = jump_result;
            hook_log("[patch_target] rw-sibling OK target=%p via writable=%p len=%d",
                     target, writable, jump_result);
            return 0;
        }
    }

    /* Fallback: mprotect + direct write */
    uintptr_t page_start = (uintptr_t)target & ~0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        hook_log("[patch_target] mprotect(RWX) %p failed errno=%d(%s)",
                 (void*)page_start, errno, strerror(errno));
        return HOOK_ERROR_MPROTECT_FAILED;
    }
    jump_result = hook_write_jump(target, jump_dest);
    if (jump_result < 0) {
        restore_page_rx(page_start);
        return jump_result;
    }
    entry->stealth = 0;
    entry->original_size = jump_result;
    restore_page_rx(page_start);

    return 0;
}

void finalize_hook(HookEntry* entry, void* thunk, size_t thunk_size) {
    /* Flush caches */
    if (!entry->stealth) {
        hook_flush_cache(entry->target, MIN_HOOK_SIZE);
    }
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);
    if (thunk && thunk_size > 0) {
        hook_flush_cache(thunk, thunk_size);
    }

    /* Add to hook list */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;
}

/* --- Diagnostic: alloc_near 有效性测试 --- */

static const char* identify_pool(void* ptr, int prev_pool_count, int* out_idx) {
    if ((uint8_t*)ptr >= (uint8_t*)g_engine.exec_mem &&
        (uint8_t*)ptr < (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_size) {
        *out_idx = -1;
        return "initial";
    }
    for (int i = 0; i < g_engine.pool_count; i++) {
        ExecPool* pool = &g_engine.pools[i];
        if ((uint8_t*)ptr >= (uint8_t*)pool->base &&
            (uint8_t*)ptr < (uint8_t*)pool->base + pool->size) {
            *out_idx = i;
            return (i >= prev_pool_count) ? "NEW" : "reuse";
        }
    }
    *out_idx = -2;
    return "???";
}

void hook_diag_alloc_near(void* target) {
    if (!g_engine.initialized) {
        hook_log("[diag] hook engine not initialized");
        return;
    }

    int64_t adrp_range = (int64_t)1 << 32;
    int prev_pool_count = g_engine.pool_count;

    hook_log("── target=%p  pools_before=%d ──", target, prev_pool_count);

    void* strict_result = hook_alloc_near_range(512, target, adrp_range);
    if (strict_result) {
        int64_t dist = (int64_t)((uint8_t*)strict_result - (uint8_t*)target);
        int idx;
        const char* src = identify_pool(strict_result, prev_pool_count, &idx);
        hook_log("  near_range(±4GB): %p  dist=%+.1fMB  pool=%s[%d]  pools_after=%d",
                 strict_result, (double)dist / (1024*1024), src, idx, g_engine.pool_count);
    } else {
        hook_log("  near_range(±4GB): FAILED");
    }

    {
        int64_t d = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        hook_log("  [initial] %p  used=%zu/%zu  dist=%+.1fGB %s",
                 g_engine.exec_mem, g_engine.exec_mem_used, g_engine.exec_mem_size,
                 (double)d / (1024*1024*1024LL),
                 (d > -adrp_range && d < adrp_range) ? "" : "OUT");
    }
    for (int i = 0; i < g_engine.pool_count; i++) {
        ExecPool* pool = &g_engine.pools[i];
        int64_t d = (int64_t)((uint8_t*)pool->base - (uint8_t*)target);
        hook_log("  [pool %d]  %p  used=%zu/%zu  dist=%+.1fGB %s%s",
                 i, pool->base, pool->used, pool->size,
                 (double)d / (1024*1024*1024LL),
                 (d > -adrp_range && d < adrp_range) ? "" : "OUT",
                 (i >= prev_pool_count) ? " ★NEW" : "");
    }
}

