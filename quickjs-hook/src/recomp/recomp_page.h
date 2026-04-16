/*
 * recompiler.h - ARM64 页级代码重编译器
 *
 * 将一页 ARM64 代码从 orig_base 重编译到 recomp_base，保持 1:1 偏移映射。
 * PC 相对指令自动调整立即数；超出范围的指令通过跳板(trampoline)处理。
 *
 * 设计原则：
 *   - 重编译页中每条指令与原始页保持相同偏移（内核直接 PC += delta）
 *   - 页内分支（B/BL/B.cond/CBZ 等目标在同页内）直接复制（偏移不变）
 *   - 页外 PC 相对引用（ADR/ADRP/LDR literal）始终指向原始地址
 *   - 超出立即数范围的指令替换为 B/BL 跳转到跳板区
 */

#ifndef RECOMP_PAGE_H
#define RECOMP_PAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RECOMP_PAGE_SIZE  4096
#define RECOMP_INSN_COUNT (RECOMP_PAGE_SIZE / 4)

/* 重编译统计 */
typedef struct {
    int num_copied;         /* 非 PC 相对指令，直接复制 */
    int num_intra_page;     /* 页内分支，直接复制 */
    int num_direct_reloc;   /* PC 相对指令，直接调整立即数 */
    int num_trampolines;    /* 需要跳板的指令 */
    int error;              /* 非零表示出错 */
    char error_msg[256];    /* 错误信息 */
} RecompileStats;

/*
 * 重编译一页 ARM64 代码
 *
 * @param orig_code     原始页数据的可读副本（RECOMP_PAGE_SIZE 字节）
 * @param orig_base     原始页在目标进程的虚拟地址（页对齐）
 * @param recomp_buf    输出：重编译代码缓冲区（RECOMP_PAGE_SIZE 字节，可写）
 * @param recomp_base   重编译页将被映射到的虚拟地址（页对齐）
 * @param tramp_buf     输出：跳板代码缓冲区（可写）
 * @param tramp_base    跳板缓冲区的虚拟地址
 * @param tramp_cap     跳板缓冲区容量（字节）
 * @param tramp_used    输出：跳板区已使用字节数
 * @param stats         输出：统计信息（可为 NULL）
 * @return              0 成功，-1 失败
 */
int recompile_page(
    const void* orig_code,
    uint64_t orig_base,
    void* recomp_buf,
    uint64_t recomp_base,
    void* tramp_buf,
    uint64_t tramp_base,
    size_t tramp_cap,
    size_t* tramp_used,
    RecompileStats* stats
);

/*
 * Relocate a user-provided instruction stream into a preallocated slot buffer
 * and append an unconditional B to `fall_through_target` (unless the last
 * relocated instruction is itself an unconditional flow terminator — B/BR/RET).
 *
 * Intended for stealth-2 "one-instruction-for-N-instruction" patching: the
 * caller overwrites one 4-byte instruction position in the recomp page with
 * `B → slot_buf`; this function builds the slot body so that PC-relative
 * instructions inside `user_bytes` are re-emitted correctly for execution at
 * `slot_pc`, and execution falls back to the next original instruction after
 * the user patch finishes.
 *
 * @param user_bytes              Raw patch bytes (must be 4-byte aligned and 4-byte multiple)
 * @param user_len                Length of user_bytes in bytes
 * @param user_src_pc             Address the user *thinks* the patch runs at
 *                                (the original address, used for PC-rel math)
 * @param slot_buf                Output buffer for relocated slot body
 * @param slot_cap                Capacity of slot_buf
 * @param slot_pc                 Runtime address where slot_buf will execute
 * @param fall_through_target     Address to B to after the user patch finishes
 *                                (typically `orig_addr + 4` in recomp-page space)
 * @param err_buf                 Optional error message buffer, may be NULL
 * @param err_cap                 Capacity of err_buf
 * @return                        Bytes written into slot_buf on success, -1 on error
 */
int arm64_install_user_patch(
    const uint8_t* user_bytes, size_t user_len,
    uint64_t user_src_pc,
    uint8_t* slot_buf, size_t slot_cap, uint64_t slot_pc,
    uint64_t fall_through_target,
    uint64_t orig_page_base,
    uint64_t recomp_page_base,
    size_t   redirect_page_size,
    char* err_buf, size_t err_cap
);

#ifdef __cplusplus
}
#endif

#endif /* RECOMPILER_H */
