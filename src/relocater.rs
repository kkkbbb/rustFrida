#![allow(dead_code)]

use std::io::Write;
use crate::GLOBAL_STREAM;

/// 最终结果：是否真的改写了立即数；若超范围则原样写回并提示。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocStatus {
    Patched,                   // 已重定位并改写
    UnchangedNotPcRelative,    // 不是 PC 相对类，原样拷贝
    UnchangedOutOfRange,       // 是 PC 相对类但新位置超出可编码范围（已原样拷贝）
}

/// 从 src_addr 读一条 A64 指令；若含 PC 相对偏移则按新位置改写；
/// 最后把（改写或原样）的 4 字节指令写到 dst_addr。
/// ⚠️ 需保证这两个地址可读/可写且 4 字节对齐。
pub unsafe fn relocate_one_a64(src_addr: usize, dst_addr: usize) -> RelocStatus {
    let insn: u32 = core::ptr::read_volatile(src_addr as *const u32).swap_bytes();
    GLOBAL_STREAM.get().unwrap().write_all(format!("relocate_one_a64: {:x}\n",insn).as_bytes());
    match relocate_pc_relative(src_addr, dst_addr, insn) {
        TryPatch::Patched(p) => {
            core::ptr::write_volatile(dst_addr as *mut u32, p.swap_bytes());
            RelocStatus::Patched
        }
        TryPatch::OutOfRange => {
            core::ptr::write_volatile(dst_addr as *mut u32, insn.swap_bytes());
            RelocStatus::UnchangedOutOfRange
        }
        TryPatch::NotMatch => {
            core::ptr::write_volatile(dst_addr as *mut u32, insn.swap_bytes());
            RelocStatus::UnchangedNotPcRelative
        }
    }
}

/* ==================== 内部实现 ==================== */

enum TryPatch { NotMatch, Patched(u32), OutOfRange }

#[inline] fn get_bits(x: u32, hi: u32, lo: u32) -> u32 {
    debug_assert!(hi < 32 && lo < 32 && hi >= lo);
    (x >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}
#[inline] fn set_bits(orig: u32, hi: u32, lo: u32, v: u32) -> u32 {
    let mask = ((1u32 << (hi - lo + 1)) - 1) << lo;
    (orig & !mask) | ((v << lo) & mask)
}
#[inline] fn sign_extend_usize_to_i64(value: usize, bits: u32) -> i64 {
    let s = 64 - bits;
    ((value << s) as i64) >> s
}
#[inline] fn fits_signed(v: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max =  (1i64 << (bits - 1)) - 1;
    v >= min && v <= max
}

fn relocate_pc_relative(src: usize, dst: usize, insn: u32) -> TryPatch {
    // 按指令族依次尝试
    try_b_bl(src, dst, insn)
        .or_else(|| try_b_cond(src, dst, insn))
        .or_else(|| try_cbz_cbnz(src, dst, insn))
        .or_else(|| try_tbz_tbnz(src, dst, insn))
        .or_else(|| try_adr(src, dst, insn))
        .or_else(|| try_adrp(src, dst, insn))
        .or_else(|| try_ldr_literal_gpr_or_ldrsw(src, dst, insn))
        .or_else(|| try_ldr_literal_fp_simd(src, dst, insn))
        .or_else(|| try_prfm_literal(src, dst, insn))
        .unwrap_or(TryPatch::NotMatch)
}

trait OrElse {
    fn or_else(self, f: impl FnOnce() -> Option<TryPatch>) -> Option<TryPatch>;
}
impl OrElse for Option<TryPatch> {
    fn or_else(self, f: impl FnOnce() -> Option<TryPatch>) -> Option<TryPatch> {
        match self { Some(x) => Some(x), None => f() }
    }
}

/* === B / BL (imm26, 基于 PC+4) ============================
 * 掩码/模式： (insn & 0x7C00_0000) == 0x1400_0000
 * BL 由 bit31 区分。偏移字节 = sign_extend(imm26)<<2
 * 参考：Arm DDI0602 — B / BL（imm26, ±128MB） :contentReference[oaicite:0]{index=0}
 */
fn try_b_bl(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x7C00_0000) != 0x1400_0000 { return None; }
    let imm26 = get_bits(insn, 25, 0) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm26, 26)) << 2;

    let target = (src + 4) as i64 + off_bytes;
    let new_off = target - (dst as i64 + 4);

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm26 = new_off >> 2;
    if !fits_signed(new_imm26, 26) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 25, 0, (new_imm26 as u32) & 0x03FF_FFFF);
    Some(TryPatch::Patched(patched))
}

/* === B.cond (imm19, 基于 PC+4) ============================
 * 掩码/模式： (insn & 0xFF00_0010) == 0x5400_0000
 * 偏移字节 = sign_extend(imm19)<<2，范围 ±1MB
 * 参考：GDB 源码解码掩码（aarch64_decode_bcond） :contentReference[oaicite:1]{index=1}
 */
fn try_b_cond(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0xFF00_0010) != 0x5400_0000 { return None; }
    let imm19 = get_bits(insn, 23, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm19, 19)) << 2;

    let target = (src + 4) as i64 + off_bytes;
    let new_off = target - (dst as i64 + 4);

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm19 = new_off >> 2;
    if !fits_signed(new_imm19, 19) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 23, 5, (new_imm19 as u32) & 0x7FFFF);
    Some(TryPatch::Patched(patched))
}

/* === CBZ/CBNZ (imm19, 基于 PC+4) ==========================
 * 掩码/模式： (insn & 0x7E00_0000) == 0x3400_0000（bit31/24 区分宽度/是否 CBNZ）
 * 偏移字节 = sign_extend(imm19)<<2
 * 参考：GDB aarch64_decode_cb 掩码/字段位置 :contentReference[oaicite:2]{index=2}
 */
fn try_cbz_cbnz(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x7E00_0000) != 0x3400_0000 { return None; }
    let imm19 = get_bits(insn, 23, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm19, 19)) << 2;

    let target = (src + 4) as i64 + off_bytes;
    let new_off = target - (dst as i64 + 4);

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm19 = new_off >> 2;
    if !fits_signed(new_imm19, 19) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 23, 5, (new_imm19 as u32) & 0x7FFFF);
    Some(TryPatch::Patched(patched))
}

/* === TBZ/TBNZ (imm14, 基于 PC+4) ==========================
 * 掩码/模式： (insn & 0x7E00_0000) == 0x3600_0000（bit24 区分 TBNZ）
 * imm14 在 [18:5]，偏移字节 = sign_extend(imm14)<<2（±32KB）
 * 参考：GDB aarch64_decode_tb 掩码/字段位置；斯坦福资料范围说明 :contentReference[oaicite:3]{index=3}
 */
fn try_tbz_tbnz(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x7E00_0000) != 0x3600_0000 { return None; }
    let imm14 = get_bits(insn, 18, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm14, 14)) << 2;

    let target = (src + 4) as i64 + off_bytes;
    let new_off = target - (dst as i64 + 4);

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm14 = new_off >> 2;
    if !fits_signed(new_imm14, 14) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 18, 5, (new_imm14 as u32) & 0x3FFF);
    Some(TryPatch::Patched(patched))
}

/* === ADR（imm21, 基于 PC） ================================
 * 掩码/模式： (insn & 0x1F00_0000) == 0x1000_0000；imm = immhi[23:5]<<2 | immlo[30:29]
 * 偏移字节 = sign_extend(imm21)
 * 参考：GDB aarch64_decode_adr；范围 ±1MB :contentReference[oaicite:4]{index=4}
 */
fn try_adr(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x1F00_0000) != 0x1000_0000 { return None; }
    let immlo = get_bits(insn, 30, 29) as usize;
    let immhi = get_bits(insn, 23, 5) as usize;
    let imm21 = (immhi << 2) | immlo;
    let off = sign_extend_usize_to_i64(imm21, 21);

    let target = src as i64 + off;
    let new_off = target - dst as i64;
    if !fits_signed(new_off, 21) { return Some(TryPatch::OutOfRange); }

    let u = new_off as usize;
    let new_immlo = (u & 0b11) as u32;
    let new_immhi = ((u >> 2) & 0x7FFFF) as u32;

    let patched = set_bits(set_bits(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    Some(TryPatch::Patched(patched))
}

/* === ADRP（imm21(页)*4096, 基于对齐PC页） =================
 * 掩码/模式： (insn & 0x1F00_0000) == 0x1000_0000 且 bit31=1（GDB同一解码）
 * 语义：target = AlignPC4K(src) + sign_extend(imm21)<<12
 * 参考：Arm DDI0602/0596 & GDB 源码；范围 ±4GB（页粒度） :contentReference[oaicite:5]{index=5}
 */
fn try_adrp(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x1F00_0000) != 0x1000_0000 || (insn >> 31) & 1 == 0 { return None; }
    let immlo = get_bits(insn, 30, 29) as usize;
    let immhi = get_bits(insn, 23, 5) as usize;
    let imm21 = (immhi << 2) | immlo;
    let off_pages = sign_extend_usize_to_i64(imm21, 21);

    let src_page = (src as i64) & !0xFFF;
    let target   = src_page + (off_pages << 12);

    let dst_page = (dst as i64) & !0xFFF;
    let new_off_pages = (target - dst_page) >> 12;
    if !fits_signed(new_off_pages, 21) { return Some(TryPatch::OutOfRange); }

    let u = new_off_pages as usize;
    let new_immlo = (u & 0b11) as u32;
    let new_immhi = ((u >> 2) & 0x7FFFF) as u32;

    let patched = set_bits(set_bits(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    Some(TryPatch::Patched(patched))
}

/* === LDR (literal, GPR) & LDRSW (literal) =================
 * GPR LDR literal（W/X）：(insn & 0xBF00_0000) == 0x1800_0000
 * LDRSW literal：        (insn & 0xFF00_0000) == 0x9800_0000
 * imm19 在 [23:5]，偏移字节 = sign_extend(imm19)<<2，基于 “本指令地址（PC）”
 * 参考：GDB opcode 表；Arm 文档（±1MB） :contentReference[oaicite:6]{index=6}
 */
fn try_ldr_literal_gpr_or_ldrsw(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    let is_gpr_lit = (insn & 0xBF00_0000) == 0x1800_0000;
    let is_ldrsw   = (insn & 0xFF00_0000) == 0x9800_0000;
    if !(is_gpr_lit || is_ldrsw) { return None; }

    let imm19 = get_bits(insn, 23, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm19, 19)) << 2;

    let target = src as i64 + off_bytes;
    let new_off = target - dst as i64;

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm19 = new_off >> 2;
    if !fits_signed(new_imm19, 19) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 23, 5, (new_imm19 as u32) & 0x7FFFF);
    Some(TryPatch::Patched(patched))
}

/* === LDR (literal, FP/SIMD) ===============================
 * 掩码/模式： (insn & 0x3F00_0000) == 0x1C00_0000（S/D/Q 都在此类）
 * imm19 同上；基于 PC
 * 参考：GDB opcode 表（OP_LDRV_LIT） :contentReference[oaicite:7]{index=7}
 */
fn try_ldr_literal_fp_simd(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0x3F00_0000) != 0x1C00_0000 { return None; }

    let imm19 = get_bits(insn, 23, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm19, 19)) << 2;

    let target = src as i64 + off_bytes;
    let new_off = target - dst as i64;

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm19 = new_off >> 2;
    if !fits_signed(new_imm19, 19) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 23, 5, (new_imm19 as u32) & 0x7FFFF);
    Some(TryPatch::Patched(patched))
}

/* === PRFM (literal) ======================================
 * 掩码/模式： (insn & 0xFF00_0000) == 0xD800_0000
 * imm19 同上；基于 PC
 * 参考：GDB opcode 表 PRFM_LIT（掩码/模式） :contentReference[oaicite:8]{index=8}
 */
fn try_prfm_literal(src: usize, dst: usize, insn: u32) -> Option<TryPatch> {
    if (insn & 0xFF00_0000) != 0xD800_0000 { return None; }

    let imm19 = get_bits(insn, 23, 5) as usize;
    let off_bytes = (sign_extend_usize_to_i64(imm19, 19)) << 2;

    let target = src as i64 + off_bytes;
    let new_off = target - dst as i64;

    if (new_off & 0b11) != 0 { return Some(TryPatch::OutOfRange); }
    let new_imm19 = new_off >> 2;
    if !fits_signed(new_imm19, 19) { return Some(TryPatch::OutOfRange); }

    let patched = set_bits(insn, 23, 5, (new_imm19 as u32) & 0x7FFFF);
    Some(TryPatch::Patched(patched))
}
