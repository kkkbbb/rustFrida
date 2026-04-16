//! ARM64 页级代码重编译器
//!
//! 用户层职责：
//!   1. 读取原始页代码
//!   2. 重编译到新地址（调整 PC 相对指令）
//!   3. prctl(PR_RECOMPILE_REGISTER) 注册映射
//!
//! 内核层职责（不在本模块）：
//!   - 去掉原始页的 X 权限
//!   - 捕获执行异常，修改 PC 跳转到重编译页（同偏移）
//!
//! 用途：stealth hook — 在重编译页上修改代码，原始页不变。

use crate::communication::log_msg;
use crate::vma_name::set_anon_vma_name_raw;
use libc::{
    mmap, mprotect, munmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
    _SC_PAGESIZE,
};
use std::collections::HashMap;
use std::io::Error;
use std::ptr;
use std::sync::Mutex;

type Result<T> = std::result::Result<T, String>;

// 内核 prctl 接口
const PR_RECOMPILE_REGISTER: i32 = 0x52430001;
const PR_RECOMPILE_RELEASE: i32 = 0x52430002;

const PAGE_SIZE: usize = 4096;
const MAX_TRAMPOLINE_PAGES: usize = 16; // 远距 recomp 时需要更多跳板空间

static VMA_RECOMP_CODE: &[u8] = b"wwb_recomp_code\0";
static VMA_RECOMP_TRAMP: &[u8] = b"wwb_recomp_tramp\0";

// C FFI
extern "C" {
    fn recompile_page(
        orig_code: *const u8,
        orig_base: u64,
        recomp_buf: *mut u8,
        recomp_base: u64,
        tramp_buf: *mut u8,
        tramp_base: u64,
        tramp_cap: usize,
        tramp_used: *mut usize,
        stats: *mut RecompileStatsC,
    ) -> i32;

    fn hook_flush_cache(start: *mut libc::c_void, size: usize);
    fn hook_write_jump(dst: *mut libc::c_void, target: *mut libc::c_void) -> i32;
    fn hook_mmap_near(target: *mut libc::c_void, alloc_size: usize) -> *mut libc::c_void;
    fn hook_register_pool(base: *mut libc::c_void, size: usize) -> i32;
    fn arm64_install_user_patch(
        user_bytes: *const u8,
        user_len: usize,
        user_src_pc: u64,
        slot_buf: *mut u8,
        slot_cap: usize,
        slot_pc: u64,
        fall_through_target: u64,
        orig_page_base: u64,
        recomp_page_base: u64,
        redirect_page_size: usize,
        err_buf: *mut u8,
        err_cap: usize,
    ) -> i32;
    fn hook_rebuild_trampoline(
        trampoline: *mut libc::c_void,
        trampoline_size: usize,
        orig_bytes: *const u8,
        orig_pc: u64,
        jump_back_target: *mut libc::c_void,
    ) -> i32;
}

/// C 侧的 RecompileStats 对应结构
#[repr(C)]
struct RecompileStatsC {
    num_copied: i32,
    num_intra_page: i32,
    num_direct_reloc: i32,
    num_trampolines: i32,
    error: i32,
    error_msg: [u8; 256],
}

impl RecompileStatsC {
    fn new() -> Self {
        RecompileStatsC {
            num_copied: 0,
            num_intra_page: 0,
            num_direct_reloc: 0,
            num_trampolines: 0,
            error: 0,
            error_msg: [0u8; 256],
        }
    }
}

/// 重编译统计信息
pub struct RecompileStats {
    pub num_copied: i32,
    pub num_intra_page: i32,
    pub num_direct_reloc: i32,
    pub num_trampolines: i32,
}

impl From<&RecompileStatsC> for RecompileStats {
    fn from(c: &RecompileStatsC) -> Self {
        RecompileStats {
            num_copied: c.num_copied,
            num_intra_page: c.num_intra_page,
            num_direct_reloc: c.num_direct_reloc,
            num_trampolines: c.num_trampolines,
        }
    }
}

/// alloc_trampoline_slot 保存的原始指令信息
struct SlotInfo {
    /// recomp 代码页上被 B 覆盖的地址
    recomp_addr: usize,
    /// slot 地址（跳板区）
    slot_addr: usize,
    /// 被覆盖前的原始 4 字节指令
    orig_insn: [u8; 4],
    /// slot 字节数；决定能否放进固定 32B free list
    slot_size: usize,
    /// true = 32B 可复用 hook slot；false = writest 变长 slot，不进 free list
    reusable: bool,
}

/// 一个已重编译的页
struct RecompiledPage {
    /// 原始页基地址（用于内核注销时传参）
    #[allow(dead_code)]
    orig_base: usize,
    /// 重编译区域基地址（包含重编译页 + 跳板区）
    recomp_ptr: *mut u8,
    /// 重编译区域总大小
    recomp_total_size: usize,
    /// 跳板区已使用字节数
    tramp_used: usize,
    /// 跳板区总容量（字节）
    tramp_capacity: usize,
    /// 是否已在内核注册
    registered: bool,
    /// slot 分配记录: orig_addr → (recomp_addr, 原始指令)
    slots: HashMap<usize, SlotInfo>,
    /// 回收的 32B hook slot 地址（从 revert_slot_patch 归还），alloc 优先 pop 复用
    free_hook_slots: Vec<usize>,
}

// SAFETY: 指针只在当前进程内使用，由 Mutex 保护
unsafe impl Send for RecompiledPage {}

/// 全局重编译页管理器
static RECOMP_PAGES: Mutex<Option<HashMap<usize, RecompiledPage>>> = Mutex::new(None);

fn ensure_init() {
    let mut guard = RECOMP_PAGES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// 重编译指定地址所在的页
///
/// - `addr`: 页内任意地址（自动对齐到页边界）
/// - `pid`: 目标进程 pid（0 = 当前进程）
///
/// 返回重编译页的基地址和统计信息
pub fn recompile(addr: usize, pid: u32) -> Result<(usize, RecompileStats)> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    // 检查是否已重编译
    {
        let guard = RECOMP_PAGES.lock().unwrap();
        if let Some(ref pages) = *guard {
            if pages.contains_key(&orig_base) {
                return Err(format!("页 0x{:x} 已重编译", orig_base));
            }
        }
    }

    // 重编译（共享 do_recompile_temp 逻辑）
    let t = do_recompile_temp(orig_base)?;

    // 接管 mmap 所有权（阻止 TempRecomp::drop 释放）
    let recomp_ptr = t.recomp_ptr;
    let recomp_base = t.recomp_base;
    let total_size = t.total_size;
    let tramp_used = t.tramp_used;
    let tramp_capacity = t.tramp_capacity;
    let stats = RecompileStats::from(&t.stats);
    std::mem::forget(t); // 所有权转移到 RecompiledPage

    // 命名 VMA
    let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
    let _ = set_anon_vma_name_raw(recomp_ptr, PAGE_SIZE, VMA_RECOMP_CODE);
    let _ = set_anon_vma_name_raw(tramp_ptr, tramp_capacity, VMA_RECOMP_TRAMP);

    // 刷新 icache（整个区域保持 RWX，后续 alloc_trampoline_slot 直接写，无需 mprotect）
    unsafe {
        hook_flush_cache(recomp_ptr as *mut _, PAGE_SIZE + tramp_used);
    }

    log_msg(format!(
        "[recompiler] 0x{:x} → 0x{:x} | copied={} intra={} reloc={} tramp={} tramp_bytes={}",
        orig_base,
        recomp_base,
        stats.num_copied,
        stats.num_intra_page,
        stats.num_direct_reloc,
        stats.num_trampolines,
        tramp_used,
    ));

    // 注册到内核（pid=0 表示当前进程，内核只接受 0）
    let prctl_ret = unsafe {
        libc::prctl(
            PR_RECOMPILE_REGISTER,
            0u64,
            orig_base as u64,
            recomp_base,
            0u64,
        )
    };

    let registered = if prctl_ret != 0 {
        log_msg(format!(
            "\x1b[31m[STEALTH 失效] recomp prctl 注册失败: {}，hook 将无法生效！\x1b[0m",
            Error::last_os_error()
        ));
        false
    } else {
        log_msg(format!(
            "[recompiler] prctl 注册成功: 0x{:x} → 0x{:x}",
            orig_base, recomp_base
        ));
        true
    };

    // 保存记录
    let page = RecompiledPage {
        orig_base,
        recomp_ptr,
        recomp_total_size: total_size,
        tramp_used,
        tramp_capacity,
        slots: HashMap::new(),
        free_hook_slots: Vec::new(),
        registered,
    };

    {
        let mut guard = RECOMP_PAGES.lock().unwrap();
        guard.as_mut().unwrap().insert(orig_base, page);
    }

    Ok((recomp_base as usize, stats))
}

/// 释放重编译页
pub fn release(addr: usize, pid: u32) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .remove(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 从内核注销（pid=0 表示当前进程）
    if page.registered {
        unsafe {
            libc::prctl(
                PR_RECOMPILE_RELEASE,
                0u64,
                orig_base as u64,
                0u64,
                0u64,
            );
        }
    }

    // 释放内存
    unsafe {
        munmap(page.recomp_ptr as *mut _, page.recomp_total_size);
    }

    log_msg(format!("[recompiler] 释放 0x{:x}", orig_base));
    Ok(())
}

/// 释放所有重编译页（agent cleanup 时调用）
///
/// 注销所有 prctl 注册 + munmap。释放后内核不再重定向执行到 recomp 页，
/// 原始页恢复 X 权限，代码从原始位置正常执行。
pub fn release_all() {
    ensure_init();

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    let keys: Vec<usize> = pages.keys().cloned().collect();
    for orig_base in keys {
        if let Some(page) = pages.remove(&orig_base) {
            if page.registered {
                unsafe {
                    libc::prctl(
                        PR_RECOMPILE_RELEASE,
                        0u64,
                        orig_base as u64,
                        0u64,
                        0u64,
                    );
                }
            }
            // 不 munmap: prctl release 后内核恢复原始页 X 权限，
            // 但其他线程可能仍在 recomp 页上执行（icache 里有旧指令）。
            // 保留 recomp 页直到进程退出，避免 SIGSEGV。
        }
    }
    log_msg("[recompiler] release_all: 所有 recomp 页已释放".to_string());
}

/// 获取重编译页的可写指针（用于 hook 修改代码）
///
/// 调用方负责：修改前 mprotect RWX，修改后 mprotect RX + flush icache
pub fn get_recomp_ptr(addr: usize) -> Result<*mut u8> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr)
}

/// 确保地址所在页已重编译，返回翻译后的地址
/// 供 quickjs-hook 的 JS hook API 通过回调调用
pub fn ensure_and_translate(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    // 如果还没重编译，先重编译
    let need_recomp = {
        let guard = RECOMP_PAGES.lock().unwrap();
        !guard.as_ref().unwrap().contains_key(&orig_base)
    };

    if need_recomp {
        recompile(addr, 0)?;
    }

    translate_addr(addr)
}

/// 获取地址在重编译页中的对应地址
pub fn translate_addr(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr as usize + offset)
}

/// 在重编译页上 patch 指令
///
/// `addr`: 原始地址（自动翻译到重编译页对应偏移）
/// `insns`: 要写入的指令（u32 数组）
pub fn patch_insns(addr: usize, insns: &[u32]) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    let patch_size = insns.len() * 4;
    if offset + patch_size > PAGE_SIZE {
        return Err("patch 超出页边界".into());
    }

    unsafe {
        let dst = page.recomp_ptr.add(offset) as *mut u32;
        for (i, &insn) in insns.iter().enumerate() {
            ptr::write_volatile(dst.add(i), insn);
        }
        hook_flush_cache(page.recomp_ptr.add(offset) as *mut _, patch_size);
    }

    Ok(())
}

/// 在 recomp 页的跳板区分配 slot 并写入跳转，在代码页写 B 指令。
///
/// 保持 recomp 页 offset 一一对应：代码页只改 1 条指令（B tramp_slot），
/// 完整跳转（ADRP+ADD+BR 或 MOVZ+MOVK+BR）写在跳板区。
///
/// `orig_addr`: 原始代码地址（自动翻译到 recomp 页偏移）
/// `jump_dest`: 跳转目标（如 router thunk）
/// 返回 recomp 页内被 patch 的地址（供调用方记录）
pub fn patch_with_trampoline(orig_addr: usize, jump_dest: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 跳板区在 recomp 页之后 (recomp_ptr + PAGE_SIZE)
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let tramp_cap = page.tramp_capacity;
    let slot_size = 20usize; // ADRP+ADD+BR (12) 或 MOVZ+MOVK+BR (16)，留 20 足够
    if page.tramp_used + slot_size > tramp_cap {
        return Err("recomp 跳板区已满".into());
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;

    unsafe {
        // 1. 在跳板 slot 写 full jump → jump_dest
        let jump_len = hook_write_jump(slot_ptr as *mut _, jump_dest as *mut _);
        if jump_len <= 0 {
            return Err(format!("hook_write_jump failed: {}", jump_len));
        }

        // 2. 在 recomp 代码页写 B slot（ARM64 B imm26: ±128MB）
        let recomp_code_addr = page.recomp_ptr.add(offset) as usize;
        let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
        if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
            return Err(format!("B 指令范围超限: offset={}", b_offset));
        }
        let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
        let b_insn: u32 = 0x14000000 | b_imm26;
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);

        hook_flush_cache(slot_ptr as *mut _, jump_len as usize);
        hook_flush_cache(recomp_code_addr as *mut _, 4);
    }

    page.tramp_used += slot_size;
    Ok(unsafe { page.recomp_ptr.add(offset) as usize })
}

/// 在 recomp 跳板区分配 slot，在 recomp 代码页写 B 指令指向 slot。
/// 返回 slot 地址（hook engine 后续在 slot 上写 full jump→thunk）。
///
/// 调用链: recomp 代码页[offset] → B slot → (hook engine 写) full jump → thunk
pub fn alloc_trampoline_slot(orig_addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 跳板区在 recomp 页之后
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let slot_size = 32usize; // 预留足够空间给 hook engine 写 full jump + trampoline

    // 优先复用 unhook 归还的 slot；否则 bump tramp_used。
    // 不清零 —— hook engine 在 slot 上写 full jump 覆盖前 16~20B, fixup_slot_trampoline
    // 会用 SlotInfo.orig_insn 重建 callOriginal trampoline 不依赖 slot 内容。
    let slot_addr = if let Some(reused) = page.free_hook_slots.pop() {
        reused
    } else {
        if page.tramp_used + slot_size > page.tramp_capacity {
            return Err("recomp 跳板区已满".into());
        }
        let s = unsafe { tramp_base.add(page.tramp_used) as usize };
        page.tramp_used += slot_size;
        s
    };

    let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };

    // 保存 recomp 代码页上将被 B 覆盖的原始指令
    let mut orig_insn = [0u8; 4];
    unsafe {
        ptr::copy_nonoverlapping(recomp_code_addr as *const u8, orig_insn.as_mut_ptr(), 4);
    }

    // B 指令范围预检查（commit_slot_patch 时才真正写入）
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
        return Err(format!("B 指令范围超限: offset={}", b_offset));
    }

    page.slots.insert(
        orig_addr,
        SlotInfo {
            recomp_addr: recomp_code_addr,
            slot_addr,
            orig_insn,
            slot_size,
            reusable: true,
        },
    );
    // 注意: 此时 recomp 代码页上的原始指令未被修改，slot 已分配但内容是 0。
    // 调用方必须在 hook engine 写好 thunk + fixup trampoline 后调用 commit_slot_patch。
    Ok(slot_addr)
}

/// 在 recomp 页对应位置安装 "1 指令 → N 指令" 用户 patch (writest stealth-2)。
///
/// 步骤：
/// 1. 分配 slot（足够大小：patch + reloc 膨胀 + fall-through B）
/// 2. 通过 arm64_install_user_patch 把 user_bytes relocate 到 slot，末尾追加
///    `B → recomp_addr + 4`（除非 patch 本身以 RET/B 等无条件终止）
/// 3. flush_cache 整个 slot
/// 4. 原子写 recomp 页对应 4 字节为 `B → slot`
///
/// 原页始终不动，取指通过 prctl 重定向到 recomp 页 → B→slot → reloc 后 patch。
pub fn install_patch(orig_addr: usize, user_bytes: &[u8]) -> Result<()> {
    ensure_init();

    if orig_addr % 4 != 0 {
        return Err("orig_addr must be 4-byte aligned".into());
    }
    if user_bytes.is_empty() || user_bytes.len() % 4 != 0 {
        return Err("patch must be non-empty and 4-byte multiple".into());
    }

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    if page.slots.contains_key(&orig_addr) {
        return Err(format!("地址 0x{:x} 已被占用（hook 或 patch 已在位）", orig_addr));
    }

    // Reloc 最坏情况：每条 PC-rel 指令膨胀到 ~20 字节（ADRP→MOVZ+MOVK*3）。
    // 预留 user_len × 5 + 20 字节（fall-through put_b_safe 兜底）。
    let slot_size_raw = user_bytes.len().saturating_mul(5).saturating_add(32);
    let slot_size = (slot_size_raw + 15) & !15;

    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    if page.tramp_used + slot_size > page.tramp_capacity {
        return Err(format!(
            "recomp 跳板区已满 (need {} bytes, avail {})",
            slot_size,
            page.tramp_capacity - page.tramp_used
        ));
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;
    let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };

    // 备份被覆盖的 4 字节原始指令（供 unhook 恢复）
    let mut orig_insn = [0u8; 4];
    unsafe {
        ptr::copy_nonoverlapping(recomp_code_addr as *const u8, orig_insn.as_mut_ptr(), 4);
    }

    // B 指令范围预检查
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
        return Err(format!("B range exceeded: offset={}", b_offset));
    }

    // Relocate user patch into slot via C helper
    let mut err_buf = [0u8; 128];
    let fall_through_target = (recomp_code_addr + 4) as u64;
    let recomp_page_base_addr = page.recomp_ptr as u64;
    let written = unsafe {
        arm64_install_user_patch(
            user_bytes.as_ptr(),
            user_bytes.len(),
            orig_addr as u64,
            slot_ptr,
            slot_size,
            slot_addr as u64,
            fall_through_target,
            orig_base as u64,
            recomp_page_base_addr,
            PAGE_SIZE,
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if written < 0 {
        let nul = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
        let msg = std::str::from_utf8(&err_buf[..nul]).unwrap_or("?");
        return Err(format!("arm64_install_user_patch: {}", msg));
    }

    unsafe {
        hook_flush_cache(slot_ptr as *mut _, written as usize);
    }

    page.tramp_used += slot_size;
    page.slots.insert(
        orig_addr,
        SlotInfo {
            recomp_addr: recomp_code_addr,
            slot_addr,
            orig_insn,
            slot_size,
            reusable: false, // writest 变长 slot，不进 free list
        },
    );

    // 原子写 B→slot
    let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
    let b_insn: u32 = 0x14000000 | b_imm26;
    unsafe {
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);
        hook_flush_cache(recomp_code_addr as *mut libc::c_void, 4);
    }

    Ok(())
}

/// 在 recomp 代码页上写 B→slot 指令（原子 4 字节写入）。
///
/// 必须在 hook engine 已将 thunk 写入 slot 之后调用。
/// B 指令写入后，其他线程执行到此处会立即跳到 slot 里的 thunk。
pub fn commit_slot_patch(orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = match pages.get(&orig_base) {
        Some(p) => p,
        None => return Ok(()),
    };

    let info = match page.slots.get(&orig_addr) {
        Some(i) => i,
        None => return Ok(()),
    };

    let recomp_code_addr = info.recomp_addr;
    let slot_addr = info.slot_addr;
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
    let b_insn: u32 = 0x14000000 | b_imm26;

    unsafe {
        // 原子 4 字节写入 + icache flush
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);
        hook_flush_cache(recomp_code_addr as *mut libc::c_void, 4);
    }

    Ok(())
}

/// 恢复 recomp 代码页上被 B 覆盖的原始指令（unhook 时调用）。
///
/// commit_slot_patch 写入 B→slot，本函数做逆操作：
/// 从 SlotInfo.orig_insn 恢复被覆盖的 4 字节原始指令，并移除 slot 记录。
/// 同 `revert_slot_patch`, 但返回 bool: true = 有 slot 被清；false = 该地址没 slot 记录.
/// 供 js_unhook 判断"是否真的 revert 了 writest/hook"。
pub fn try_revert_slot_patch(orig_addr: usize) -> bool {
    ensure_init();
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = match guard.as_mut() {
        Some(p) => p,
        None => return false,
    };
    let page = match pages.get_mut(&orig_base) {
        Some(p) => p,
        None => return false,
    };
    let info = match page.slots.remove(&orig_addr) {
        Some(i) => i,
        None => return false,
    };
    unsafe {
        ptr::write_volatile(info.recomp_addr as *mut u32, u32::from_le_bytes(info.orig_insn));
        hook_flush_cache(info.recomp_addr as *mut libc::c_void, 4);
    }
    if info.reusable {
        page.free_hook_slots.push(info.slot_addr);
    }
    true
}

pub fn revert_slot_patch(orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = match pages.get_mut(&orig_base) {
        Some(p) => p,
        None => return Ok(()), // 非 recomp 模式
    };

    let info = match page.slots.remove(&orig_addr) {
        Some(i) => i,
        None => return Ok(()), // 无 slot 记录
    };

    unsafe {
        ptr::write_volatile(info.recomp_addr as *mut u32, u32::from_le_bytes(info.orig_insn));
        hook_flush_cache(info.recomp_addr as *mut libc::c_void, 4);
    }

    // 归还可复用的 32B hook slot 到 free list；writest 变长 slot 不回收。
    if info.reusable {
        page.free_hook_slots.push(info.slot_addr);
    }

    Ok(())
}

/// 修复 hook engine 为 slot 自动生成的 trampoline。
///
/// hook engine 的 build_trampoline 从 slot 地址读 "original bytes"（清零后是 NOP/0），
/// 生成的 trampoline 无法正确 call original。本函数用 recomp 代码页上被 B 覆盖的
/// 真正原始指令重建 trampoline: 重定位原始指令 + 跳回 recomp_addr+4。
pub fn fixup_slot_trampoline(trampoline: *mut u8, orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = match pages.get(&orig_base) {
        Some(p) => p,
        None => return Ok(()), // 非 recomp 模式，无需 fixup
    };

    let info = match page.slots.get(&orig_addr) {
        Some(i) => i,
        None => return Ok(()), // 无 slot 记录（非 stealth2 路径或已释放）
    };

    let ret = unsafe {
        hook_rebuild_trampoline(
            trampoline as *mut libc::c_void,
            256, // TRAMPOLINE_ALLOC_SIZE
            info.orig_insn.as_ptr(),
            info.recomp_addr as u64,
            (info.recomp_addr + 4) as *mut libc::c_void,
        )
    };

    if ret < 0 {
        return Err(format!("hook_rebuild_trampoline failed: {}", ret));
    }

    Ok(())
}

/// 临时重编译结果（mmap 分配 + C 重编译，不注册 prctl）
struct TempRecomp {
    orig_code: Vec<u8>,
    recomp_ptr: *mut u8,
    total_size: usize,
    recomp_base: u64,
    tramp_used: usize,
    tramp_capacity: usize,
    stats: RecompileStatsC,
}

impl Drop for TempRecomp {
    fn drop(&mut self) {
        unsafe { munmap(self.recomp_ptr as *mut _, self.total_size) };
    }
}

fn do_recompile_temp(orig_base: usize) -> Result<TempRecomp> {
    let mut orig_code = vec![0u8; PAGE_SIZE];
    unsafe {
        ptr::copy_nonoverlapping(orig_base as *const u8, orig_code.as_mut_ptr(), PAGE_SIZE);
    }

    // recomp 本体不需要靠近原始页；真正需要近距离的是 recomp 内部的 slot/thunk。
    // 这里改用普通 mmap，消除 ±128MB 近址分配失败。
    // 同时按需放大跳板区，平衡内存占用和 trampoline 容量。
    for tramp_pages in [4usize, 8, MAX_TRAMPOLINE_PAGES] {
        let total_size = PAGE_SIZE + tramp_pages * PAGE_SIZE;
        let tramp_cap = tramp_pages * PAGE_SIZE;
        let recomp_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                total_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if recomp_ptr == libc::MAP_FAILED {
            let err = Error::last_os_error();
            if tramp_pages == MAX_TRAMPOLINE_PAGES {
                return Err(format!("mmap recomp region: {}", err));
            }
            log_msg(format!(
                "[recompiler] mmap recomp region failed (tramp_pages={}): {}",
                tramp_pages, err
            ));
            continue;
        }

        let recomp_ptr = recomp_ptr as *mut u8;
        let recomp_base = recomp_ptr as u64;
        let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
        let tramp_base = recomp_base + PAGE_SIZE as u64;

        let mut tramp_used: usize = 0;
        let mut stats = RecompileStatsC::new();

        let ret = unsafe {
            recompile_page(
                orig_code.as_ptr(), orig_base as u64,
                recomp_ptr, recomp_base,
                tramp_ptr, tramp_base, tramp_cap,
                &mut tramp_used, &mut stats,
            )
        };

        if ret == 0 {
            return Ok(TempRecomp {
                orig_code,
                recomp_ptr,
                total_size,
                recomp_base,
                tramp_used,
                tramp_capacity: tramp_cap,
                stats,
            });
        }

        let msg = std::str::from_utf8(&stats.error_msg).unwrap_or("?").trim_end_matches('\0');
        unsafe { munmap(recomp_ptr as *mut _, total_size) };

        if !msg.contains("跳板区空间不足") || tramp_pages == MAX_TRAMPOLINE_PAGES {
            return Err(format!("重编译失败: {}", msg));
        }

        log_msg(format!(
            "[recompiler] tramp_pages={} 不足，升级跳板区后重试: 0x{:x}",
            tramp_pages, orig_base
        ));
    }

    Err("重编译失败: 未找到可用的跳板区配置".to_string())
}

/// Dry-run：只重编译不注册 prctl，对比原始 vs 重编译指令
pub fn dry_run(addr: usize) -> Result<String> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let t = do_recompile_temp(orig_base)?;

    let mut output = format!(
        "orig=0x{:x} recomp=0x{:x} delta=0x{:x}\n\
         copied={} intra={} reloc={} tramp={} tramp_bytes={}\n",
        orig_base, t.recomp_base,
        t.recomp_base.wrapping_sub(orig_base as u64),
        t.stats.num_copied, t.stats.num_intra_page,
        t.stats.num_direct_reloc, t.stats.num_trampolines, t.tramp_used
    );

    let orig_insns = unsafe { std::slice::from_raw_parts(t.orig_code.as_ptr() as *const u32, 1024) };
    let recomp_insns = unsafe { std::slice::from_raw_parts(t.recomp_ptr as *const u32, 1024) };

    let mut changed = 0;
    for i in 0..1024 {
        if orig_insns[i] != recomp_insns[i] {
            let off = i * 4;
            let recomp = recomp_insns[i];
            let is_b  = (recomp & 0xFC000000) == 0x14000000;
            let is_bl = (recomp & 0xFC000000) == 0x94000000;
            if is_b || is_bl {
                let imm26 = recomp & 0x03FFFFFF;
                let sext = ((imm26 as i32) << 6) >> 6;
                let target = (t.recomp_base as i64 + off as i64 + (sext as i64) * 4) as u64;
                output.push_str(&format!(
                    "  +0x{:03x} {:08x} {} 0x{:x}\n",
                    off, orig_insns[i], if is_bl { "BL" } else { "B " }, target
                ));
            } else {
                output.push_str(&format!(
                    "  +0x{:03x} {:08x} → {:08x}\n", off, orig_insns[i], recomp
                ));
            }
            changed += 1;
        }
    }
    output.push_str(&format!("changed: {}/1024\n", changed));
    Ok(output)
    // TempRecomp Drop 自动 munmap
}

/// 列出所有已重编译的页
pub fn list_pages() -> Vec<(usize, usize, usize)> {
    ensure_init();
    let guard = RECOMP_PAGES.lock().unwrap();
    match guard.as_ref() {
        Some(pages) => pages
            .iter()
            .map(|(&orig, p)| (orig, p.recomp_ptr as usize, p.tramp_used))
            .collect(),
        None => vec![],
    }
}
