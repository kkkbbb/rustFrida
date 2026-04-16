//! jsapi 共用工具函数

use crate::ffi;
use std::ffi::CString;

/// QuickJS CFunction 签名类型
pub(crate) type JSCFn = unsafe extern "C" fn(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue;

/// 将 CFunction 作为属性添加到 JS 对象上。
/// 各 jsapi 模块注册函数时的通用模式。
pub(crate) unsafe fn add_cfunction_to_object(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    ffi::qjs_set_property(ctx, obj, atom, func_val);
    ffi::JS_FreeAtom(ctx, atom);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcMapEntry<'a> {
    pub start: u64,
    pub end: u64,
    pub perms: &'a str,
    pub path: Option<&'a str>,
}

impl ProcMapEntry<'_> {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn prot_flags(&self) -> i32 {
        let perms = self.perms.as_bytes();
        let mut prot = 0i32;
        if perms.first() == Some(&b'r') {
            prot |= libc::PROT_READ;
        }
        if perms.get(1) == Some(&b'w') {
            prot |= libc::PROT_WRITE;
        }
        if perms.get(2) == Some(&b'x') {
            prot |= libc::PROT_EXEC;
        }
        prot
    }
}

/// 读取 /proc/self/maps 并返回内容字符串。
/// 使用 `String::from_utf8` 快速路径，仅在内容包含非 UTF-8 字节时回退到 lossy 转换。
pub(crate) fn read_proc_self_maps() -> Option<String> {
    let bytes = std::fs::read("/proc/self/maps").ok()?;
    Some(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

pub(crate) fn parse_proc_map_line(line: &str) -> Option<ProcMapEntry<'_>> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next();

    let mut parts = range.splitn(2, '-');
    let start = u64::from_str_radix(parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(parts.next()?, 16).ok()?;

    Some(ProcMapEntry {
        start,
        end,
        perms,
        path,
    })
}

pub(crate) fn proc_maps_entries(maps: &str) -> impl Iterator<Item = ProcMapEntry<'_>> + '_ {
    maps.lines().filter_map(parse_proc_map_line)
}

/// Check if [addr, addr+size) is accessible using mincore(2).
/// Returns false for null/zero or unmapped pages.
pub(crate) fn is_addr_accessible(addr: u64, size: usize) -> bool {
    if addr == 0 || size == 0 {
        return false;
    }
    unsafe {
        const PAGE_SIZE: usize = 0x1000;
        let page_addr = (addr as usize) & !(PAGE_SIZE - 1);
        let end = match (addr as usize).checked_add(size) {
            Some(e) => e,
            None => return false, // overflow: address range wraps around
        };
        let region_len = end.saturating_sub(page_addr);
        let pages = (region_len + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut vec = vec![0u8; pages];
        libc::mincore(page_addr as *mut libc::c_void, region_len, vec.as_mut_ptr() as *mut _) == 0
    }
}
