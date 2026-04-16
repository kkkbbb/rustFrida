//! ExecMem - 可读写可执行内存分配器

use crate::vma_name::set_anon_vma_name_raw;
use libc::{mmap, munmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
use std::io::Error;
use std::ptr;
use std::ptr::null_mut;

type Result<T> = std::result::Result<T, String>;
static TRACE_EXEC_VMA_NAME: &[u8] = b"wwb_trace_exec\0";

pub struct ExecMem {
    pub(crate) ptr: *mut u8,
    size: usize,
    used: usize,
    page_size: usize,
}

impl ExecMem {
    /// 新建一块可读写可执行内存（自动按页分配）
    pub fn new() -> Result<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(Error::last_os_error().to_string());
            }
            let _ = set_anon_vma_name_raw(ptr as *mut u8, page_size, TRACE_EXEC_VMA_NAME);
            Ok(ExecMem {
                ptr: ptr as *mut u8,
                size: page_size,
                used: 0,
                page_size,
            })
        }
    }

    /// 写入数据，自动扩容（每次扩容一页）
    pub fn write(&mut self, data: &[u8]) -> Result<*mut u8> {
        if self.used + data.len() > self.size {
            // self.grow()?;
            return Err(String::from("剩余exe_mem耗尽"));
        }
        unsafe {
            let dest = self.ptr.add(self.used);
            ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
            // let old_used = self.used;
            self.used += data.len();
            Ok(self.ptr.add(self.used))
        }
    }

    pub fn reset(&mut self) {
        self.used = 0;
    }

    pub fn write_u32(&mut self, value: u32) -> Result<*mut u8> {
        let bytes = value.to_le_bytes(); // ARM64 小端
        self.write(&bytes)
    }

    /// 扩容（每次扩容一页）
    fn grow(&mut self) -> Result<()> {
        let new_size = self.size + self.page_size;
        unsafe {
            // 申请新内存
            let new_ptr = mmap(
                null_mut(),
                new_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if new_ptr == libc::MAP_FAILED {
                return Err(format!(
                    "无法扩展内存 ({}->{}): {}",
                    self.size,
                    new_size,
                    Error::last_os_error()
                ));
            }
            let _ = set_anon_vma_name_raw(new_ptr as *mut u8, new_size, TRACE_EXEC_VMA_NAME);
            // 拷贝旧数据
            ptr::copy_nonoverlapping(self.ptr, new_ptr as *mut u8, self.used);
            // 释放旧内存
            munmap(self.ptr as *mut _, self.size);
            self.ptr = new_ptr as *mut u8;
            self.size = new_size;
        }
        Ok(())
    }

    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
    pub fn current_addr(&self) -> usize {
        unsafe { self.ptr.add(self.used) as usize }
    }

    pub fn external_write_instruct(&mut self) -> usize {
        unsafe {
            let result = self.ptr.add(self.used) as usize;
            self.used += 4;
            result
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn capacity(&self) -> usize {
        self.size
    }
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}
