//! Memory management utilities for QBDI

use crate::ffi;
use crate::state::{GPRState, RWord};
use std::ffi::CStr;
use std::ptr;

pub use ffi::Permission;

/// Memory map entry
#[derive(Debug)]
pub struct MemoryMap {
    pub start: RWord,
    pub end: RWord,
    pub permission: Permission,
    pub name: String,
}

impl MemoryMap {
    /// Get the size of this memory region
    pub fn size(&self) -> RWord {
        self.end.saturating_sub(self.start)
    }

    /// Check if an address is within this region
    pub fn contains(&self, addr: RWord) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Check if this region is readable
    pub fn is_readable(&self) -> bool {
        (self.permission as u32) & ffi::PF_READ != 0
    }

    /// Check if this region is writable
    pub fn is_writable(&self) -> bool {
        (self.permission as u32) & ffi::PF_WRITE != 0
    }

    /// Check if this region is executable
    pub fn is_executable(&self) -> bool {
        (self.permission as u32) & ffi::PF_EXEC != 0
    }
}

/// Get memory maps of a remote process
pub fn get_remote_process_maps(pid: RWord, full_path: bool) -> Vec<MemoryMap> {
    let mut size: libc::size_t = 0;
    let maps = unsafe { ffi::qbdi_getRemoteProcessMaps(pid, full_path, &mut size) };

    if maps.is_null() || size == 0 {
        return Vec::new();
    }

    let result = (0..size)
        .map(|i| {
            let map = unsafe { &*maps.add(i) };
            let name = if map.name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(map.name).to_string_lossy().into_owned() }
            };
            MemoryMap {
                start: map.start,
                end: map.end,
                permission: map.permission,
                name,
            }
        })
        .collect();

    unsafe {
        ffi::qbdi_freeMemoryMapArray(maps, size);
    }

    result
}

/// Get memory maps of the current process
pub fn get_current_process_maps(full_path: bool) -> Vec<MemoryMap> {
    let mut size: libc::size_t = 0;
    let maps = unsafe { ffi::qbdi_getCurrentProcessMaps(full_path, &mut size) };

    if maps.is_null() || size == 0 {
        return Vec::new();
    }

    let result = (0..size)
        .map(|i| {
            let map = unsafe { &*maps.add(i) };
            let name = if map.name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(map.name).to_string_lossy().into_owned() }
            };
            MemoryMap {
                start: map.start,
                end: map.end,
                permission: map.permission,
                name,
            }
        })
        .collect();

    unsafe {
        ffi::qbdi_freeMemoryMapArray(maps, size);
    }

    result
}

/// Get list of loaded module names
pub fn get_module_names() -> Vec<String> {
    let mut size: libc::size_t = 0;
    let names = unsafe { ffi::qbdi_getModuleNames(&mut size) };

    if names.is_null() || size == 0 {
        return Vec::new();
    }

    let result = (0..size)
        .map(|i| {
            let name_ptr = unsafe { *names.add(i) };
            if name_ptr.is_null() {
                String::new()
            } else {
                let s = unsafe { CStr::from_ptr(name_ptr).to_string_lossy().into_owned() };
                unsafe { libc::free(name_ptr as *mut libc::c_void) };
                s
            }
        })
        .collect();

    unsafe {
        libc::free(names as *mut libc::c_void);
    }

    result
}

/// RAII wrapper for aligned memory allocation
pub struct AlignedAlloc {
    pub ptr: *mut u8,
    pub size: usize,
}

impl AlignedAlloc {
    /// Allocate aligned memory
    pub fn new(size: usize, align: usize) -> Option<Self> {
        let ptr = unsafe { ffi::qbdi_alignedAlloc(size, align) as *mut u8 };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, size })
        }
    }

    /// Get pointer to the allocated memory
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the size of the allocation
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice to the allocated memory
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    /// Get a mutable slice to the allocated memory
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
}

impl Drop for AlignedAlloc {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                ffi::qbdi_alignedFree(self.ptr as *mut libc::c_void);
            }
        }
    }
}

/// Virtual stack allocation helper
pub struct VirtualStack {
    pub alloc: AlignedAlloc,
}

impl VirtualStack {
    /// Allocate a virtual stack and setup GPRState
    pub fn new(gpr_state: *mut GPRState, stack_size: u32) -> Option<Self> {
        let mut stack_ptr: *mut u8 = ptr::null_mut();
        let success = unsafe { ffi::qbdi_allocateVirtualStack(gpr_state, stack_size, &mut stack_ptr) };

        if success && !stack_ptr.is_null() {
            // The stack is allocated internally by QBDI
            // We wrap it in AlignedAlloc for proper cleanup
            Some(Self {
                alloc: AlignedAlloc {
                    ptr: stack_ptr,
                    size: stack_size as usize,
                },
            })
        } else {
            None
        }
    }

    /// Get the stack pointer
    pub fn as_ptr(&self) -> *mut u8 {
        self.alloc.as_ptr()
    }
}

/// Simulate a function call by setting up the stack and registers
pub fn simulate_call(gpr_state: &mut GPRState, return_address: RWord, args: &[RWord]) {
    unsafe {
        ffi::qbdi_simulateCallA(
            gpr_state,
            return_address,
            args.len() as u32,
            if args.is_empty() { ptr::null() } else { args.as_ptr() },
        );
    }
}

/// Find a module by name in the current process memory maps
pub fn find_module(name: &str) -> Option<MemoryMap> {
    get_current_process_maps(true)
        .into_iter()
        .find(|m| m.name.contains(name))
}

/// Find a module by address
pub fn find_module_by_addr(addr: RWord) -> Option<MemoryMap> {
    get_current_process_maps(true).into_iter().find(|m| m.contains(addr))
}

/// Get executable ranges of a module
pub fn get_module_executable_ranges(name: &str) -> Vec<(RWord, RWord)> {
    get_current_process_maps(true)
        .into_iter()
        .filter(|m| m.name.contains(name) && m.is_executable())
        .map(|m| (m.start, m.end))
        .collect()
}
