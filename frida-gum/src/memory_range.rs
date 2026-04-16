/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use {crate::NativePointer, core::ffi::c_void, cstr_core::CString, frida_gum_sys as gum_sys};

use core::{
    fmt::{Debug, Display, LowerHex, UpperHex},
    ops::Range,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub struct MatchPattern {
    pub(crate) internal: *mut gum_sys::GumMatchPattern,
}

impl MatchPattern {
    pub fn from_string(pattern: &str) -> Option<Self> {
        let pattern = CString::new(pattern).unwrap();

        let internal = unsafe { gum_sys::gum_match_pattern_new_from_string(pattern.as_ptr().cast()) };
        if !internal.is_null() {
            Some(Self { internal })
        } else {
            None
        }
    }
}

impl Drop for MatchPattern {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_match_pattern_unref(self.internal) }
    }
}

#[allow(dead_code)]
pub struct ScanResult {
    pub address: usize,
    pub size: usize,
}

#[derive(Clone)]
pub struct MemoryRange {
    pub(crate) memory_range: gum_sys::GumMemoryRange,
}

impl MemoryRange {
    pub(crate) fn from_raw(memory_range: *const gum_sys::GumMemoryRange) -> MemoryRange {
        MemoryRange {
            memory_range: unsafe { *memory_range },
        }
    }

    pub fn new(base_address: NativePointer, size: usize) -> MemoryRange {
        MemoryRange {
            memory_range: gum_sys::GumMemoryRange {
                base_address: base_address.0 as u64,
                size: size as _,
            },
        }
    }

    /// Get the start address of the range.
    pub fn base_address(&self) -> NativePointer {
        NativePointer(self.memory_range.base_address as *mut c_void)
    }

    /// Get the size of the range.
    /// The end address of the range can be computed by adding the [`MemoryRange::base_address()`]
    /// to the size.
    pub fn size(&self) -> usize {
        self.memory_range.size as usize
    }

    pub fn scan(&self, pattern: &MatchPattern) -> Vec<ScanResult> {
        let mut results = Vec::new();
        unsafe {
            #[cfg(target_pointer_width = "32")]
            extern "C" fn callback32(address: u64, size: u32, user_data: *mut c_void) -> i32 {
                callback64(address, size as u64, user_data)
            }

            extern "C" fn callback64(address: u64, size: u64, user_data: *mut c_void) -> i32 {
                let results: &mut Vec<ScanResult> = unsafe { &mut *(user_data as *mut Vec<ScanResult>) };
                results.push(ScanResult {
                    address: address as usize,
                    size: size as usize,
                });
                0
            }

            #[cfg(target_pointer_width = "32")]
            let callback = callback32;

            #[cfg(target_pointer_width = "64")]
            let callback = callback64;

            gum_sys::gum_memory_scan(
                &self.memory_range as *const gum_sys::GumMemoryRange,
                pattern.internal,
                Some(callback),
                &mut results as *mut _ as *mut _,
            );
        }

        results
    }
}

impl LowerHex for MemoryRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.base_address(), f)?;
        write!(f, "..")?;
        LowerHex::fmt(&(self.base_address().0 as usize + self.size()), f)
    }
}

impl UpperHex for MemoryRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.base_address(), f)?;
        write!(f, "..")?;
        UpperHex::fmt(&(self.base_address().0 as usize + self.size()), f)
    }
}

impl Display for MemoryRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}..{}",
            self.base_address(),
            self.base_address().0 as usize + self.size()
        )
    }
}

impl Debug for MemoryRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let range: Range<usize> = self.into();
        f.debug_tuple("MemoryRange").field(&range).finish()
    }
}

impl From<&MemoryRange> for Range<usize> {
    fn from(value: &MemoryRange) -> Self {
        value.base_address().0 as usize..(value.base_address().0 as usize + value.size())
    }
}

impl From<MemoryRange> for Range<usize> {
    fn from(value: MemoryRange) -> Self {
        (&value).into()
    }
}
