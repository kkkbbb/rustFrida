/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Module helpers.
//!

#![cfg_attr(any(target_arch = "x86_64", target_arch = "x86"), allow(clippy::unnecessary_cast))]

use crate::MemoryRange;
#[cfg(feature = "std")]
use std::{ffi::CStr, string::ToString};

use {
    crate::{Gum, NativePointer, PageProtection, RangeDetails},
    core::{ffi::c_void, fmt},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gboolean, gpointer, GumExportDetails, GumModule, GumSectionDetails, GumSymbolDetails},
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

extern "C" fn enumerate_ranges_callout(
    range_details: *const gum_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>) };
    let r = f(RangeDetails::from_raw(range_details));
    Box::leak(f);
    r as gum_sys::gboolean
}

/// Export type.
#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum ExportType {
    Function = gum_sys::GumExportType_GUM_EXPORT_FUNCTION as u32,
    Variable = gum_sys::GumExportType_GUM_EXPORT_VARIABLE as u32,
}

impl fmt::Display for ExportType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportType::Function => write!(fmt, "function"),
            ExportType::Variable => write!(fmt, "variable"),
        }
    }
}

/// Module symbol details returned by [`Module::enumerate_symbols`].
pub struct SymbolDetails {
    pub name: String,
    pub address: usize,
    pub size: usize,
}

/// Module symbol details returned by [`Module::enumerate_sections`].
pub struct SectionDetails {
    pub id: String,
    pub name: String,
    pub address: usize,
    pub size: usize,
}

/// Module export details returned by [`Module::enumerate_exports`].
pub struct ExportDetails {
    pub typ: ExportType,
    pub name: String,
    pub address: usize,
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            gum_sys::g_object_unref(self.inner as _);
        }
    }
}

pub struct Module {
    inner: *mut GumModule,
}

impl Module {
    pub(crate) fn from_raw(module: *mut GumModule) -> Self {
        unsafe {
            gum_sys::g_object_ref(module.cast());
        }
        Self { inner: module }
    }
    /// Load a module by name
    pub fn load(_gum: &Gum, module_name: &str) -> Self {
        let module_name = CString::new(module_name).unwrap();
        Self {
            inner: unsafe { gum_sys::gum_module_load(module_name.as_ptr().cast(), core::ptr::null_mut()) },
        }
    }

    #[cfg(feature = "std")]
    /// Get the name of this module
    pub fn name(&self) -> String {
        unsafe {
            CStr::from_ptr(gum_sys::gum_module_get_name(self.inner))
                .to_string_lossy()
                .to_string()
        }
    }

    #[cfg(feature = "std")]
    /// Get the path of this module
    pub fn path(&self) -> String {
        unsafe {
            CStr::from_ptr(gum_sys::gum_module_get_path(self.inner))
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get the range of this module
    pub fn range(&self) -> MemoryRange {
        MemoryRange::from_raw(unsafe { gum_sys::gum_module_get_range(self.inner) })
    }

    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_export_by_name(&self, symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr =
            unsafe { gum_sys::gum_module_find_export_by_name(self.inner, symbol_name.as_ptr().cast()) as *mut c_void };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_global_export_by_name(symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = unsafe { gum_sys::gum_module_find_global_export_by_name(symbol_name.as_ptr().cast()) as *mut c_void };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// The absolute address of the symbol. In the event that no such symbol
    /// could be found, returns NULL.
    pub fn find_symbol_by_name(&self, symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr =
            unsafe { gum_sys::gum_module_find_symbol_by_name(self.inner, symbol_name.as_ptr().cast()) } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(&self, prot: PageProtection, callout: impl FnMut(RangeDetails) -> bool) {
        unsafe {
            let user_data =
                Box::leak(Box::new(Box::new(callout) as Box<dyn FnMut(RangeDetails) -> bool>)) as *mut _ as *mut c_void;

            gum_sys::gum_module_enumerate_ranges(self.inner, prot as u32, Some(enumerate_ranges_callout), user_data);

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }

    /// Enumerates exports in module.
    pub fn enumerate_exports(&self) -> Vec<ExportDetails> {
        let result: Vec<ExportDetails> = vec![];

        unsafe extern "C" fn callback(details: *const GumExportDetails, user_data: gpointer) -> gboolean {
            let res = &mut *(user_data as *mut Vec<ExportDetails>);
            let name: String = NativePointer((*details).name as *mut _).try_into().unwrap_or_default();

            let address = (*details).address as usize;
            let typ = num::FromPrimitive::from_u32((*details).type_ as u32).unwrap();
            let info = ExportDetails { typ, name, address };
            res.push(info);
            1
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_exports(self.inner, Some(callback), &result as *const _ as *mut c_void);
        }
        result
    }

    /// Enumerates symbols in module.
    pub fn enumerate_symbols(&self) -> Vec<SymbolDetails> {
        let result: Vec<SymbolDetails> = vec![];
        unsafe extern "C" fn callback(details: *const GumSymbolDetails, user_data: gpointer) -> gboolean {
            let res = &mut *(user_data as *mut Vec<SymbolDetails>);

            let name: String = NativePointer((*details).name as *mut _).try_into().unwrap_or_default();
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SymbolDetails { name, address, size };
            res.push(info);

            1
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_symbols(self.inner, Some(callback), &result as *const _ as *mut c_void);
        }
        result
    }

    /// Enumerates sections of module.
    pub fn enumerate_sections(&self) -> Vec<SectionDetails> {
        let result: Vec<SectionDetails> = vec![];

        unsafe extern "C" fn callback(details: *const GumSectionDetails, user_data: gpointer) -> gboolean {
            let res = &mut *(user_data as *mut Vec<SectionDetails>);

            let id: String = NativePointer((*details).id as *mut _).try_into().unwrap_or_default();
            let name: String = NativePointer((*details).name as *mut _).try_into().unwrap_or_default();
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SectionDetails {
                id,
                name,
                address,
                size,
            };
            res.push(info);

            1
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_sections(
                self.inner,
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }
}
