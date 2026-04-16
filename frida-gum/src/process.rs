//! Process helpers.
//!

#![cfg_attr(any(target_arch = "x86_64", target_arch = "x86"), allow(clippy::unnecessary_cast))]

use crate::{FileMapping, Module, NativePointer};

use {
    crate::{Gum, PageProtection, RangeDetails},
    core::ffi::{c_char, c_void, CStr},
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gboolean, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use cstr_core::CString;

#[cfg(target_os = "linux")]
extern "C" {
    pub fn _frida_g_get_home_dir() -> *const c_char;
    pub fn _frida_g_get_current_dir() -> *const c_char;
    pub fn _frida_g_get_tmp_dir() -> *const c_char;
}

#[cfg(not(target_os = "linux"))]
extern "C" {
    pub fn g_get_home_dir() -> *const c_char;
    pub fn g_get_current_dir() -> *const c_char;
    pub fn g_get_tmp_dir() -> *const c_char;
}

#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum CodeSigningPolicy {
    CodeSigningOptional = gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_OPTIONAL as u32,
    CodeSigningRequired = gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_REQUIRED as u32,
}

#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum Os {
    OsWindows = gum_sys::_GumOS_GUM_OS_WINDOWS as u32,
    OsMacos = gum_sys::_GumOS_GUM_OS_MACOS as u32,
    OsLinux = gum_sys::_GumOS_GUM_OS_LINUX as u32,
    OsIos = gum_sys::_GumOS_GUM_OS_IOS as u32,
    OsWatchos = gum_sys::_GumOS_GUM_OS_WATCHOS as u32,
    OsTvos = gum_sys::_GumOS_GUM_OS_TVOS as u32,
    OsAndroid = gum_sys::_GumOS_GUM_OS_ANDROID as u32,
    OsFreebsd = gum_sys::_GumOS_GUM_OS_FREEBSD as u32,
    OsQnx = gum_sys::_GumOS_GUM_OS_QNX as u32,
}

pub struct Range<'a> {
    /// Base address
    pub base: NativePointer,
    /// Size in bytes
    pub size: usize,
    /// Protection flag (e.g., Read, Write, Execute)
    pub protection: PageProtection,
    /// When available, file mapping details.
    pub file: Option<FileMapping<'a>>,
}

pub struct Process<'a> {
    // This is to verify that Gum is initialized before using any Module methods which requires
    // intialization.
    // Note that Gum is expected to be initialized via OnceCell which provides &Gum for every
    // instance.
    _gum: &'a Gum,
    /// Property containing the PID as a number
    pub id: u32,
    /// Properly specifying the current platform.
    pub platform: Os,
    /// Property which can be `optional` or `required`, where the latter means Frida will avoid modifying
    /// existing code in memory and will not try to run unsigned code.
    pub code_signing_policy: CodeSigningPolicy,
    /// Contains a Module representing the main executable of the process.
    pub main_module: Module,
}

impl<'a> Process<'a> {
    /// Initialize a new process
    pub fn obtain(gum: &'a Gum) -> Process<'a> {
        let id = unsafe { gum_sys::gum_process_get_id() };
        let platform = num::FromPrimitive::from_u32(unsafe { gum_sys::gum_process_get_native_os() }).unwrap();
        let code_signing_policy =
            num::FromPrimitive::from_u32(unsafe { gum_sys::gum_process_get_code_signing_policy() as u32 }).unwrap();

        let main_module = unsafe { Module::from_raw(gum_sys::gum_process_get_main_module()) };

        Process {
            _gum: gum,
            id,
            platform,
            code_signing_policy,
            main_module,
        }
    }

    pub fn find_module_by_name(&self, module_name: &str) -> Option<Module> {
        let module_name = CString::new(module_name).unwrap();
        unsafe {
            let module = gum_sys::gum_process_find_module_by_name(module_name.as_ptr().cast());
            if !module.is_null() {
                Some(Module::from_raw(module))
            } else {
                None
            }
        }
    }

    pub fn find_module_by_address(&self, address: usize) -> Option<Module> {
        unsafe {
            let module = gum_sys::gum_process_find_module_by_address(address as u64);
            if !module.is_null() {
                Some(Module::from_raw(module))
            } else {
                None
            }
        }
    }
    /// Returns a string specifying the filesystem path to the current working directory
    pub fn current_dir(&self) -> String {
        unsafe {
            #[cfg(target_os = "linux")]
            let dir = _frida_g_get_current_dir();
            #[cfg(not(target_os = "linux"))]
            let dir = g_get_current_dir();

            CStr::from_ptr(dir).to_string_lossy().to_string()
        }
    }

    /// Returns a string specifying the filesystem path to the directory to use for temporary files
    pub fn tmp_dir(&self) -> String {
        unsafe {
            #[cfg(target_os = "linux")]
            let dir = _frida_g_get_tmp_dir();
            #[cfg(not(target_os = "linux"))]
            let dir = g_get_tmp_dir();

            CStr::from_ptr(dir).to_string_lossy().to_string()
        }
    }

    /// Returns a string specifying the filesystem path to the current user’s home directory
    pub fn home_dir(&self) -> String {
        unsafe {
            #[cfg(target_os = "linux")]
            let dir = _frida_g_get_home_dir();
            #[cfg(not(target_os = "linux"))]
            let dir = g_get_home_dir();

            CStr::from_ptr(dir).to_string_lossy().to_string()
        }
    }

    /// Get this thread’s OS-specific id as a number
    pub fn current_thread_id(&self) -> u32 {
        unsafe { gum_sys::gum_process_get_current_thread_id() as u32 }
    }

    /// Enumerates memory ranges satisfying `protection` given
    pub fn enumerate_ranges(&self, protection: PageProtection) -> Vec<Range<'a>> {
        struct CallbackData<'a> {
            ranges: Vec<Range<'a>>,
            protection: PageProtection,
        }

        unsafe extern "C" fn enumerate_ranges_callback(
            details: *const gum_sys::GumRangeDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut CallbackData);
            let r_details = RangeDetails::from_raw(details);

            let prot = r_details.protection();
            if res.protection == prot {
                let m_range = r_details.memory_range();
                let file_map = r_details.file_mapping();

                res.ranges.push(Range {
                    base: m_range.base_address(),
                    size: m_range.size(),
                    protection: prot,
                    file: file_map,
                });
            }

            1
        }

        let callback_data = CallbackData {
            ranges: Vec::new(),
            protection: protection.clone(),
        };

        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                protection as u32,
                Some(enumerate_ranges_callback),
                &callback_data as *const _ as *mut c_void,
            );
        }

        callback_data.ranges
    }

    /// Enumerates loaded modules
    pub fn enumerate_modules(&self) -> Vec<Module> {
        struct CallbackData {
            modules: Vec<Module>,
        }

        unsafe extern "C" fn enumerate_modules_callback(
            details: *mut gum_sys::GumModule,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut CallbackData);
            res.modules.push(Module::from_raw(details));

            1
        }

        let callback_data = CallbackData { modules: Vec::new() };

        unsafe {
            gum_sys::gum_process_enumerate_modules(
                Some(enumerate_modules_callback),
                &callback_data as *const _ as *mut c_void,
            );
        }

        callback_data.modules
    }
}
