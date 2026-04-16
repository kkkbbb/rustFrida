// ============================================================================
// Module handle + symbol resolution
// ============================================================================

#[repr(C)]
struct AndroidDlextinfo {
    flags: u64,
    reserved_addr: u64,
    reserved_size: u64,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: u64,
    library_namespace: u64,
}

/// Get a dlopen handle to libart.so via unrestricted linker API (Frida-style).
unsafe fn get_libart_handle() -> *mut std::ffi::c_void {
    LIBART_HANDLE
        .get_or_init(|| {
            let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
            if let Some(api) = api {
                let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
                if libart_base == 0 {
                    output_message("[linker api] libart.so base not found in /proc/self/maps");
                    return SyncPtr(std::ptr::null_mut());
                }

                let caller_addr = libart_base as *const std::ffi::c_void;

                let paths_to_try: Vec<String> = {
                    let mut paths = Vec::new();
                    if let Some(Some(path)) = LIBART_PATH.get() {
                        paths.push(path.clone());
                    }
                    paths.push("libart.so".to_string());
                    paths
                };

                for path in &paths_to_try {
                    let c_path = CString::new(path.as_str()).unwrap();
                    let handle = (api.dlopen)(
                        c_path.as_ptr() as *const i8,
                        libc::RTLD_NOW | libc::RTLD_NOLOAD,
                        caller_addr,
                    );
                    if !handle.is_null() {
                        output_message(&format!(
                            "[linker api] dlopen({}, NOLOAD, caller={:#x}) = {:?}",
                            path, libart_base, handle
                        ));
                        return SyncPtr(handle);
                    }

                    let err = libc::dlerror();
                    if !err.is_null() {
                        let err_msg = std::ffi::CStr::from_ptr(err).to_string_lossy();
                        output_message(&format!(
                            "[linker api] dlopen({}, NOLOAD) failed: {}",
                            path, err_msg
                        ));
                    }
                }

                output_message("[linker api] all dlopen attempts failed");
            }
            SyncPtr(std::ptr::null_mut())
        })
        .0
}

/// Get a dlopen handle to an arbitrary module via unrestricted linker API.
///
/// hide_soinfo 摘除 agent soinfo 后，libc::dlopen 会导致 linker 内部空指针崩溃，
/// 因此跳过 standard dlopen fast path，直接走 unrestricted API。
unsafe fn module_dlopen(module_name: &str) -> *mut std::ffi::c_void {
    let c_name = CString::new(module_name).unwrap();

    // 直接走 unrestricted path（跳过 standard dlopen fast path）
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let base = find_module_base(module_name);
        if base != 0 {
            let caller_addr = base as *const std::ffi::c_void;
            let handle = (api.dlopen)(
                c_name.as_ptr() as *const i8,
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
                caller_addr,
            );
            if !handle.is_null() {
                return handle;
            }
        }

        // Try with trusted_caller as fallback
        let handle = (api.dlopen)(
            c_name.as_ptr() as *const i8,
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
            api.trusted_caller,
        );
        if !handle.is_null() {
            return handle;
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from an arbitrary module, bypassing linker namespace restrictions.
///
/// **Primary path**: directly parse the module's ELF `.symtab`/`.dynsym` from disk.
/// This bypasses the linker's namespace machinery entirely (which can silently
/// return NULL for cross-namespace `dlopen("libc.so", RTLD_NOLOAD)` on modern
/// Android even though the library is loaded).
///
/// **Fallback**: unrestricted linker `__loader_dlopen` + `__loader_dlvsym` for
/// modules whose backing file is not on disk (memfd, synthetic modules).
pub(crate) unsafe fn module_dlsym(module_name: &str, symbol: &str) -> *mut std::ffi::c_void {
    // Primary: direct ELF symbol lookup from disk file.
    if let Some((path, base)) = find_module_path_and_base(module_name) {
        let syms = elf_module_find_symbols(&path, base, &[symbol]);
        if let Some(&addr) = syms.get(symbol) {
            return addr as *mut std::ffi::c_void;
        }
    }

    // Fallback: unrestricted linker dlopen + dlvsym.
    // hide_soinfo 摘除 agent soinfo 后 libc::dlsym(RTLD_DEFAULT) 会崩溃，
    // 因此跳过 fast path 直接走 unrestricted API。
    let c_sym = CString::new(symbol).unwrap();
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let handle = module_dlopen(module_name);
        if !handle.is_null() {
            let addr = (api.dlsym)(
                handle,
                c_sym.as_ptr() as *const i8,
                std::ptr::null(),
                api.trusted_caller,
            );
            if !addr.is_null() {
                return addr;
            }
        }
    }

    std::ptr::null_mut()
}

/// Load a shared object from an existing memfd using the linker's trusted-caller API.
pub(crate) unsafe fn memfd_dlopen(name: &str, fd: i32) -> *mut std::ffi::c_void {
    let c_name = match CString::new(name) {
        Ok(value) => value,
        Err(_) => return std::ptr::null_mut(),
    };

    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        if let Some(android_dlopen_ext) = api.android_dlopen_ext {
            let extinfo = AndroidDlextinfo {
                flags: 0x10,
                reserved_addr: 0,
                reserved_size: 0,
                relro_fd: 0,
                library_fd: fd,
                library_fd_offset: 0,
                library_namespace: 0,
            };
            return android_dlopen_ext(
                c_name.as_ptr() as *const i8,
                libc::RTLD_NOW,
                &extinfo as *const _ as *const std::ffi::c_void,
                api.trusted_caller,
            );
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from libart.so, bypassing linker namespace restrictions.
///
/// hide_soinfo 摘除 agent soinfo 后，libc::dlsym(RTLD_DEFAULT) 会导致 linker
/// 内部空指针崩溃，因此跳过 fast path，直接走 unrestricted dlvsym。
pub(crate) unsafe fn libart_dlsym(name: &str) -> *mut std::ffi::c_void {
    let c_sym = CString::new(name).unwrap();

    // 直接走 unrestricted dlvsym（跳过 RTLD_DEFAULT fast path）
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let handle = get_libart_handle();
        if !handle.is_null() {
            let addr = (api.dlsym)(
                handle,
                c_sym.as_ptr() as *const i8,
                std::ptr::null(),
                api.trusted_caller,
            );
            if !addr.is_null() {
                return addr;
            }
        }
    }

    std::ptr::null_mut()
}

/// 在多个候选符号中查找第一个可用的（通过 libart_dlsym）
pub(crate) unsafe fn dlsym_first_match(candidates: &[&str]) -> u64 {
    for &sym_name in candidates {
        let addr = libart_dlsym(sym_name);
        if !addr.is_null() {
            return addr as u64;
        }
    }
    0
}

/// Check if an address falls within libart.so.
pub(crate) fn is_in_libart(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }
    let &(start, end) = LIBART_RANGE.get_or_init(probe_libart_range);
    if start == 0 && end == 0 {
        unsafe {
            let mut info: libc::Dl_info = std::mem::zeroed();
            if libc::dladdr(addr as *const std::ffi::c_void, &mut info) != 0 {
                if !info.dli_fname.is_null() {
                    let name = std::ffi::CStr::from_ptr(info.dli_fname).to_bytes();
                    return name.windows(9).any(|w| w == b"libart.so");
                }
            }
            false
        }
    } else {
        addr >= start && addr < end
    }
}

// ============================================================================
// soinfo traversal (Frida-style)
// ============================================================================

/// Walk the linker's soinfo linked list under dl_mutex.
/// Returns Vec<(base_addr, path)> for all loaded modules.
///
/// Reference: gum_enumerate_soinfo() at gumandroid.c:994
///
/// soinfo layout (API 26+):
///   soinfo starts with a ListEntry (prev, next) = 16 bytes
///   body = soinfo + 16 (API 26+) or soinfo + 12 (API 23-25)
///   body->next at body + 0x28 (40 bytes)
///   body->base at body + 0x80 (128 bytes, after phdr/phnum/entry/base)
#[allow(dead_code)]
unsafe fn enumerate_soinfo() -> Vec<(u64, String)> {
    let api = match UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api()) {
        Some(api) => api,
        None => return Vec::new(),
    };

    // Get soinfo list head
    let head: *mut std::ffi::c_void = if let Some(get_head) = api.solist_get_head {
        get_head()
    } else if !api.solist.is_null() {
        *api.solist
    } else {
        return Vec::new();
    };

    if head.is_null() {
        return Vec::new();
    }

    let soinfo_get_path = match api.soinfo_get_path {
        Some(f) => f,
        None => return Vec::new(),
    };

    let mut result = Vec::new();

    // Lock dl_mutex for thread safety
    let has_mutex = !api.dl_mutex.is_null();
    if has_mutex {
        libc::pthread_mutex_lock(api.dl_mutex);
    }

    let mut current = head;
    let mut count = 0u32;
    while !current.is_null() && count < 4096 {
        count += 1;

        // Get path via soinfo::get_realpath()
        let path_ptr = soinfo_get_path(current);
        let path = if !path_ptr.is_null() {
            std::ffi::CStr::from_ptr(path_ptr)
                .to_string_lossy()
                .to_string()
        } else {
            String::new()
        };

        // soinfo body: skip ListEntry header (16 bytes on API 26+)
        // body->base is at a known offset — but varies by Android version.
        // For the JS API we use /proc/self/maps instead (more reliable).
        // Here we just collect paths for namespace-aware dlopen.
        let base = find_module_base_for_path(&path);
        if base != 0 || !path.is_empty() {
            result.push((base, path));
        }

        // next soinfo: soinfo is a linked list via ListEntry at offset 0
        // ListEntry { next: *mut soinfo, prev: *mut soinfo }
        // next is at offset 0
        let next = *(current as *const *mut std::ffi::c_void);
        current = next;
    }

    if has_mutex {
        libc::pthread_mutex_unlock(api.dl_mutex);
    }

    result
}

/// Find base address for a given full path from /proc/self/maps.
fn find_module_base_for_path(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };
    let base = crate::jsapi::util::proc_maps_entries(&maps)
        .find_map(|entry| (entry.path == Some(path)).then_some(entry.start))
        .unwrap_or(0);
    base
}
