// ============================================================================
// Linker info + init
// ============================================================================

/// Find linker64 base address and file path from /proc/self/maps.
fn find_linker_info() -> (u64, String) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, String::new()),
    };

    for entry in crate::jsapi::util::proc_maps_entries(&maps) {
        let Some(path) = entry.path else {
            continue;
        };
        if path.contains("linker64") && !path.contains(".so") {
            return (entry.start, path.to_string());
        }
    }
    (0, String::new())
}

/// Initialize the unrestricted linker API (Frida-style).
///
/// One read, one pass through .symtab — batch-extract all needed linker symbols.
/// Falls back to reading from in-memory ELF if file not readable.
///
/// Reference: gum_linker_api_try_init() in gumandroid.c:1127
unsafe fn init_unrestricted_linker_api() -> Option<UnrestrictedLinkerApi> {
    let (linker_base, linker_path) = find_linker_info();
    if linker_base == 0 || linker_path.is_empty() {
        output_message("[linker api] linker64 not found in /proc/self/maps");
        return None;
    }

    output_message(&format!(
        "[linker api] linker64 base={:#x}, path={}",
        linker_base, linker_path
    ));

    // Batch lookup all needed symbols in one pass (Frida-style)
    let symbols = elf_module_find_symbols(
        &linker_path,
        linker_base,
        &[
            // dlopen/dlvsym (API 28+)
            "__dl___loader_dlopen",
            "__dl___loader_android_dlopen_ext",
            "__dl___loader_dlvsym",
            // dlopen/dlvsym (API 26-27 fallback)
            "__loader_android_dlopen_ext",
            "__dl__Z8__dlopenPKciPKv",
            "__dl__Z8__dlvsymPvPKcS1_PKv",
            // Linker internals (Frida's gum_store_linker_symbol_if_needed)
            "__dl_g_dl_mutex",       // API 24+ (extern "C", no mangling)
            "__dl__ZL10g_dl_mutex",  // API 21-23 (C++ internal linkage)
            "__dl__ZL8gDlMutex",     // < API 21
            "__dl__Z15solist_get_headv",
            "__dl__ZL6solist",
            "__dl__ZNK6soinfo12get_realpathEv",
            "__dl__ZNK6soinfo7get_pathEv", // older fallback
        ],
    );

    output_message(&format!(
        "[linker api] found {} symbols in one pass",
        symbols.len()
    ));
    for (name, addr) in &symbols {
        output_message(&format!("[linker api]   {}={:#x}", name, addr));
    }

    // Extract dlopen: prefer API 28+ name, fallback to API 26-27
    let dlopen_addr = symbols
        .get("__dl___loader_dlopen")
        .or_else(|| symbols.get("__dl__Z8__dlopenPKciPKv"))
        .copied();
    let dlsym_addr = symbols
        .get("__dl___loader_dlvsym")
        .or_else(|| symbols.get("__dl__Z8__dlvsymPvPKcS1_PKv"))
        .copied();
    let android_dlopen_ext_addr = symbols
        .get("__dl___loader_android_dlopen_ext")
        .or_else(|| symbols.get("__loader_android_dlopen_ext"))
        .copied();

    if dlopen_addr.is_none() || dlsym_addr.is_none() {
        output_message(&format!(
            "[linker api] dlopen/dlsym not found: dlopen={:?}, dlsym={:?}",
            dlopen_addr, dlsym_addr
        ));
        return None;
    }

    let dlopen_addr = dlopen_addr.unwrap();
    let dlsym_addr = dlsym_addr.unwrap();

    // 使用已解析的 linker 符号地址作为 trusted_caller（避免 dlsym 依赖）
    // hide_soinfo.c 的 .init_array 会在 dlopen 时摘除 agent 的 soinfo，
    // 导致后续 dlsym(RTLD_DEFAULT, ...) 因找不到 caller 的 soinfo 而失败。
    // 直接用 linker64 内部地址作为 trusted_caller 绕过此问题。
    let trusted_caller = dlopen_addr as *mut std::ffi::c_void;

    output_message(&format!(
        "[linker api] unrestricted API: dlopen={:#x}, dlsym={:#x}, trusted_caller={:#x}",
        dlopen_addr, dlsym_addr, trusted_caller as u64
    ));

    // Extract optional linker internals
    let dl_mutex = symbols
        .get("__dl_g_dl_mutex")
        .or_else(|| symbols.get("__dl__ZL10g_dl_mutex"))
        .or_else(|| symbols.get("__dl__ZL8gDlMutex"))
        .map(|&addr| addr as *mut libc::pthread_mutex_t)
        .unwrap_or_else(|| {
            output_message("[linker api] dl_mutex not found");
            std::ptr::null_mut()
        });

    let solist_get_head: Option<unsafe extern "C" fn() -> *mut std::ffi::c_void> = symbols
        .get("__dl__Z15solist_get_headv")
        .map(|&addr| std::mem::transmute(addr));

    let solist = symbols
        .get("__dl__ZL6solist")
        .map(|&addr| addr as *mut *mut std::ffi::c_void)
        .unwrap_or(std::ptr::null_mut());

    let soinfo_get_path: Option<
        unsafe extern "C" fn(*mut std::ffi::c_void) -> *const std::os::raw::c_char,
    > = symbols
        .get("__dl__ZNK6soinfo12get_realpathEv")
        .or_else(|| symbols.get("__dl__ZNK6soinfo7get_pathEv"))
        .map(|&addr| std::mem::transmute(addr));
    if soinfo_get_path.is_none() {
        output_message("[linker api] soinfo_get_path not found");
    }

    Some(UnrestrictedLinkerApi {
        dlopen: std::mem::transmute(dlopen_addr),
        android_dlopen_ext: android_dlopen_ext_addr.map(|addr| std::mem::transmute(addr)),
        dlsym: std::mem::transmute(dlsym_addr),
        trusted_caller: trusted_caller as *const std::ffi::c_void,
        dl_mutex,
        solist_get_head,
        solist,
        soinfo_get_path,
    })
}
