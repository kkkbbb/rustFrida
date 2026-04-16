// ============================================================================
// ELF symbol lookup — Frida-style (gum_elf_module)
//
// Strategy: file from disk first, memory at base_address as fallback.
// One read, one pass through .symtab, batch-extract all needed symbols.
//
// Reference: gumelfmodule.c — gum_elf_module_load_file_data():
//   1. g_mapped_file_new(path) → mmap from disk
//   2. If file not readable (ONLINE mode) → use base_address as data pointer
// ============================================================================

/// Batch lookup symbols from an ELF module's `.symtab` or `.dynsym`.
///
/// Strategy (Frida-style, gum_elf_module):
/// 1. Try read file from disk → parse `.symtab`/`.dynsym` in one pass
/// 2. If file not accessible → read from in-memory ELF mapping at base_address
///
/// **IFUNC handling**: on Android ARM64, libc exports many symbols
/// (`strlen`, `memcpy`, `strcmp`, ...) as `STT_GNU_IFUNC`. The `.symtab`
/// address is the *resolver*, not the real implementation. We detect
/// IFUNC entries and call the resolver with the bionic (hwcap, &arg)
/// convention so the returned address matches `dlsym()`.
///
/// Returns HashMap of found symbols: name -> resolved runtime address.
unsafe fn elf_module_find_symbols(
    file_path: &str,
    base_address: u64,
    wanted: &[&str],
) -> HashMap<String, u64> {
    if wanted.is_empty() {
        return HashMap::new();
    }

    let wanted_set: HashSet<&str> = wanted.iter().copied().collect();
    let mut result = HashMap::new();
    let mut ifunc_names: HashSet<String> = HashSet::new();

    // Compute load_bias from in-memory program headers
    let load_bias = elf_compute_load_bias(base_address);

    // Strategy 1: read file from disk (one read, one pass).
    // If the file read succeeds we trust the result — an empty map just means
    // the symbol isn't exported by this module. Falling through to the memory
    // strategy only makes sense when the disk path is unreadable.
    let file_read_ok = if let Ok(data) = std::fs::read(file_path) {
        elf_find_symbols_in_data(&data, &wanted_set, load_bias, &mut result, &mut ifunc_names);
        true
    } else {
        false
    };

    if !file_read_ok {
        // Strategy 2: read from in-memory ELF at base_address (Frida fallback).
        // Section headers usually are not in any PT_LOAD for stripped libs, so
        // this rarely succeeds — keep the diagnostic in verbose mode only.
        crate::jsapi::console::output_verbose(&format!(
            "[module] file read failed for {}, trying memory at {:#x}",
            file_path, base_address
        ));
        elf_find_symbols_in_memory(
            base_address,
            &wanted_set,
            load_bias,
            &mut result,
            &mut ifunc_names,
        );
    }

    resolve_ifunc_entries(&ifunc_names, &mut result);
    result
}

/// Bionic's ARM64 IFUNC resolver argument block.
/// Reference: `linker/linker_relocate.cpp`.
#[repr(C)]
struct IfuncArg {
    size: u64,
    hwcap: u64,
    hwcap2: u64,
}

const IFUNC_ARG_HWCAP: u64 = 1 << 62;

/// Lazily-initialized (hwcap_arg, ifunc_arg) tuple reused by every IFUNC call.
fn ifunc_resolver_context() -> (u64, &'static IfuncArg) {
    static CTX: std::sync::OnceLock<(u64, IfuncArg)> = std::sync::OnceLock::new();
    let cached = CTX.get_or_init(|| unsafe {
        let arg = IfuncArg {
            size: std::mem::size_of::<IfuncArg>() as u64,
            hwcap: libc::getauxval(libc::AT_HWCAP),
            hwcap2: libc::getauxval(libc::AT_HWCAP2),
        };
        let hwcap_arg = arg.hwcap | IFUNC_ARG_HWCAP;
        (hwcap_arg, arg)
    });
    (cached.0, &cached.1)
}

/// Call an IFUNC resolver with the bionic (hwcap, &arg) ABI; returns the resolved
/// runtime address, or 0 if the resolver returns null.
unsafe fn resolve_ifunc_address(resolver_addr: u64) -> u64 {
    if resolver_addr == 0 {
        return 0;
    }
    type IfuncResolver = unsafe extern "C" fn(u64, *const IfuncArg) -> u64;
    let resolver: IfuncResolver = std::mem::transmute(resolver_addr);
    let (hwcap_arg, arg) = ifunc_resolver_context();
    resolver(hwcap_arg, arg)
}

/// Call IFUNC resolvers to replace resolver addresses with real implementation
/// addresses for symbols captured by the batch lookup above.
unsafe fn resolve_ifunc_entries(ifunc_names: &HashSet<String>, result: &mut HashMap<String, u64>) {
    for name in ifunc_names {
        let Some(resolver_addr) = result.get(name).copied() else {
            continue;
        };
        let resolved = resolve_ifunc_address(resolver_addr);
        if resolved != 0 {
            result.insert(name.clone(), resolved);
        }
    }
}

/// Compute load_bias from in-memory ELF at base_address.
/// load_bias = base_address - first_PT_LOAD.p_vaddr
unsafe fn elf_compute_load_bias(base_address: u64) -> u64 {
    if base_address == 0 {
        return 0;
    }
    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return base_address;
    }
    let phdr_base = base_address + ehdr.e_phoff;
    for i in 0..ehdr.e_phnum as u64 {
        let phdr = &*((phdr_base + i * ehdr.e_phentsize as u64) as *const Elf64Phdr);
        if phdr.p_type == PT_LOAD {
            return base_address.wrapping_sub(phdr.p_vaddr);
        }
    }
    base_address
}

/// Find symbols in .symtab/.dynsym from file data (byte slice). One pass.
/// Symbols whose type is `STT_GNU_IFUNC` have their names recorded in
/// `ifunc_names` so the caller can resolve them after parsing.
fn elf_find_symbols_in_data(
    data: &[u8],
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
    ifunc_names: &mut HashSet<String>,
) {
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return;
    }

    unsafe {
        let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
            return;
        }

        let shdr_off = ehdr.e_shoff as usize;
        let shdr_size = std::mem::size_of::<Elf64Shdr>();
        let shnum = ehdr.e_shnum as usize;

        if shdr_off == 0 || shdr_off + shnum * shdr_size > data.len() {
            return;
        }

        // Find SHT_SYMTAB first (more complete), fall back to SHT_DYNSYM for stripped libs.
        let mut symtab_shdr: Option<&Elf64Shdr> = None;
        let mut dynsym_shdr: Option<&Elf64Shdr> = None;
        for i in 0..shnum {
            let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
            match shdr.sh_type {
                SHT_SYMTAB if symtab_shdr.is_none() => symtab_shdr = Some(shdr),
                SHT_DYNSYM if dynsym_shdr.is_none() => dynsym_shdr = Some(shdr),
                _ => {}
            }
        }

        let symtab = match symtab_shdr.or(dynsym_shdr) {
            Some(s) => s,
            None => return,
        };

        let strtab_idx = symtab.sh_link as usize;
        if strtab_idx >= shnum {
            return;
        }
        let strtab_shdr =
            &*(data.as_ptr().add(shdr_off + strtab_idx * shdr_size) as *const Elf64Shdr);
        if strtab_shdr.sh_type != SHT_STRTAB {
            return;
        }

        let strtab_off = strtab_shdr.sh_offset as usize;
        let strtab_size = strtab_shdr.sh_size as usize;
        if strtab_off + strtab_size > data.len() {
            return;
        }

        let symtab_off = symtab.sh_offset as usize;
        let sym_size = if symtab.sh_entsize > 0 {
            symtab.sh_entsize as usize
        } else {
            std::mem::size_of::<Elf64Sym>()
        };
        let nsyms = symtab.sh_size as usize / sym_size;

        if symtab_off + nsyms * sym_size > data.len() {
            return;
        }

        let mut remaining = wanted.len();

        for idx in 0..nsyms {
            if remaining == 0 {
                break;
            }

            let sym = &*(data.as_ptr().add(symtab_off + idx * sym_size) as *const Elf64Sym);
            if sym.st_name == 0 || sym.st_value == 0 {
                continue;
            }

            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= strtab_off + strtab_size {
                continue;
            }

            // Read null-terminated name
            let name_slice = &data[name_off..strtab_off + strtab_size];
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
            if name_len == 0 {
                continue;
            }

            if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
                if wanted.contains(name) && !result.contains_key(name) {
                    result.insert(name.to_string(), load_bias + sym.st_value);
                    if sym.st_type() == STT_GNU_IFUNC {
                        ifunc_names.insert(name.to_string());
                    }
                    remaining -= 1;
                }
            }
        }
    }
}

/// Find symbols in .symtab/.dynsym from in-memory ELF at base_address.
///
/// Fallback when file is not readable on disk.
/// Uses mincore(2) to check page accessibility before each read.
///
/// Reference: gumelfmodule.c line 570-572 — ONLINE mode fallback:
///   self->file_bytes = g_bytes_new_static(base_address, G_MAXSIZE - base_address)
unsafe fn elf_find_symbols_in_memory(
    base_address: u64,
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
    ifunc_names: &mut HashSet<String>,
) {
    if base_address == 0 {
        return;
    }

    // Check ELF header accessible
    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return;
    }

    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shnum = ehdr.e_shnum as usize;
    let shdr_addr = base_address + ehdr.e_shoff;

    // Check section headers accessible
    if !is_addr_accessible(shdr_addr, shnum * shdr_size) {
        crate::jsapi::console::output_verbose("[module] section headers not accessible in memory");
        return;
    }

    // Find SHT_SYMTAB first (more complete), fall back to SHT_DYNSYM for stripped libs.
    let mut symtab_shdr: Option<Elf64ShdrCopy> = None;
    let mut dynsym_shdr: Option<Elf64ShdrCopy> = None;
    for i in 0..shnum {
        let shdr = &*((shdr_addr as usize + i * shdr_size) as *const Elf64Shdr);
        let copy = Elf64ShdrCopy {
            sh_offset: shdr.sh_offset,
            sh_size: shdr.sh_size,
            sh_link: shdr.sh_link,
            sh_entsize: shdr.sh_entsize,
        };
        match shdr.sh_type {
            SHT_SYMTAB if symtab_shdr.is_none() => symtab_shdr = Some(copy),
            SHT_DYNSYM if dynsym_shdr.is_none() => dynsym_shdr = Some(copy),
            _ => {}
        }
    }

    let symtab = match symtab_shdr.or(dynsym_shdr) {
        Some(s) => s,
        None => {
            crate::jsapi::console::output_verbose(
                "[module] .symtab/.dynsym not found in memory ELF",
            );
            return;
        }
    };

    let strtab_idx = symtab.sh_link as usize;
    if strtab_idx >= shnum {
        return;
    }
    let strtab_shdr = &*((shdr_addr as usize + strtab_idx * shdr_size) as *const Elf64Shdr);
    if strtab_shdr.sh_type != SHT_STRTAB {
        return;
    }

    // Check .symtab and .strtab data accessible
    let symtab_data_addr = base_address + symtab.sh_offset;
    let strtab_data_addr = base_address + strtab_shdr.sh_offset;

    let sym_size = if symtab.sh_entsize > 0 {
        symtab.sh_entsize as usize
    } else {
        std::mem::size_of::<Elf64Sym>()
    };
    let nsyms = symtab.sh_size as usize / sym_size;
    let strtab_size = strtab_shdr.sh_size as usize;

    if !is_addr_accessible(symtab_data_addr, nsyms * sym_size) {
        crate::jsapi::console::output_verbose("[module] .symtab data not accessible in memory");
        return;
    }
    if !is_addr_accessible(strtab_data_addr, strtab_size) {
        crate::jsapi::console::output_verbose("[module] .strtab data not accessible in memory");
        return;
    }

    crate::jsapi::console::output_verbose(&format!(
        "[module] reading .symtab from memory: {} symbols",
        nsyms
    ));

    let mut remaining = wanted.len();

    for idx in 0..nsyms {
        if remaining == 0 {
            break;
        }

        let sym = &*((symtab_data_addr as usize + idx * sym_size) as *const Elf64Sym);
        if sym.st_name == 0 || sym.st_value == 0 {
            continue;
        }

        let name_off = sym.st_name as usize;
        if name_off >= strtab_size {
            continue;
        }

        let name_ptr = (strtab_data_addr as usize + name_off) as *const u8;
        let max_len = strtab_size - name_off;
        let name_slice = std::slice::from_raw_parts(name_ptr, max_len);
        let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
        if name_len == 0 {
            continue;
        }

        if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
            if wanted.contains(name) && !result.contains_key(name) {
                result.insert(name.to_string(), load_bias + sym.st_value);
                if sym.st_type() == STT_GNU_IFUNC {
                    ifunc_names.insert(name.to_string());
                }
                remaining -= 1;
            }
        }
    }
}

/// Minimal copy of Elf64Shdr fields needed for .symtab processing.
/// Avoids holding a reference into memory that might be invalidated.
struct Elf64ShdrCopy {
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}
