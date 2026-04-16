// ============================================================================
// ELF full-module enumeration: exports, imports, symbols + range filter.
//
// Strategy mirrors `elf.rs`: parse on-disk ELF first (always complete),
// skip in-memory fallback (stripped libs rarely expose section headers in
// any PT_LOAD, so a memory pass adds complexity without coverage).
// IFUNC resolvers are invoked via `resolve_ifunc_address` so the reported
// address matches what `dlsym` would return at runtime.
// ============================================================================

/// Defined symbol record (enumerateExports / enumerateSymbols).
struct SymbolRecord {
    name: String,
    /// Resolved runtime address (post-IFUNC). 0 means undefined or weak-absent.
    address: u64,
    /// "function" or "variable"
    kind: &'static str,
    /// STB_GLOBAL or STB_WEAK
    is_global: bool,
    /// st_shndx != SHN_UNDEF
    is_defined: bool,
}

/// Import record (enumerateImports).
///
/// `slot` is the GOT/PLT entry address within this module; `address` is the
/// current value stored in that slot (i.e. the resolved target, or 0 if not
/// yet bound or the slot is unmapped).
struct ImportRecord {
    name: String,
    kind: &'static str,
    slot: u64,
    address: u64,
}

/// Memory range record (enumerateRanges).
struct RangeRecord {
    base: u64,
    size: u64,
    /// Three-char "rwx"-style protection derived from /proc/self/maps perms.
    protection: String,
    path: String,
}

/// Enumerate every named symbol from the module's .symtab and .dynsym.
/// Names are de-duplicated (.symtab wins when both sections list the same name).
unsafe fn elf_module_enumerate_symbols(file_path: &str, base_address: u64) -> Vec<SymbolRecord> {
    let data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let load_bias = elf_compute_load_bias(base_address);
    enumerate_symbols_in_data(&data, load_bias)
}

unsafe fn enumerate_symbols_in_data(data: &[u8], load_bias: u64) -> Vec<SymbolRecord> {
    let mut out = Vec::new();
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return out;
    }
    let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return out;
    }

    let shdr_off = ehdr.e_shoff as usize;
    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shnum = ehdr.e_shnum as usize;
    if shdr_off == 0 || shdr_off + shnum * shdr_size > data.len() {
        return out;
    }

    let mut seen: HashSet<String> = HashSet::new();
    // SHT_SYMTAB first (more complete); SHT_DYNSYM fills gaps on stripped libs.
    for &target_type in &[SHT_SYMTAB, SHT_DYNSYM] {
        for i in 0..shnum {
            let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
            if shdr.sh_type != target_type {
                continue;
            }
            collect_symbols_from_section(data, shdr, shdr_off, shnum, load_bias, &mut seen, &mut out);
        }
    }
    out
}

unsafe fn collect_symbols_from_section(
    data: &[u8],
    symtab: &Elf64Shdr,
    shdr_off: usize,
    shnum: usize,
    load_bias: u64,
    seen: &mut HashSet<String>,
    out: &mut Vec<SymbolRecord>,
) {
    let shdr_size = std::mem::size_of::<Elf64Shdr>();

    let strtab_idx = symtab.sh_link as usize;
    if strtab_idx >= shnum {
        return;
    }
    let strtab_shdr = &*(data.as_ptr().add(shdr_off + strtab_idx * shdr_size) as *const Elf64Shdr);
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

    for idx in 0..nsyms {
        let sym = &*(data.as_ptr().add(symtab_off + idx * sym_size) as *const Elf64Sym);
        if sym.st_name == 0 {
            continue;
        }

        let name_off = strtab_off + sym.st_name as usize;
        if name_off >= strtab_off + strtab_size {
            continue;
        }
        let name_slice = &data[name_off..strtab_off + strtab_size];
        let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
        if name_len == 0 {
            continue;
        }
        let name = match std::str::from_utf8(&name_slice[..name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        if !seen.insert(name.clone()) {
            continue;
        }

        let bind = sym.st_bind();
        let typ = sym.st_type();
        let kind: &'static str = match typ {
            STT_FUNC | STT_GNU_IFUNC => "function",
            STT_OBJECT => "variable",
            _ => "variable",
        };
        let is_global = bind == STB_GLOBAL || bind == STB_WEAK;
        let is_defined = sym.st_shndx != SHN_UNDEF;

        let mut address = if is_defined && sym.st_value != 0 {
            load_bias + sym.st_value
        } else {
            0
        };
        if typ == STT_GNU_IFUNC && address != 0 {
            let resolved = resolve_ifunc_address(address);
            if resolved != 0 {
                address = resolved;
            }
        }

        out.push(SymbolRecord {
            name,
            address,
            kind,
            is_global,
            is_defined,
        });
    }
}

/// Handle of the module's `.dynsym` + associated `.dynstr` section.
struct DynsymView {
    dynsym_off: usize,
    dynstr_off: usize,
    dynstr_size: usize,
    sym_entsize: usize,
}

unsafe fn find_dynsym_view(data: &[u8], ehdr: &Elf64Ehdr) -> Option<DynsymView> {
    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shdr_off = ehdr.e_shoff as usize;
    let shnum = ehdr.e_shnum as usize;
    if shdr_off == 0 || shdr_off + shnum * shdr_size > data.len() {
        return None;
    }

    for i in 0..shnum {
        let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
        if shdr.sh_type != SHT_DYNSYM {
            continue;
        }
        let strtab_idx = shdr.sh_link as usize;
        if strtab_idx >= shnum {
            return None;
        }
        let strtab_shdr =
            &*(data.as_ptr().add(shdr_off + strtab_idx * shdr_size) as *const Elf64Shdr);
        if strtab_shdr.sh_type != SHT_STRTAB {
            return None;
        }
        let strtab_off = strtab_shdr.sh_offset as usize;
        let strtab_size = strtab_shdr.sh_size as usize;
        if strtab_off + strtab_size > data.len() {
            return None;
        }
        return Some(DynsymView {
            dynsym_off: shdr.sh_offset as usize,
            dynstr_off: strtab_off,
            dynstr_size: strtab_size,
            sym_entsize: if shdr.sh_entsize > 0 {
                shdr.sh_entsize as usize
            } else {
                std::mem::size_of::<Elf64Sym>()
            },
        });
    }
    None
}

/// Enumerate every undefined (imported) symbol referenced by the module's
/// dynamic relocations (.rela.dyn + .rela.plt).
unsafe fn elf_module_enumerate_imports(file_path: &str, base_address: u64) -> Vec<ImportRecord> {
    let data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let load_bias = elf_compute_load_bias(base_address);
    enumerate_imports_in_data(&data, load_bias)
}

unsafe fn enumerate_imports_in_data(data: &[u8], load_bias: u64) -> Vec<ImportRecord> {
    let mut out = Vec::new();
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return out;
    }
    let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return out;
    }
    let dynsym = match find_dynsym_view(data, ehdr) {
        Some(v) => v,
        None => return out,
    };

    let shdr_off = ehdr.e_shoff as usize;
    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shnum = ehdr.e_shnum as usize;

    // De-dup by name (Frida semantics): a symbol that is both called (PLT) and
    // address-taken (GOT) would otherwise appear twice with different slots —
    // we keep only the first slot encountered.
    let mut seen: HashSet<String> = HashSet::new();

    for i in 0..shnum {
        let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
        if shdr.sh_type != SHT_RELA {
            continue;
        }
        let rela_off = shdr.sh_offset as usize;
        let rela_ent = if shdr.sh_entsize > 0 {
            shdr.sh_entsize as usize
        } else {
            std::mem::size_of::<Elf64Rela>()
        };
        let nrelas = shdr.sh_size as usize / rela_ent;
        if rela_off + nrelas * rela_ent > data.len() {
            continue;
        }

        for r in 0..nrelas {
            let rel = &*(data.as_ptr().add(rela_off + r * rela_ent) as *const Elf64Rela);
            let sym_idx = rel.r_sym() as usize;
            if sym_idx == 0 {
                continue;
            }
            let sym_off = dynsym.dynsym_off + sym_idx * dynsym.sym_entsize;
            if sym_off + dynsym.sym_entsize > data.len() {
                continue;
            }
            let sym = &*(data.as_ptr().add(sym_off) as *const Elf64Sym);
            // Only undefined symbols qualify as imports.
            if sym.st_shndx != SHN_UNDEF || sym.st_name == 0 {
                continue;
            }

            let name_off = dynsym.dynstr_off + sym.st_name as usize;
            if name_off >= dynsym.dynstr_off + dynsym.dynstr_size {
                continue;
            }
            let name_slice = &data[name_off..dynsym.dynstr_off + dynsym.dynstr_size];
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
            if name_len == 0 {
                continue;
            }
            let name = match std::str::from_utf8(&name_slice[..name_len]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            if !seen.insert(name.clone()) {
                continue;
            }
            let slot = load_bias.wrapping_add(rel.r_offset);

            let sym_type = sym.st_type();
            let kind: &'static str = match rel.r_type() {
                R_AARCH64_JUMP_SLOT => "function",
                R_AARCH64_GLOB_DAT | R_AARCH64_ABS64 => match sym_type {
                    STT_FUNC | STT_GNU_IFUNC => "function",
                    _ => "variable",
                },
                _ => match sym_type {
                    STT_FUNC | STT_GNU_IFUNC => "function",
                    _ => "variable",
                },
            };

            // Try to read the slot for the currently-bound address. Guard with
            // mincore — modules whose GOT pages were mprotect'd out will fail.
            let address = if crate::jsapi::util::is_addr_accessible(slot, 8) {
                *(slot as *const u64)
            } else {
                0
            };

            out.push(ImportRecord {
                name,
                kind,
                slot,
                address,
            });
        }
    }
    out
}

/// Enumerate VMAs of a module, optionally filtered by Frida-style protection
/// (e.g. "r-x" matches rw- pages when the filter has '-' in the write slot).
fn enumerate_module_ranges(module_name: &str, prot_filter: Option<&str>) -> Vec<RangeRecord> {
    let maps = match crate::jsapi::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    crate::jsapi::util::proc_maps_entries(&maps)
        .filter_map(|entry| {
            let path = entry.path?;
            if !matches_module_lookup_name(path, module_name) {
                return None;
            }
            let prot3_end = entry.perms.len().min(3);
            let prot3 = &entry.perms[..prot3_end];
            if prot3.len() < 3 {
                return None;
            }
            if let Some(filter) = prot_filter {
                if !protection_matches(prot3, filter) {
                    return None;
                }
            }
            Some(RangeRecord {
                base: entry.start,
                size: entry.end - entry.start,
                protection: prot3.to_string(),
                path: path.to_string(),
            })
        })
        .collect()
}

/// Frida-compatible protection matcher. Each slot in `filter` either names a
/// required flag ('r', 'w', 'x') or is '-' (wildcard). A page `rwx` satisfies
/// filter `r-x`; `r--` does not satisfy `r-x`.
fn protection_matches(actual: &str, filter: &str) -> bool {
    let a = actual.as_bytes();
    let f = filter.as_bytes();
    if f.len() != 3 || a.len() < 3 {
        return false;
    }
    for i in 0..3 {
        let want = f[i];
        if want != b'-' && want != a[i] {
            return false;
        }
    }
    true
}
