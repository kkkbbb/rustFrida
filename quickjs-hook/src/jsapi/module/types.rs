// ============================================================================
// ELF types
// ============================================================================

/// ELF64 header
#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    _e_machine: u16,
    _e_version: u32,
    _e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    _e_flags: u32,
    _e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    _e_shentsize: u16,
    e_shnum: u16,
    _e_shstrndx: u16,
}

/// ELF64 program header
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    _p_flags: u32,
    _p_offset: u64,
    p_vaddr: u64,
    _p_paddr: u64,
    _p_filesz: u64,
    _p_memsz: u64,
    _p_align: u64,
}

/// ELF64 symbol table entry
#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    _st_other: u8,
    st_shndx: u16,
    st_value: u64,
    _st_size: u64,
}

impl Elf64Sym {
    /// ELF64_ST_TYPE(st_info): low nibble is symbol type.
    #[inline]
    fn st_type(&self) -> u8 {
        self.st_info & 0xf
    }

    /// ELF64_ST_BIND(st_info): high nibble is binding class (LOCAL/GLOBAL/WEAK).
    #[inline]
    fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }
}

/// ELF64 RELA relocation entry (aarch64 always uses RELA).
#[repr(C)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    _r_addend: i64,
}

impl Elf64Rela {
    #[inline]
    fn r_sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    #[inline]
    fn r_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

/// ELF64 section header (for reading .symtab from file)
#[repr(C)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    _sh_flags: u64,
    _sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    _sh_info: u32,
    _sh_addralign: u64,
    sh_entsize: u64,
}

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;

/// Special section index: undefined (imported) symbol.
const SHN_UNDEF: u16 = 0;

/// Symbol bindings (upper nibble of st_info).
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

/// Symbol types (lower nibble of st_info).
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
/// GNU extension: symbol is an indirect function resolver (IFUNC).
/// The `st_value` is a resolver function to be called at runtime to get
/// the actual implementation address.
const STT_GNU_IFUNC: u8 = 10;

/// AArch64 dynamic relocation types (relevant subset).
const R_AARCH64_ABS64: u32 = 257;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;

// ============================================================================
// Unrestricted linker API — Frida-style namespace bypass
// Reference: frida-gum/gum/backend-linux/gumandroid.c
// ============================================================================

/// Cached unrestricted linker API function pointers.
struct UnrestrictedLinkerApi {
    /// __dl___loader_dlopen(filename, flags, caller_addr) -> handle
    dlopen: unsafe extern "C" fn(*const i8, i32, *const std::ffi::c_void) -> *mut std::ffi::c_void,
    /// __dl___loader_android_dlopen_ext(filename, flags, extinfo, caller_addr) -> handle
    android_dlopen_ext: Option<
        unsafe extern "C" fn(
            *const i8,
            i32,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> *mut std::ffi::c_void,
    >,
    /// __dl___loader_dlvsym(handle, symbol, version, caller_addr) -> addr
    dlsym: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *const i8,
        *const i8,
        *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void,
    /// Trusted caller address (linker64 内部地址，dlopen_addr)
    trusted_caller: *const std::ffi::c_void,
    /// dl_mutex — __dl__ZL10g_dl_mutex
    dl_mutex: *mut libc::pthread_mutex_t,
    /// solist_get_head() — __dl__Z15solist_get_headv
    solist_get_head: Option<unsafe extern "C" fn() -> *mut std::ffi::c_void>,
    /// solist global variable (fallback) — __dl__ZL6solist
    solist: *mut *mut std::ffi::c_void,
    /// soinfo::get_realpath() — __dl__ZNK6soinfo12get_realpathEv
    soinfo_get_path:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> *const std::os::raw::c_char>,
}

unsafe impl Send for UnrestrictedLinkerApi {}
unsafe impl Sync for UnrestrictedLinkerApi {}

static UNRESTRICTED_LINKER_API: std::sync::OnceLock<Option<UnrestrictedLinkerApi>> =
    std::sync::OnceLock::new();

/// Newtype wrapper for *mut c_void to implement Send+Sync
pub(crate) struct SyncPtr(pub(crate) *mut std::ffi::c_void);
unsafe impl Send for SyncPtr {}
unsafe impl Sync for SyncPtr {}

static LIBART_HANDLE: std::sync::OnceLock<SyncPtr> = std::sync::OnceLock::new();

/// Cached libart.so address range (start, end).
pub(crate) static LIBART_RANGE: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

/// Cached libart.so full file path.
static LIBART_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
