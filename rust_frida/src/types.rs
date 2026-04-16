#![cfg(all(target_os = "android", target_arch = "aarch64"))]

/// 获取所有可用的字符串名称（用于 CLI --string 参数验证）
pub(crate) fn get_string_table_names() -> Vec<&'static str> {
    vec!["sym_name", "pthread_err", "dlsym_err", "cmdline", "output_path"]
}

/// 用户空间寄存器结构体
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UserRegs {
    pub(crate) regs: [u64; 31], // X0-X30 寄存器
    pub(crate) sp: u64,         // SP 栈指针
    pub(crate) pc: u64,         // PC 程序计数器
    pub(crate) pstate: u64,     // 处理器状态
}

/// ARM64 FP/SIMD 寄存器结构体 (NT_FPREGSET / NT_PRFPREG)
/// 对应 Linux struct user_fpsimd_state (asm/ptrace.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UserFpRegs {
    pub(crate) vregs: [u128; 32], // V0-V31 (128-bit SIMD 寄存器)
    pub(crate) fpsr: u32,         // 浮点状态寄存器
    pub(crate) fpcr: u32,         // 浮点控制寄存器
}

impl Default for UserFpRegs {
    fn default() -> Self {
        // 不能用 derive(Default) 因为 [u128; 32] 没有 Default
        unsafe { std::mem::zeroed() }
    }
}

// =============================================================================
// Frida-style 注入框架结构体
// ABI 关键：必须与 loader/helpers/ 中的 C 结构体布局完全一致
// =============================================================================

/// Frida bootstrapper 返回状态码
#[allow(dead_code)]
pub(crate) mod bootstrap_status {
    pub const ALLOCATION_SUCCESS: usize = 0;
    pub const ALLOCATION_ERROR: usize = 1;
    pub const SUCCESS: usize = 2;
    pub const AUXV_NOT_FOUND: usize = 3;
    pub const TOO_EARLY: usize = 4;
    pub const LIBC_LOAD_ERROR: usize = 5;
    pub const LIBC_UNSUPPORTED: usize = 6;
}

/// Frida loader IPC 消息类型
#[allow(dead_code)]
pub(crate) mod message_type {
    pub const HELLO: u8 = 0;
    pub const READY: u8 = 1;
    pub const ACK: u8 = 2;
    pub const BYE: u8 = 3;
    pub const ERROR_DLOPEN: u8 = 4;
    pub const ERROR_DLSYM: u8 = 5;
}

/// FridaBootstrapContext — bootstrapper 的输入/输出参数
/// 对应 inject-context.h 中的 struct _FridaBootstrapContext
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct FridaBootstrapContext {
    pub(crate) allocation_base: u64, // void *
    pub(crate) allocation_size: u64, // size_t
    pub(crate) page_size: u64,       // size_t
    pub(crate) fallback_ld: u64,     // const char * (unused on Android)
    pub(crate) fallback_libc: u64,   // const char * (unused on Android)
    pub(crate) rtld_flavor: i32,     // FridaRtldFlavor (int)
    _pad0: i32,                      // 对齐 padding
    pub(crate) rtld_base: u64,       // void *
    pub(crate) r_brk: u64,           // void *
    pub(crate) enable_ctrlfds: i32,
    pub(crate) ctrlfds: [i32; 2],
    _pad1: i32,           // 对齐 padding（ctrlfds 后 12 字节到下一个 8 字节边界）
    pub(crate) libc: u64, // FridaLibcApi *
}

impl Default for FridaBootstrapContext {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// FridaLibcApi — bootstrapper 解析出的 18 个 libc/linker 函数指针
/// 对应 inject-context.h 中的 struct _FridaLibcApi
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct FridaLibcApi {
    pub(crate) printf: u64,
    pub(crate) sprintf: u64,
    pub(crate) mmap_fn: u64, // 避免与 libc::mmap 冲突
    pub(crate) munmap_fn: u64,
    pub(crate) socket: u64,
    pub(crate) socketpair: u64,
    pub(crate) connect: u64,
    pub(crate) recvmsg: u64,
    pub(crate) send: u64,
    pub(crate) fcntl: u64,
    pub(crate) close: u64,
    pub(crate) pthread_create: u64,
    pub(crate) pthread_detach: u64,
    pub(crate) dlopen: u64,
    pub(crate) dlopen_flags: i32,
    _pad: i32,
    pub(crate) dlclose: u64,
    pub(crate) dlsym: u64,
    pub(crate) dlerror: u64,
}

impl Default for FridaLibcApi {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// RustFridaLoaderContext — loader 的输入参数
/// 对应 rustfrida-loader.c 中的 RustFridaLoaderContext
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct RustFridaLoaderContext {
    pub(crate) ctrlfds: [i32; 2],
    pub(crate) agent_entrypoint: u64, // const char *
    pub(crate) agent_data: u64,       // const char *
    pub(crate) fallback_address: u64, // const char *
    pub(crate) libc: u64,             // FridaLibcApi *
    pub(crate) string_table_addr: u64,
    pub(crate) worker: u64,                // pthread_t (runtime, zeroed)
    pub(crate) agent_handle: u64,          // void * (runtime, zeroed)
    pub(crate) agent_entrypoint_impl: u64, // fn ptr (runtime, zeroed)
}

impl Default for RustFridaLoaderContext {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
