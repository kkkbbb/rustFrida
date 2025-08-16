#![cfg(all(target_os = "android", target_arch = "aarch64"))]
mod jhook;
mod gumlibc;
mod writer;

use crate::gumlibc::{gum_libc_ptrace, gum_libc_waitpid};
use crate::jhook::jhook;
use libc::{c_char, c_int, close, iovec, kill, mmap, munmap, pid_t, sockaddr, sockaddr_un, sysconf, AF_UNIX, CLONE_SETTLS, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, PTRACE_DETACH, SIGSTOP, _SC_PAGESIZE,SIGCONT};
use libc::{PTRACE_ATTACH, PTRACE_GETREGSET, PTRACE_CONT};
use nix::errno::Errno;
use once_cell::unsync::Lazy;
use std::ffi::c_void;
use std::io::Write;
use std::io::{Error, Read};
use std::mem::{size_of, zeroed};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::ptr;
use std::ptr::null_mut;
use std::sync::{ Mutex, OnceLock};
use clear_cache::clear_cache;

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UserRegs {
    regs: [usize; 31],      // X0-X30 寄存器
    sp: usize,             // SP 栈指针
    pc: usize,             // PC 程序计数器
    pstate: usize,         // 处理器状态
}

pub struct ExecMem {
    ptr: *mut u8,
    size: usize,
    used: usize,
    page_size: usize,
}

impl ExecMem {
    /// 新建一块可读写可执行内存（自动按页分配）
    pub fn new() -> Result<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(Error::last_os_error().to_string());
            }
            Ok(ExecMem { ptr: ptr as *mut u8, size: page_size, used: 0, page_size })
        }
    }

    /// 写入数据，自动扩容（每次扩容一页）
    pub fn write(&mut self, data: &[u8]) -> Result<*mut u8> {
        if self.used + data.len() > self.size {
            // self.grow()?;
            return Err(String::from("剩余exe_mem耗尽"))
        }
        unsafe {
            let dest = self.ptr.add(self.used);
            ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
            // let old_used = self.used;
            self.used += data.len();
            Ok(self.ptr.add(self.used))
        }
    }

    pub fn reset(&mut self) {
        self.used = 0;
    }

    pub fn write_u32(&mut self, value: u32) -> Result<*mut u8> {
        let bytes = value.to_le_bytes(); // ARM64 小端
        self.write(&bytes)
    }

    /// 扩容（每次扩容一页）
    fn grow(&mut self) -> Result<()> {
        let new_size = self.size + self.page_size;
        unsafe {
            // 申请新内存
            let new_ptr = mmap(
                null_mut(),
                new_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if new_ptr == libc::MAP_FAILED {
                return Err(format!("无法扩展内存 ({}->{}): {}", 
                    self.size, new_size, Error::last_os_error()));
            }
            // 拷贝旧数据
            ptr::copy_nonoverlapping(self.ptr, new_ptr as *mut u8, self.used);
            // 释放旧内存
            munmap(self.ptr as *mut _, self.size);
            self.ptr = new_ptr as *mut u8;
            self.size = new_size;
        }
        Ok(())
    }

    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
    pub fn current_addr(&self) -> usize { unsafe { self.ptr.add(self.used) as usize } }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn capacity(&self) -> usize {
        self.size
    }
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

fn get_registers(pid: i32) -> Result<UserRegs> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        gum_libc_ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as usize,
        )
    };

    if result < 0 {
        return Err("获取线程 寄存器失败，错误码: ".to_string() + &*(-result).to_string());
    }
    Ok(regs)
}

fn connect_socket() -> Result<UnixStream> {
    let name = b"rust_frida_socket";
    let fd = unsafe { libc::socket(AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("创建 socket 失败: {}", Error::last_os_error()));
    }

    // 构造 abstract sockaddr_un
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    addr.sun_path[0] = 0; // abstract namespace
    for (i, &b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = b as c_char;
    }

    // 计算 sockaddr_un 长度
    let addr_len = (size_of::<libc::sa_family_t>() + 1 + name.len()) as u32;

    // 连接
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const sockaddr,
            addr_len,
        )
    };
    if ret != 0 {
        let err = Error::last_os_error();
        unsafe { close(fd) };
        return Err(format!("连接到套接字失败: {}", err));
    }

    // 用 Rust 的 UnixStream 包装 fd，方便写数据
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(stream)
}

fn attach_to_thread(thread_id: i32) -> Result<()> {

    // 尝试附加到目标进程
    match gum_libc_ptrace(PTRACE_ATTACH, thread_id, 0, 0) {
        res if res >= 0 => {
            let mut status:usize = 0;
            let wait_result = gum_libc_waitpid(thread_id, &mut status as *mut _ as usize, 0x40000000);
            if wait_result < 0 {
                return Err("waitpid failed!!!!".to_string() + &*(-wait_result).to_string())
            }
            if !(status & 0xff) == 0x7f {
                return Err("attach failed to stop !!!".to_string())
            }
            
            Ok(())
        },
        res => {
            let err_msg = match Errno::from_i32(-res) {
                Errno::EPERM => "权限不足，请使用root权限运行 ".to_string(),
                Errno::ESRCH => "目标线程不存在".to_string(),
                _ => "附加到线程失败: ".to_string() + &*res.to_string(),
            };
            Err(err_msg)
        }
    }
}

pub fn is_arm64_branch(code: u32) -> bool {
    let op6 = code >> 26;
    if op6 == 0b000101 || op6 == 0b100101 {
        // B, BL
        return true;
    }
    let op8 = code >> 24;
    if op8 == 0b01010100 {
        // B.cond
        return true;
    }
    let op10 = code >> 21;
    if op10 == 0b1101011000 {
        // BR, BLR, RET
        return true;
    }
    // CBZ/CBNZ
    if (code & 0x7F000000) == 0x34000000 || (code & 0x7F000000) == 0x35000000 {
        return true;
    }
    // TBZ/TBNZ
    if ((code & 0xFF000000) == 0x36000000 || (code & 0xFF000000) == 0x37000000) {
        return true;
    }
    false
}

pub fn is_arm64_call(instr: u32) -> bool {
    // BL: 高6位 0b100101
    if (instr >> 26) == 0b100101 {
        return true;
    }
    // BLR: 高10位 0b11010110001
    if (instr >> 21) == 0b11010110001 {
        return true;
    }
    false
}

/// 返回即将执行的下一条指令地址（已判断条件）
fn resolve_next_addr(
    instr_ptr: *const u32,
    regs: UserRegs,
) -> Option<usize> {
    unsafe {
        let instr = *instr_ptr;
        let instr_addr = instr_ptr;
        let pstate = regs.pstate;

        // 1. 无条件跳转 (B, BL)
        let op6 = instr >> 26;
        if op6 == 0b000101 || op6 == 0b100101 {
            let offset = ((instr & 0x03FFFFFF) << 2) as i32;
            let offset = if (offset & 0x02000000) != 0 {
                (offset as u32 | 0xFC000000u32) as isize
            } else {
                offset as isize
            };
            return Some(instr_addr.offset(offset) as usize);
        }

        // 2. 条件跳转 (B.cond)
        if (instr >> 24) == 0b01010100 {
            let cond = (instr & 0xF) as u8;
            let offset = (((instr >> 5) & 0x7FFFF) << 2) as isize;
            let offset = if (offset & 0x00100000) != 0 {
                (offset as u32 | 0xFFE00000u32) as isize
            } else {
                offset
            };
            let branch_addr = instr_addr.offset(offset);
            let next_addr = instr_addr.offset(4);
            if arm64_cond_pass(cond, pstate) {
                return Some(branch_addr as usize);
            } else {
                return Some(next_addr as usize);
            }
        }

        // 3. CBZ/CBNZ
        if ((instr >> 25) & 0x3F) == 0b011010 || ((instr >> 25) & 0x3F) == 0b011011 {
            let is_cbz = ((instr >> 24) & 1) == 0;
            let reg = ((instr >> 0) & 0x1F) as usize;
            let offset = (((instr >> 5) & 0x7FFFF) << 2) as i32;
            let offset = if (offset & 0x00100000) != 0 {
                (offset as u32 | 0xFFE00000u32) as isize
            } else {
                offset as isize
            };
            let branch_addr = instr_addr.offset(offset);
            let next_addr = instr_addr.offset(4);
            let reg_val = regs.regs[reg];
            let is_zero = reg_val == 0;
            if (is_cbz && is_zero) || (!is_cbz && !is_zero) {
                return Some(branch_addr as usize);
            } else {
                return Some(next_addr as usize);
            }
        }

        // 4. TBZ/TBNZ
        if ((instr >> 25) & 0x3E) == 0b011110 {
            let is_tbz = ((instr >> 24) & 1) == 0;
            let reg = ((instr >> 0) & 0x1F) as usize;
            let bit = ((instr >> 19) & 0x1F) as u8 | (((instr >> 31) & 1) << 5) as u8;
            let offset = (((instr >> 5) & 0x3FFF) << 2) as i32;
            let offset = if (offset & 0x00008000) != 0 {
                (offset as u32 | 0xFFFF0000u32) as isize
            } else {
                offset as isize
            };
            let branch_addr = instr_addr.offset(offset);
            let next_addr = instr_addr.offset(4);
            let reg_val = regs.regs[reg];
            let bit_set = ((reg_val >> bit) & 1) != 0;
            if (is_tbz && !bit_set) || (!is_tbz && bit_set) {
                return Some(branch_addr as usize);
            } else {
                return Some(next_addr as usize);
            }
        }

        // 5. 间接跳转 (BR/BLR/RET)
        let op10 = instr >> 21;
        // BR: 1101011000
        if op10 == 0b1101011000 {
            let reg_num = ((instr >> 5) & 0x1F) as usize;
            return Some(if reg_num < 31 { regs.regs[reg_num] } else { regs.sp });
        }
        // BLR: 1101011001
        if op10 == 0b1101011001 {
            let reg_num = ((instr >> 5) & 0x1F) as usize;
            return Some(if reg_num < 31 { regs.regs[reg_num] } else { regs.sp });
        }
        // RET: 1101011010
        if op10 == 0b1101011010 {
            // let reg_num = ((instr >> 5) & 0x1F) as usize;
            return Some( regs.regs[30] );
        }

        // 不是跳转指令
        None
    }
}

/// 判断 ARM64 条件码是否成立
fn arm64_cond_pass(cond: u8, pstate: usize) -> bool {
    let n = (pstate >> 31) & 1;
    let z = (pstate >> 30) & 1;
    let c = (pstate >> 29) & 1;
    let v = (pstate >> 28) & 1;
    match cond {
        0x0 => z == 1,                    // EQ
        0x1 => z == 0,                    // NE
        0x2 => c == 1,                    // CS/HS
        0x3 => c == 0,                    // CC/LO
        0x4 => n == 1,                    // MI
        0x5 => n == 0,                    // PL
        0x6 => v == 1,                    // VS
        0x7 => v == 0,                    // VC
        0x8 => c == 1 && z == 0,          // HI
        0x9 => c == 0 || z == 1,          // LS
        0xA => n == v,                    // GE
        0xB => n != v,                    // LT
        0xC => z == 0 && (n == v),        // GT
        0xD => z == 1 || (n != v),        // LE
        0xE => true,                      // AL
        0xF => false,                     // NV (保留)
        _ => false,
    }
}

static GLOBAL_STREAM: OnceLock<UnixStream> = OnceLock::new();
#[no_mangle]
pub extern "C" fn hello_entry(){
    unsafe {
        let name = std::ffi::CString::new("wwb").unwrap();
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    // GLOBAL_STREAM.lock().unwrap().set(connect_socket().unwrap()).unwrap();
    GLOBAL_STREAM.set(connect_socket().expect("wwb connect socket failed!!!")).unwrap();
    let mut stream = GLOBAL_STREAM.get().unwrap();
    
    let _ = stream.write("HELLO_AGENT".as_bytes()).unwrap();
    
    // 循环等待stream发送命令
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(size) if size > 0 => {
                // 处理接收到的命令
                let command = std::str::from_utf8(&buffer[0..size]).unwrap_or("无效命令");
                // 可以在这里添加命令处理逻辑
                let _ = stream.write(format!("收到命令: {}", command).as_bytes()).unwrap();
                match command.split_whitespace().next() {
                    Some("trace") => {
                        let tid = command.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                        std::thread::spawn(move || {
                            match gum_modify_thread(tid) {
                                Ok(pid) => {
                                    GLOBAL_STREAM.get().unwrap().write_all(format!("clone success {}",pid).as_bytes()).unwrap();
                                }
                                Err(e) => {
                                    GLOBAL_STREAM.get().unwrap().write_all(format!("error: {}", e).as_bytes()).unwrap();
                                }
                            }
                            unsafe { kill(process::id() as pid_t, SIGSTOP ) }
                        });
                    },
                    Some("jhook") => {
                        std::thread::spawn(|| {
                            match jhook() {
                                Ok(_) => {},
                                Err(e) => {
                                    GLOBAL_STREAM.get().unwrap().write_all(format!("{}", e).as_bytes()).unwrap();
                                }
                            }
                        });
                    },
                    _ => {
                        stream.write_all(format!("无效命令: {}", command).as_bytes()).unwrap();
                    }
                }
            },
            Ok(_) => {
                // 连接关闭
                break;
            },
            Err(e) => {
                // 读取错误
                stream.write_all(format!("读取命令错误: {}", e).as_bytes()).unwrap();
                break;
            }
        }
    }
}

pub fn gen_mov_reg_addr(reg: u8, imm: usize) -> Vec<u32> {
    let mut code = Vec::new();
    // 4个16位段
    for i in 0..4 {
        let imm16 = ((imm >> (i * 16)) & 0xFFFF) as u16;
        if i == 0 {
            // MOVZ
            if imm16 != 0 {
                let instr = 0xD2800000 // MOVZ
                    | ((imm16 as u32) << 5)
                    | ((reg as u32) & 0x1F)
                    | ((i as u32) << 21);
                code.push(instr);
            }
        } else {
            // MOVK
            if imm16 != 0 {
                let instr = 0xF2800000 // MOVK
                    | ((imm16 as u32) << 5)
                    | ((reg as u32) & 0x1F)
                    | ((i as u32) << 21);
                code.push(instr);
            }
        }
    }
    code
}

pub fn gen_jump_to_transformer() -> Vec<u32> {
    
    // 1. 加载地址到 X30
    let mut instruct = gen_mov_reg_addr(30,mtransform as usize);
    
    // 2. BR X30
    instruct.push(0xD61F03C0);
    instruct
}

#[derive(Debug, Default)]
pub struct BranchRegUsage {
    /// 读取的寄存器
    pub read_regs: u8,
    // /// 写入的寄存器
    // pub write_regs: Vec<u8>,
    /// 是否读取NZCV标志
    pub read_flags: bool, 
}

/// 分析一条跳转指令涉及的寄存器
pub fn analyze_branch_regs(instr: u32) -> BranchRegUsage {
    let mut usage = BranchRegUsage::default();

    let op6 = instr >> 26;
    let op8 = instr >> 24;
    let op10 = instr >> 21;

    // 1. B, BL（无条件跳转/带链接）
    if op6 == 0b000101 {
        // B: 无寄存器涉及
    } else if op6 == 0b100101 {
        // BL: 写入X30（LR）
        // usage.write_regs.push(30);
    }
    // 2. B.cond（条件跳转，读取NZCV）
    else if op8 == 0b01010100 {
        usage.read_flags = true;
    }
    // 3. CBZ/CBNZ（比较寄存器是否为0）
    else if ((instr >> 25) & 0x3F) == 0b011010 || ((instr >> 25) & 0x3F) == 0b011011 {
        let reg = (instr & 0x1F) as u8;
        usage.read_regs = reg;
    }
    // 4. TBZ/TBNZ（测试寄存器某一位）
    else if ((instr >> 25) & 0x3E) == 0b011110 {
        let reg = (instr & 0x1F) as u8;
        usage.read_regs = reg;
    }
    // 5. BR/BLR/RET（间接跳转）
    else if op10 == 0b1101011000 {
        // BR
        let reg = ((instr >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
    } else if op10 == 0b1101011001 {
        // BLR
        let reg = ((instr >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
        // usage.write_regs.push(30); // X30 (LR)
    } else if op10 == 0b1101011010 {
        // RET
        let reg = ((instr >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
    }

    usage
}

/// 生成 mov x0, xN 的机器码
fn gen_mov_x0_xn(reg_num: u8) -> u32 {
    0xAA000000 | ((reg_num as u32) << 16)
}

/// 生成 mov x1, #imm 的机器码
fn gen_mov_x1_imm(reg_num: u8) -> u32 {
    0xD2800000 | (1 << 5) | (reg_num as u32)
}

fn gen_mov_x1_xzr() -> u32 {
    0xAA1F03E1
}

/// 综合生成
fn gen_bridge_movs(reg_num: u8) -> [u32; 3] {
    [
        gen_mov_x0_xn(reg_num),   // mov x0, xN
        gen_mov_x1_xzr(),
        gen_mov_x1_imm(reg_num),  // mov x1, #reg_num
    ]
}

static mut INSTRUCT_PTR: *const u32 = null_mut();
static mut EXE_MEM: Lazy<Mutex<ExecMem>> = Lazy::new(|| {Mutex::new(ExecMem::new().unwrap())});

#[no_mangle]
pub extern "C" fn transformer_wrapper_full(ctx:[usize;31],lr:usize) -> usize {
    unsafe {
        let mut vall = UserRegs::default();
        vall.regs[..29].copy_from_slice(&ctx[..29]);
        vall.regs[30] = lr;
        vall.pstate = ctx[30];
        // if xn == 31 {
        //     vall.pstate = val;
        // }else {
        //     vall.regs[xn] = val;
        // }
        let addr = resolve_next_addr(INSTRUCT_PTR, vall).unwrap();
        
        // let exe_mem = EXE_MEM.lock().unwrap();

        // let old_mem_used = exe_mem.used;
        match transformer_global(addr) {
            Ok(addr) => {
                addr
            },
            _ => {
                panic!("transformer failed!! please file a issue")
            }
        }
    }
}

pub fn transformer_global(addr: usize) -> Result<usize>{
    unsafe {
        let mut exe_mem = EXE_MEM.lock().unwrap();
        let ret_addr = exe_mem.current_addr();

        if is_arm64_call(*INSTRUCT_PTR) {
            for instr in gen_mov_reg_addr(30,INSTRUCT_PTR.add(1) as usize) {
                exe_mem.write_u32(instr)?;
            }
        }

        INSTRUCT_PTR = addr as *const u32;
        let closure_result = {
            while !is_arm64_branch(*INSTRUCT_PTR) {
                exe_mem.write_u32(*INSTRUCT_PTR).unwrap();
                INSTRUCT_PTR = INSTRUCT_PTR.add(1);
            }
            Ok(())
        };
        match closure_result{
            Ok(_)=>{},
            Err(e)=>{
                GLOBAL_STREAM.get().unwrap().write_all(e).unwrap();
                exe_mem.reset();
                transformer_global(addr);
            }
        }
        
        // let reg_used = analyze_branch_regs(*INSTRUCT_PTR);
        // if !reg_used.read_flags {
        //     for instruct in gen_bridge_movs(reg_used.read_regs){
        //         exe_mem.write_u32(instruct).unwrap();
        //     }
        // }else {
        //     exe_mem.write_u32(0xD53B4200).unwrap();
        //     exe_mem.write_u32(gen_mov_x1_imm(31)).unwrap();
        // }
        for instruct in gen_jump_to_transformer(){
            exe_mem.write_u32(instruct).unwrap();
        }
        clear_cache(exe_mem.ptr,exe_mem.ptr.add(exe_mem.size));
        Ok(ret_addr)
    }
}

fn set_reg(pid: i32, mut regs: &mut UserRegs) -> Result<()> {
    // 2. 修改PC
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    
    let ret =
        gum_libc_ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            1,
            &mut iov as *const _ as usize,
        );
    if ret == -1 {
        return Err(format!("设置寄存器失败: {}", Error::last_os_error()));
    }
    Ok(())
}



fn gum_modify_thread(thread_id:usize) -> Result<pid_t> {
    let stack = unsafe { mmap(null_mut(),0x1100000,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0).add(0x1100000) };
    let tls = unsafe { mmap(null_mut(),0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)};
    gumlibc::gum_libc_clone(tracer as *mut usize,thread_id,(CLONE_VM | CLONE_SETTLS) as u64, stack as *mut usize,null_mut(),null_mut(),tls)
    // unsafe {
    //     let pid = libc::clone(tracer,stack,CLONE_VM,thread_id as *mut c_void);
    //     if pid == -1 {
    //         Err(format!("clone<UNK>: {}", Error::last_os_error()))
    //     }else {
    //         Ok(pid)
    //     }
    // }
}

extern "C" {
    pub fn mtransform();
    // pub fn clearCache(begin:*mut u8,end:*mut u8);
    
}

extern "C" fn tracer(thread_id:i32) -> c_int {
    let mut stream = GLOBAL_STREAM.get().unwrap();
    
    unsafe {
         match attach_to_thread(thread_id){
            Ok(_) => {
                stream.write_all(("attach success!! ").as_bytes()).expect("stream write error");
            },
            Err(e) => {
                stream.write_all(("tracer exit: ".to_string() + &*e).as_bytes()).expect("stream write error");
                return -1
            }
        }
        let mut exe_mem = EXE_MEM.lock().unwrap();
        
        let mut regs = get_registers(thread_id).unwrap();
        INSTRUCT_PTR = regs.pc as *const u32;
        stream.write_all(("\nget pc: ".to_string() + &*(INSTRUCT_PTR as usize).to_string()).as_bytes());
        
        while !is_arm64_branch(*INSTRUCT_PTR) {
            exe_mem.write_u32(*INSTRUCT_PTR).unwrap();
            INSTRUCT_PTR = INSTRUCT_PTR.add(1);
        }
        
        // let reg_used = analyze_branch_regs(*INSTRUCT_PTR);
        // if !reg_used.read_flags {
        //     for instruct in gen_bridge_movs(reg_used.read_regs){
        //         exe_mem.write_u32(instruct).unwrap();
        //     }
        // }else {
        //     exe_mem.write_u32(0xD53B4200).unwrap();
        //     exe_mem.write_u32(gen_mov_x1_imm(31)).unwrap();
        // }
        
        for instruct in gen_jump_to_transformer(){
            exe_mem.write_u32(instruct).unwrap();
        }
        stream.write_all(("\ntrace compile finished :".to_string()+&*(regs.pc as u64).to_string()).as_bytes());
        regs.pc = exe_mem.ptr as usize;
        set_reg(thread_id, &mut regs).unwrap();
        // gum_libc_ptrace(PTRACE_CONT,thread_id,0,0);
        
        // gum_libc_ptrace(PTRACE_DETACH,thread_id,0,SIGSTOP as usize);
        gum_libc_ptrace(PTRACE_DETACH,thread_id,0,0);
        stream.write_all("\ndone! detached!".as_bytes()).expect("stream write error");
        return 1;
        // let ret =  libc::ptrace(libc::PTRACE_CONT, thread_id, 0, 0);
        // if ret == -1 {
        //     panic!("ptrace_cont: {}", Error::last_os_error())
        // }
        
    }
    1
    
}