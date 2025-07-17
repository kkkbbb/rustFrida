#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use clap::Parser;
use libc::{bind, listen, sleep, sockaddr_un, AF_UNIX, SOCK_STREAM};
use libc::{c_int, c_void, close, connect, dlopen, free, iovec, malloc, mmap, mprotect, munmap, pid_t, pthread_create, pthread_detach, recvmsg, socket, write, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use libc::{dlsym, memcpy, memfd_create, snprintf, write as libc_write, MFD_CLOEXEC};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use once_cell::unsync::Lazy;
use paste::paste;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, IoSlice, Write};
use std::io::Read;
use std::mem::{size_of_val, zeroed};
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{OnceLock, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::{io, process};

static AGENT_MEMFD: AtomicI32 = AtomicI32::new(-1);

/// 定义需要获取偏移的函数列表
macro_rules! define_libc_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default)]
        struct LibcOffsets {
            $($name: usize),*
        }

        impl LibcOffsets {
            fn calculate(self_base: usize, target_base: usize) -> Self {
                Self {
                    $(
                        $name: {
                            let sym_addr = $name as *const () as usize;
                            if sym_addr < self_base {
                                panic!(
                                    "符号 {} 地址(0x{:x}) 小于libc基址(0x{:x})",
                                    stringify!($name), sym_addr, self_base
                                );
                            }
                            let offset = sym_addr - self_base;
                            target_base + offset
                        }
                    ),*
                }
            }

            fn print_offsets(&self) {
                println!("目标进程函数地址列表:");
                $(println!("  {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

macro_rules! define_dl_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default)]
        struct DlOffsets {
            $($name: usize),*
        }

        impl DlOffsets {
            fn calculate(self_base: usize, target_base: usize) -> Self {
                Self {
                    $(
                        $name: {
                            let sym_addr = $name as *const () as usize;
                            if sym_addr < self_base {
                                panic!(
                                    "符号 {} 地址(0x{:x}) 小于dl基址(0x{:x})",
                                    stringify!($name), sym_addr, self_base
                                );
                            }
                            let offset = sym_addr - self_base;
                            target_base + offset
                        }
                    ),*
                }
            }

            fn print_offsets(&self) {
                println!("libdl.so 函数地址列表:");
                $(println!("  {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

// 定义字符串表宏
macro_rules! define_string_table {
    ($(($name:ident, $value:expr)),* $(,)?) => {
        paste! {
            #[repr(C)]
            pub struct StringTable {
                $(
                    pub $name: u64,
                    pub [<$name _len>]: u32,
                )*
            }

            #[allow(unused_assignments)]
            fn write_string_table(pid: i32, malloc_addr: usize) -> Result<usize, String> {
                $(
                    // 添加 \0 结尾的字符串
                    let mut $name = $value.to_vec();
                    $name.push(0); // 添加 NULL 结尾
                )*

                let strings_len = 0 $(+ $name.len())*;
                let table_size = std::mem::size_of::<StringTable>();
                let total_size = table_size + strings_len;

                // 通过 call_target_function 用目标进程的 malloc 分配内存
                let table_addr = call_target_function(pid, malloc_addr, &[total_size],None)?;
                let mut string_addr = table_addr + table_size;

                let mut table = StringTable {
                    $(
                        $name: 0,
                        [<$name _len>] : 0,
                    )*
                };

                $(
                    table.$name = string_addr as u64;
                    // 长度包含最后的 NULL 结尾
                    table.[<$name _len>] = $name.len() as u32;
                    write_bytes(pid, string_addr, &$name)?;
                    string_addr += $name.len();
                )*

                write_memory(pid, table_addr, &table)?;
                Ok(table_addr)
            }
        }
    };
}

// 使用宏定义字符串表
define_string_table!(
    (socket_name, b"rust_frida_socket"),
    (hello_msg, b"HELLO_LOADER"),
    (sym_name, b"hello_entry"),
    (pthread_err, b"pthreadded"),
    (dlsym_err, b"dlsymFail"),
    (proc_path, b"/proc/self/fd/"),
    // 未来添加字符串只需在这里添加新行即可
);

// 使用宏定义函数列表
define_libc_functions!(
    malloc,    // 用于分配内存
    free,      // 用于释放内存
    socket,    // 用于创建套接字
    connect,   // 用于连接套接字
    write,     // 用于发送数据
    close,     // 用于关闭套接字
    mprotect,  // 用于设置内存保护
    mmap,      // 用于内存映射
    munmap,    // 用于释放内存映射
    recvmsg,    // 用于接收文件描述符
    pthread_create,
    pthread_detach,
    snprintf,    // 用于格式化字符串
    memcpy
);

define_dl_functions!(
    dlopen,    // 动态加载
    dlsym      // 动态符号查找
);

/// 用户空间寄存器结构体
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UserRegs {
    regs: [u64; 31],      // X0-X30 寄存器
    sp: u64,             // SP 栈指针
    pc: u64,             // PC 程序计数器
    pstate: u64,         // 处理器状态
}

/// 获取 libc 基址
/// 
/// # 参数
/// * `pid` - 进程ID，如果为 None 则获取当前进程的 libc 基址
fn get_libc_base(pid: Option<i32>) -> Result<usize, String> {
    // 构建 maps 文件路径
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    // 检查文件是否存在
    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取maps文件失败: {}", e))?;
        if line.contains("libc.so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16)
                        .map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的libc.so加载地址", pid.unwrap_or(-1)))
}

/// 获取 libdl.so 基址
/// 
/// # 参数
/// * `pid` - 进程ID，如果为 None 则获取当前进程的 libdl.so 基址
fn get_dl_base(pid: Option<i32>) -> Result<usize, String> {
    // 构建 maps 文件路径
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    // 检查文件是否存在
    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取maps文件失败: {}", e))?;
        if line.contains("libdl.so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16)
                        .map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的libdl.so加载地址", pid.unwrap_or(-1)))
}

fn attach_to_process(pid: i32) -> Result<(), String> {
    let target_pid = Pid::from_raw(pid);
    
    // 尝试附加到目标进程
    match ptrace::attach(target_pid) {
        Ok(_) => {
            println!("成功附加到进程 {}，等待 SIGSTOP...", pid);
            match waitpid(target_pid, None) {
                Ok(WaitStatus::Stopped(_, _)) => {
                    println!("进程已停止，可以操作寄存器");
                    Ok(())
                }
                other => Err(format!("waitpid 状态异常: {:?}", other)),
            }
        },
        Err(errno) => {
            let err_msg = match errno {
                Errno::EPERM => "权限不足，请使用root权限运行",
                Errno::ESRCH => "目标进程不存在",
                _ => "附加失败，未知错误",
            };
            Err(err_msg.to_string())
        }
    }
}

/// 获取进程寄存器
fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as *mut c_void,
        )
    };
    
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置进程寄存器
fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET,
            pid as pid_t,
            1,
            &mut iov as *mut _ as *mut c_void,
        )
    };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 调用目标进程的 libc 函数
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `func_addr` - 要调用的函数地址
/// * `args` - 函数参数列表
/// 
/// # 返回值
/// * `Ok(usize)` - 函数返回值
/// * `Err(String)` - 错误信息
fn call_target_function(pid: i32, func_addr: usize, args: &[usize], debug: Option<bool>) -> Result<usize, String> {
    // 获取当前寄存器状态
    let orig_regs = get_registers(pid)?;
    
    // 设置新的寄存器状态
    let mut new_regs = orig_regs;
    
    // 设置参数寄存器（ARM64 使用 X0-X7 寄存器传递参数）
    for (i, &arg) in args.iter().enumerate() {
        if i < 8 {
            new_regs.regs[i] = arg as u64;
        } else {
            break;
        }
    }
    
    // 设置返回地址为 0x340
    new_regs.regs[30] = 0x340;  // X30 是链接寄存器 (LR)
    
    // 设置 PC 指向函数地址
    new_regs.pc = func_addr as u64;
    
    // 写入新寄存器值
    set_registers(pid, &new_regs)?;
    
    // 继续执行
    if debug.unwrap_or(false) {
        let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
        process::exit(1);
    }
    let result = unsafe {
        libc::ptrace(
            PTRACE_CONT as c_int,
            pid as pid_t,
            0,
            0
        )
    };
    
    if result == -1 {
        return Err(format!("继续执行失败，错误码: {}", unsafe { *libc::__errno() }));
    }
    
    // 等待进程停止
    let target_pid = Pid::from_raw(pid);
    match waitpid(target_pid, None).map_err(|e| format!("等待进程失败: {}", e))? {
        WaitStatus::Stopped(_, Signal::SIGSEGV) => {
            // 获取寄存器，检查 PC 是否为预期值
            let regs = get_registers(pid)?;
            
            if regs.pc == 0x340 {
                // 函数执行完成，获取返回值（ARM64 使用 X0 寄存器返回值）
                let return_value = regs.regs[0] as usize;
                
                // 恢复原始寄存器状态
                set_registers(pid, &orig_regs)?;
                
                Ok(return_value)
            } else {
                Err(format!("函数执行异常，PC = 0x{:x}", regs.pc))
            }
        },
        status => Err(format!("进程异常停止: {:?}", status)),
    }
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 目标进程的PID
    #[arg(short, long)]
    pid: i32,
}

fn create_memfd_with_data(name: &str, data: &[u8]) -> Result<RawFd, String> {
    let cname = CString::new(name).unwrap();
    let fd = unsafe { memfd_create(cname.as_ptr(), MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create 失败: {}", std::io::Error::last_os_error()));
    }
    // 写入数据
    let mut written = 0;
    while written < data.len() {
        let ret = unsafe {
            libc_write(
                fd,
                data[written..].as_ptr() as *const c_void,
                data.len() - written,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!("memfd 写入失败: {}", std::io::Error::last_os_error()));
        }
        written += ret as usize;
    }
    Ok(fd)
}

fn send_fd_over_unix_socket(stream: &UnixStream, fd_to_send: RawFd) -> Result<(), String> {
    let data = b"AGENT_SO";
    let iov = [IoSlice::new(data)];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let sock_fd = stream.as_raw_fd();
    sendmsg(sock_fd, &iov, &cmsg, MsgFlags::empty(), None::<&()>)
        .map_err(|e| format!("发送文件描述符失败: {}", e))?;
    Ok(())
}

static GLOBAL_SENDER: OnceLock<Sender<String>> = OnceLock::new();
static mut AGENT_STAT: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));
fn handle_socket_connection(mut stream: UnixStream) {

    let mut buffer = [0; 1024];
    while let Ok(size) = stream.read(&mut buffer) {
        if size == 0 {
            break;
        }
        
        if let Ok(msg) = String::from_utf8(buffer[..size].to_vec()) {
            println!("收到消息: {}", msg);
            
            // 如果是 HELLO_LOADER，额外发送 memfd
            if msg.trim() == "HELLO_LOADER" {
                let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
                if memfd >= 0 {
                    if let Err(e) = send_fd_over_unix_socket(&stream, memfd) {
                        eprintln!("发送 memfd 失败: {}", e);
                    }
                } else {
                    eprintln!("memfd 无效，无法发送 agent.so");
                }
            }else if msg.trim() == "HELLO_AGENT" {
                let mut stream_clone = stream.try_clone().unwrap();
                thread::spawn(move || {
                    let (sd,rx) = channel();
                    GLOBAL_SENDER.set(sd).unwrap();
                    unsafe {*(AGENT_STAT.write().unwrap()) = true;}
                    while let Ok(msg) = rx.recv() {
                        match stream_clone.write_all(msg.as_bytes()){
                            Ok(_) => {},
                            Err(e) => {
                                eprintln!("<UNK> stream <UNK>: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
        }
    }
}

fn start_socket_listener(socket_path: &str) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    // 创建 socket
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 构造 sockaddr_un，抽象socket: sun_path[0]=0, 后面跟名字
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    let name_bytes = socket_path.as_bytes();
    let path_len = name_bytes.len().min(107); // sun_path最多108字节
    addr.sun_path[0] = 0; // 抽象socket
    addr.sun_path[1..=path_len].copy_from_slice(&name_bytes[..path_len]);
    let sockaddr_len = (size_of_val(&addr.sun_family) + 1 + path_len) as u32;

    // 绑定
    let ret = unsafe {
        bind(
            fd,
            &addr as *const _ as *const _,
            sockaddr_len,
        )
    };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 监听
    let ret = unsafe { listen(fd, 128) };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 转为 Rust 的 UnixListener
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        handle_socket_connection(stream);
                    });
                }
                Err(e) => eprintln!("接受连接失败: {}", e),
            }
        }
    });
    Ok(handle)
}

// 嵌入loader.bin
const SHELLCODE: &[u8] = include_bytes!("../loader/build/loader.bin");

const AGENT_SO: &[u8] = include_bytes!("../target/aarch64-linux-android/debug/libagent.so");

/// 向远程进程内存写入任意类型的数据
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据指针
/// * `size` - 数据大小（字节数）
fn write_remote_mem(pid: i32, addr: usize, data: *const u8, size: usize) -> Result<(), String> {
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let write_size = if remaining >= 8 { 8 } else { remaining };
        
        // 读取数据
        let mut word: u64 = 0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.add(offset),
                &mut word as *mut u64 as *mut u8,
                write_size
            );
        }
        
        // 写入目标进程
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };
        
        if result == -1 {
            return Err(format!("写入内存失败，错误码: {}", unsafe { *libc::__errno() }));
        }
        
        offset += write_size;
    }
    
    Ok(())
}

/// 向远程进程内存写入任意类型的数据的泛型包装
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据（任意类型）
fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    write_remote_mem(
        pid,
        addr,
        data as *const T as *const u8,
        size_of::<T>(),
    )
}

/// 向远程进程内存写入字节数组
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的字节数组
fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(
        pid,
        addr,
        data.as_ptr(),
        data.len(),
    )
}

fn main() {
    let args = Args::parse();
    
    if args.pid <= 0 {
        eprintln!("错误: PID必须是正整数");
        process::exit(1);
    }
    
    // 初始化 agent.so 的 memfd
    match create_memfd_with_data("wwb_so", AGENT_SO) {
        Ok(fd) => {
            AGENT_MEMFD.store(fd, Ordering::SeqCst);
            println!("已创建 agent.so memfd: {}", fd);
        }
        Err(e) => {
            eprintln!("创建 agent.so memfd 失败: {}", e);
            process::exit(1);
        }
    }
    
    println!("正在附加到进程 PID: {}", args.pid);
    
    // 启动抽象套接字监听
    let handle = start_socket_listener("rust_frida_socket");
    
    // 获取自身和目标进程的 libc 基址
    match (get_libc_base(None), get_libc_base(Some(args.pid)), get_dl_base(None), get_dl_base(Some(args.pid))) {
        (Ok(self_base), Ok(target_base), Ok(self_dl_base), Ok(target_dl_base)) => {
            println!("自身 libc.so 基址: 0x{:x}", self_base);
            println!("目标进程 libc.so 基址: 0x{:x}", target_base);
            println!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
            println!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);
            
            // 计算目标进程中的函数地址
            let offsets = LibcOffsets::calculate(self_base, target_base);
            let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base);
            
            // 打印所有函数地址
            offsets.print_offsets();
            dl_offsets.print_offsets();
            
            // 附加到目标进程
            match attach_to_process(args.pid) {
                Ok(_) => {
                    println!("附加成功，开始分配内存");
                    
                    // 分配内存用于shellcode
                    let page_size = 4096;
                    let shellcode_len = ((SHELLCODE.len() + page_size - 1) / page_size) * page_size;
                    let mmap_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
                    let mmap_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
                    let shellcode_addr = match call_target_function(
                        args.pid,
                        offsets.mmap,
                        &[
                            0, // addr = NULL，让内核分配
                            shellcode_len,
                            mmap_prot as usize,
                            mmap_flags as usize,
                            !0usize, // fd = -1
                            0,       // offset = 0
                        ], None
                    ) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("调用 mmap 失败: {}", e);
                            process::exit(1);
                        },
                    };
                    
                    println!("分配shellcode内存地址: 0x{:x}", shellcode_addr);
                    
                    // 写入shellcode
                    if let Err(e) = write_bytes(args.pid, shellcode_addr, SHELLCODE) {
                        eprintln!("写入shellcode失败: {}", e);
                        process::exit(1);
                    }
                    
                    println!("Shellcode写入成功，地址: 0x{:x}", shellcode_addr);
                    
                    // 分配内存用于LibcOffsets结构体
                    let offsets_size = size_of::<LibcOffsets>();
                    let offsets_addr = match call_target_function(args.pid, offsets.malloc, &[offsets_size],None) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("分配offsets内存失败: {}", e);
                            process::exit(1);
                        },
                    };
                    
                    println!("分配offsets内存地址: 0x{:x}", offsets_addr);
                    
                    // 写入LibcOffsets结构体
                    if let Err(e) = write_memory(args.pid, offsets_addr, &offsets) {
                        eprintln!("写入offsets失败: {}", e);
                        process::exit(1);
                    }
                    
                    println!("Offsets写入成功，地址: 0x{:x}", offsets_addr);

                    let dloffset_size = size_of::<DlOffsets>();
                    let dloffset_addr = match call_target_function(args.pid, offsets.malloc, &[dloffset_size],None) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("分配dloffsets内存失败: {}", e);
                            process::exit(1);
                        },
                    };

                    println!("分配dloffsets内存地址: 0x{:x}", dloffset_addr);

                    // 写入DlOffsets结构体
                    if let Err(e) = write_memory(args.pid, dloffset_addr, &dl_offsets) {
                        eprintln!("写入dloffsets失败: {}", e);
                        process::exit(1);
                    }

                    println!("DlOffsets写入成功，地址: 0x{:x}", dloffset_addr);

                    // 写入字符串表
                    let string_table_addr = match write_string_table(args.pid, offsets.malloc){
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("写入字符串表失败: {}", e);
                            process::exit(1);
                        }
                    };
                    
                    println!("字符串表写入成功，地址: 0x{:x}", string_table_addr);
                    
                    // 使用 call_target_function 调用 shellcode
                    match call_target_function(args.pid, shellcode_addr, &[offsets_addr, dloffset_addr, string_table_addr],None) {
                        Ok(return_value) => {
                            println!("Shellcode 执行完成，返回值: 0x{:x}", return_value);
                            
                            // 释放shellcode内存
                            println!("正在释放shellcode内存...");
                            match call_target_function(
                                args.pid,
                                offsets.munmap,
                                &[shellcode_addr, shellcode_len],
                                None
                            ) {
                                Ok(_) => println!("Shellcode内存释放成功"),
                                Err(e) => eprintln!("释放shellcode内存失败: {}", e),
                            }
                            
                            // detach 目标进程
                            if let Err(e) = ptrace::detach(Pid::from_raw(args.pid), None) {
                                eprintln!("分离目标进程失败: {}", e);
                            } else {
                                println!("已分离目标进程");
                            }
                        },
                        Err(e) => {
                            eprintln!("执行 shellcode 失败: {}", e);
                            println!("暂停目标进程，等待调试器附加...");
                            // 发送 SIGSTOP 让目标进程暂停
                            let _ = ptrace::cont(Pid::from_raw(args.pid), Some(Signal::SIGSTOP));
                            process::exit(1);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("错误: {}", e);
                    process::exit(1);
                }
            }
        },
        (Err(e), _, _, _) => eprintln!("获取自身libc基址失败: {}", e),
        (_, Err(e), _, _) => eprintln!("获取目标进程libc基址失败: {}", e),
        (_, _, Err(e), _) => eprintln!("获取自身libdl基址失败: {}", e),
        (_, _, _, Err(e)) => eprintln!("获取目标进程libdl基址失败: {}", e),
        
    }

    loop {
        unsafe {
            while *(AGENT_STAT.read().unwrap()) == false {
                eprintln!("等待Agent回连");
                sleep(1);
            }
        }
        let sender = GLOBAL_SENDER.get().unwrap();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .expect("读取失败");

        let line = line.trim().to_string();
        if line.is_empty() {
            break;
        }

        match sender.send(line) {
            Ok(_) => {},
            Err(e) => {
                eprintln!("<UNK>: {}", e);
                break;
            }
        }
    }
    // 等待监听线程退出
    handle.unwrap().join().unwrap();
    
    // 清理资源
    let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
    if memfd >= 0 {
        unsafe { close(memfd) };
        println!("已关闭 agent.so memfd");
    }
}