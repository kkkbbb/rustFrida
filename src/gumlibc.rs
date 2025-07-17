use std::arch::asm;
use std::ffi::c_void;
use libc::{c_int, c_long, pid_t, SYS_kill, SYS_wait4};
use libc::{SYS_ptrace,SYS_waitid,SYS_exit, SYS_clone};

pub fn gum_libc_syscall_4(n:c_long,a:usize,b:usize,c:usize,d:usize)-> usize{
    let result:usize;
    unsafe {
        asm!(
            "svc 0x0", 
            in("x8") n,
            inout("x0") a => result,
            in("x1") b,
            in("x2") c,
            in("x3") d,
        )
    }
    result
}

pub fn gum_libc_ptrace(request:i32, pid:i32,address:usize,data:usize) -> i32 {
    gum_libc_syscall_4 (SYS_ptrace, request as usize, pid as usize, address, data) as i32
}

pub fn gum_libc_waitpid(pid:i32,status:usize,options:usize)->i32{
    gum_libc_syscall_4 (SYS_wait4, pid as usize, status, options, 0) as i32
}

pub fn gum_libc_kill(pid:i32,sig:i32)->i32{
    gum_libc_syscall_4(SYS_kill,pid as usize,sig as usize,0,0) as i32
}

pub(crate) fn gum_libc_clone(
    child_func:*mut usize,
    threadid: usize,
    flags: u64,
    child_stack: *mut usize,
    parent_tidptr: *mut pid_t,
    child_tidptr: *mut pid_t,
    tls: *mut c_void,
) -> crate::Result<pid_t> {
    let mut result: i64 = 0;

    unsafe {
        *(child_stack.sub(1)) = child_func as usize;
        *(child_stack.sub(2)) = threadid;
        assert_eq!(*(child_stack.sub(2)), threadid);

        asm!(
            "svc 0x0",
            "cbnz x0, 1f",
    
            /* child: */
            "ldp x0, x1, [sp],#16",
            "blr x1\n\t",
            "mov x8, {exit_syscall}",
            "svc 0x0",
            "1:",
            in("x8") SYS_clone,
            inout("x0") flags => result,
            in("x1") child_stack.sub(2),
            in("x2") parent_tidptr,
            in("x3") tls,
            in("x4") child_tidptr,
            exit_syscall = const SYS_exit,
            options(nostack, preserves_flags),
            clobber_abi("C"),
        );
    }

    if result < 0 {
        Err(format!("clone系统调用失败，错误码: {}", -result))
    } else {
        Ok(result as pid_t)
    }
}