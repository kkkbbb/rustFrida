use super::arm64_analysis::{is_arm64_branch, is_arm64_call, resolve_next_addr};
use super::arm64_codegen::{gen_jump_to_transformer, gen_mov_reg_addr};
use super::ptrace_ops::{attach_to_thread, get_registers, set_reg};
use super::UserRegs;
use crate::arm64_relocator;
use crate::communication::write_stream;
use crate::exec_mem::ExecMem;
use crate::gumlibc::gum_libc_ptrace;
use libc::{
    c_int, mmap, pid_t, CLONE_SETTLS, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, PR_SET_NAME,
    PTRACE_DETACH,
};
use once_cell::sync::Lazy;
use std::ptr::{addr_of_mut, null_mut};
use std::sync::Mutex;

type Result<T> = std::result::Result<T, String>;

// ============== 静态变量 ==============

static mut INSTRUCT_PTR: *const u32 = null_mut();
static EXE_MEM: Lazy<Mutex<ExecMem>> = Lazy::new(|| Mutex::new(ExecMem::new().unwrap()));

// ============== 转换器 ==============

extern "C" {
    pub fn mtransform();
}

/// 返回 mtransform 函数地址，供 arm64_codegen 使用
pub fn mtransform_addr() -> usize {
    mtransform as *const () as usize
}

#[no_mangle]
pub extern "C" fn transformer_wrapper_full(ctx: *const usize) -> usize {
    unsafe {
        let mut vall = UserRegs::default();
        let mut log = String::from("context: \n");
        for i in 0..31 {
            vall.regs[i] = *ctx.add(31 - i);
            log.push_str(&format!("regs[{}] = {:x}\n", i, *ctx.add(31 - i)));
        }
        vall.pstate = *ctx;
        let instruct_ptr = *addr_of_mut!(INSTRUCT_PTR);
        let addr = resolve_next_addr(instruct_ptr, vall).unwrap();

        match transformer_global(addr) {
            Ok(addr) => addr,
            _ => {
                panic!("transformer failed!! please file a issue")
            }
        }
    }
}

pub fn transformer_global(addr: usize) -> Result<usize> {
    unsafe {
        let ip = addr_of_mut!(INSTRUCT_PTR);
        let mut exe_mem = EXE_MEM.lock().unwrap();
        let ret_addr = exe_mem.current_addr();

        if is_arm64_call(**ip) {
            for instr in gen_mov_reg_addr(30, (*ip).add(1) as usize) {
                exe_mem.write_u32(instr)?;
            }
        }

        *ip = addr as *const u32;
        let closure_result = {
            while !is_arm64_branch(**ip) {
                arm64_relocator::relocate_one_a64(**ip as usize, exe_mem.external_write_instruct());
                *ip = (*ip).add(1);
            }
            Ok(())
        };
        match closure_result {
            Ok(_) => {}
            Err(e) => {
                write_stream(e);
                exe_mem.reset();
                let _ = transformer_global(addr);
            }
        }

        for instruct in gen_jump_to_transformer() {
            exe_mem.write_u32(instruct).unwrap();
        }
        Ok(ret_addr)
    }
}

// ============== Trace 入口 ==============

pub fn gum_modify_thread(thread_id: usize) -> Result<pid_t> {
    let stack_base = unsafe {
        mmap(
            null_mut(),
            0x1100000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let _ = crate::vma_name::set_anon_vma_name_raw(stack_base as *mut u8, 0x1100000, b"wwb_trace_stack\0");
    let stack = unsafe { stack_base.add(0x1100000) };
    let tls = unsafe {
        mmap(
            null_mut(),
            0x1000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let _ = crate::vma_name::set_anon_vma_name_raw(tls as *mut u8, 0x1000, b"wwb_trace_tls\0");
    crate::gumlibc::gum_libc_clone(
        tracer as *mut usize,
        thread_id,
        (CLONE_VM | CLONE_SETTLS) as u64,
        stack as *mut usize,
        null_mut(),
        null_mut(),
        tls,
    )
}

extern "C" fn tracer(thread_id: i32) -> c_int {
    unsafe {
        let _ = libc::prctl(PR_SET_NAME, b"wwb-tracer\0".as_ptr(), 0, 0, 0);
        match attach_to_thread(thread_id) {
            Ok(_) => {
                write_stream(b"attach success!! ");
            }
            Err(e) => {
                write_stream(("tracer exit: ".to_string() + &e).as_bytes());
                return -1;
            }
        }
        let ip = addr_of_mut!(INSTRUCT_PTR);
        let mut exe_mem = EXE_MEM.lock().unwrap();

        let mut regs = get_registers(thread_id).unwrap();
        *ip = regs.pc as *const u32;
        write_stream(("\nget pc: ".to_string() + &(*ip as usize).to_string()).as_bytes());

        while !is_arm64_branch(**ip) {
            arm64_relocator::relocate_one_a64(**ip as usize, exe_mem.external_write_instruct());
            *ip = (*ip).add(1);
        }

        for instruct in gen_jump_to_transformer() {
            exe_mem.write_u32(instruct).unwrap();
        }
        write_stream(("\ntrace compile finished :".to_string() + &(regs.pc as u64).to_string()).as_bytes());
        regs.pc = exe_mem.ptr as usize;
        set_reg(thread_id, &mut regs).unwrap();

        gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
        write_stream(b"\ndone! detached!");
        1
    }
}
