//! Trace 命令相关功能 - ptrace 跟踪和代码转换

mod arm64_analysis;
mod arm64_codegen;
mod ptrace_ops;
mod transformer;

pub use arm64_analysis::{analyze_branch_regs, is_arm64_branch, is_arm64_call, resolve_next_addr, BranchRegUsage};
pub use arm64_codegen::{gen_jump_to_transformer, gen_mov_reg_addr};
pub use ptrace_ops::get_registers;
pub use transformer::{gum_modify_thread, transformer_global, transformer_wrapper_full};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegs {
    pub regs: [usize; 31], // X0-X30 寄存器
    pub sp: usize,         // SP 栈指针
    pub pc: usize,         // PC 程序计数器
    pub pstate: usize,     // 处理器状态
}
