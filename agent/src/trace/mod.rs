//! Trace 命令相关功能 - ptrace 跟踪和代码转换

mod arm64_analysis;
mod arm64_codegen;
mod ptrace_ops;
mod transformer;

pub use transformer::gum_modify_thread;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegs {
    pub regs: [usize; 31], // X0-X30 寄存器
    pub sp: usize,         // SP 栈指针
    pub pc: usize,         // PC 程序计数器
    pub pstate: usize,     // 处理器状态
}
