use super::UserRegs;
use crate::communication::write_stream;

/// ARM64 分支指令类型
#[derive(Debug, Clone, Copy)]
enum Arm64BranchType {
    UnconditionalBranch { target: usize },                // B, BL
    ConditionalBranch { taken: usize, not_taken: usize }, // B.cond
    CompareBranch { taken: usize, not_taken: usize },     // CBZ, CBNZ
    TestBitBranch { taken: usize, not_taken: usize },     // TBZ, TBNZ
    IndirectBranch { target: usize },                     // BR, BLR, RET
}

/// ARM64 指令 opcodes 常量
mod arm64_opcodes {
    // Unconditional branch
    pub const B_OPCODE: u32 = 0b000101;
    pub const BL_OPCODE: u32 = 0b100101;

    // Conditional branch
    pub const B_COND_MASK: u32 = 0xFF00_0000;
    pub const B_COND_VALUE: u32 = 0x5400_0000;

    // Compare and branch
    pub const CBZ_CBNZ_MASK: u32 = 0x7F00_0000;
    pub const CBZ_VALUE: u32 = 0x3400_0000;
    pub const CBNZ_VALUE: u32 = 0x3500_0000;

    // Test bit and branch
    pub const TBZ_VALUE: u32 = 0x3600_0000;
    pub const TBNZ_VALUE: u32 = 0x3700_0000;

    // Indirect branch
    pub const BR_OPCODE: u32 = 0b1101011000;
    pub const BLR_OPCODE: u32 = 0b1101011001;
    pub const RET_OPCODE: u32 = 0b1101011010;
}

#[derive(Debug, Default)]
pub struct BranchRegUsage {
    /// 读取的寄存器
    pub read_regs: u8,
    /// 是否读取NZCV标志
    pub read_flags: bool,
}

pub fn is_arm64_branch(code: u32) -> bool {
    let swapped = code.swap_bytes();
    let op6 = swapped >> 26;
    if op6 == 0b000101 || op6 == 0b100101 {
        // B, BL
        return true;
    }
    let op8 = swapped >> 24;
    if op8 == 0b01010100 {
        // B.cond
        return true;
    }
    let op10 = swapped >> 22;
    if op10 == 0b1101011000 || op10 == 0b1101011001 || op10 == 0b1101011010 {
        // BR, BLR, RET
        return true;
    }
    // CBZ/CBNZ
    if (swapped & 0x7F000000) == 0x34000000 || (swapped & 0x7F000000) == 0x35000000 {
        return true;
    }
    // TBZ/TBNZ
    if (swapped & 0xFF000000) == 0x36000000 || (swapped & 0xFF000000) == 0x37000000 {
        return true;
    }
    false
}

pub fn is_arm64_call(instr: u32) -> bool {
    let swapped = instr.swap_bytes();
    // BL: 高6位 0b100101
    if (swapped >> 26) == 0b100101 {
        return true;
    }
    // BLR: 高10位 0b11010110001
    if (swapped >> 21) == 0b11010110001 {
        return true;
    }
    false
}

/// 返回即将执行的下一条指令地址（已判断条件）
#[inline]
fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits as u64;
    ((value << shift) as i64) >> shift
}

/// 解析无条件分支指令 (B, BL)
fn parse_unconditional_branch(instr: u32, pc: usize) -> Option<Arm64BranchType> {
    use arm64_opcodes::*;

    let op6 = (instr >> 26) & 0x3F;
    if op6 == B_OPCODE || op6 == BL_OPCODE {
        let imm26 = (instr & 0x03FF_FFFF) as u64;
        let offset = (sign_extend(imm26, 26) << 2) as isize;
        let target = (pc as isize).wrapping_add(offset) as usize;
        return Some(Arm64BranchType::UnconditionalBranch { target });
    }
    None
}

/// 解析条件分支指令 (B.cond)
fn parse_conditional_branch(instr: u32, pc: usize, _regs: &UserRegs) -> Option<Arm64BranchType> {
    use arm64_opcodes::*;

    if (instr & B_COND_MASK) == B_COND_VALUE {
        let imm19 = ((instr >> 5) & 0x7FFFF) as u64;
        let offset = (sign_extend(imm19, 19) << 2) as isize;
        let branch_target = (pc as isize).wrapping_add(offset) as usize;
        let next_target = pc;

        return Some(Arm64BranchType::ConditionalBranch {
            taken: branch_target,
            not_taken: next_target,
        });
    }
    None
}

/// 解析比较分支指令 (CBZ, CBNZ)
fn parse_compare_branch(instr: u32, pc: usize, _regs: &UserRegs) -> Option<Arm64BranchType> {
    use arm64_opcodes::*;

    let top7 = instr & CBZ_CBNZ_MASK;
    if top7 == CBZ_VALUE || top7 == CBNZ_VALUE {
        let imm19 = ((instr >> 5) & 0x7FFFF) as u64;
        let offset = (sign_extend(imm19, 19) << 2) as isize;
        let branch_target = (pc as isize).wrapping_add(offset) as usize;
        let next_target = pc;

        return Some(Arm64BranchType::CompareBranch {
            taken: branch_target,
            not_taken: next_target,
        });
    }
    None
}

/// 解析测试位分支指令 (TBZ, TBNZ)
fn parse_test_bit_branch(instr: u32, pc: usize, _regs: &UserRegs) -> Option<Arm64BranchType> {
    use arm64_opcodes::*;

    let top7 = instr & CBZ_CBNZ_MASK;
    if top7 == TBZ_VALUE || top7 == TBNZ_VALUE {
        let imm14 = ((instr >> 5) & 0x3FFF) as u64;
        let offset = (sign_extend(imm14, 14) << 2) as isize;
        let branch_target = (pc as isize).wrapping_add(offset) as usize;
        let next_target = pc;

        return Some(Arm64BranchType::TestBitBranch {
            taken: branch_target,
            not_taken: next_target,
        });
    }
    None
}

/// 解析间接分支指令 (BR, BLR, RET)
fn parse_indirect_branch(instr: u32, regs: &UserRegs) -> Option<Arm64BranchType> {
    use arm64_opcodes::*;

    let op10 = (instr >> 21) & 0x3FF;
    match op10 {
        BR_OPCODE | BLR_OPCODE => {
            let rn = ((instr >> 5) & 0x1F) as usize;
            let target = if rn < 31 { regs.regs[rn] } else { regs.sp };
            Some(Arm64BranchType::IndirectBranch { target })
        }
        RET_OPCODE => {
            let rn = ((instr >> 5) & 0x1F) as usize;
            let target = if rn == 31 { regs.regs[30] } else { regs.regs[rn] };
            Some(Arm64BranchType::IndirectBranch { target })
        }
        _ => None,
    }
}

/// 判断 ARM64 条件码是否成立
fn arm64_cond_pass(cond: u8, pstate: usize) -> bool {
    let n = (pstate >> 31) & 1;
    let z = (pstate >> 30) & 1;
    let c = (pstate >> 29) & 1;
    let v = (pstate >> 28) & 1;
    match cond {
        0x0 => z == 1,             // EQ
        0x1 => z == 0,             // NE
        0x2 => c == 1,             // CS/HS
        0x3 => c == 0,             // CC/LO
        0x4 => n == 1,             // MI
        0x5 => n == 0,             // PL
        0x6 => v == 1,             // VS
        0x7 => v == 0,             // VC
        0x8 => c == 1 && z == 0,   // HI
        0x9 => c == 0 || z == 1,   // LS
        0xA => n == v,             // GE
        0xB => n != v,             // LT
        0xC => z == 0 && (n == v), // GT
        0xD => z == 1 || (n != v), // LE
        0xE => true,               // AL
        0xF => false,              // NV (保留)
        _ => false,
    }
}

/// 根据分支类型和寄存器状态决定下一条指令地址
fn resolve_branch_target(branch_type: Arm64BranchType, instr: u32, regs: &UserRegs) -> usize {
    match branch_type {
        Arm64BranchType::UnconditionalBranch { target } => target,
        Arm64BranchType::IndirectBranch { target } => target,

        Arm64BranchType::ConditionalBranch { taken, not_taken } => {
            let cond = (instr & 0xF) as u8;
            if arm64_cond_pass(cond, regs.pstate) {
                taken
            } else {
                not_taken
            }
        }

        Arm64BranchType::CompareBranch { taken, not_taken } => {
            let rt = (instr & 0x1F) as usize;
            let val = regs.regs[rt];
            let is_cbz = (instr & arm64_opcodes::CBZ_CBNZ_MASK) == arm64_opcodes::CBZ_VALUE;
            let zero = val == 0;
            if (is_cbz && zero) || (!is_cbz && !zero) {
                taken
            } else {
                not_taken
            }
        }

        Arm64BranchType::TestBitBranch { taken, not_taken } => {
            let rt = (instr & 0x1F) as usize;
            let b5 = ((instr >> 31) & 0x1) as u32;
            let b4_0 = ((instr >> 19) & 0x1F) as u32;
            let bit_ix = (b5 << 5) | b4_0;

            let val = regs.regs[rt] as u64;
            let bit_set = ((val >> bit_ix) & 1) != 0;
            let is_tbz = (instr & arm64_opcodes::CBZ_CBNZ_MASK) == arm64_opcodes::TBZ_VALUE;
            if (is_tbz && !bit_set) || (!is_tbz && bit_set) {
                taken
            } else {
                not_taken
            }
        }
    }
}

pub unsafe fn resolve_next_addr(instr_ptr: *const u32, regs: UserRegs) -> Option<usize> {
    use core::ptr;

    let instr = ptr::read_volatile(instr_ptr).swap_bytes();
    write_stream(format!("instruct: {:x}", instr).as_bytes());

    let pc = (instr_ptr as usize).wrapping_add(4);

    let branch_type = parse_unconditional_branch(instr, pc)
        .or_else(|| parse_conditional_branch(instr, pc, &regs))
        .or_else(|| parse_compare_branch(instr, pc, &regs))
        .or_else(|| parse_test_bit_branch(instr, pc, &regs))
        .or_else(|| parse_indirect_branch(instr, &regs))?;

    Some(resolve_branch_target(branch_type, instr, &regs))
}

/// 分析一条跳转指令涉及的寄存器
pub fn analyze_branch_regs(instr: u32) -> BranchRegUsage {
    let mut usage = BranchRegUsage::default();
    let swapped = instr.swap_bytes();

    let op6 = swapped >> 26;
    let op8 = swapped >> 24;
    let op10 = swapped >> 21;

    // 1. B, BL（无条件跳转/带链接）
    if op6 == 0b000101 {
        // B: 无寄存器涉及
    } else if op6 == 0b100101 {
        // BL: 写入X30（LR）
    }
    // 2. B.cond（条件跳转，读取NZCV）
    else if op8 == 0b01010100 {
        usage.read_flags = true;
    }
    // 3. CBZ/CBNZ（比较寄存器是否为0）
    else if ((swapped >> 25) & 0x3F) == 0b011010 || ((swapped >> 25) & 0x3F) == 0b011011 {
        let reg = (swapped & 0x1F) as u8;
        usage.read_regs = reg;
    }
    // 4. TBZ/TBNZ（测试寄存器某一位）
    else if ((swapped >> 25) & 0x3E) == 0b011010 || ((swapped >> 25) & 0x3E) == 0b011110 {
        let reg = (swapped & 0x1F) as u8;
        usage.read_regs = reg;
    }
    // 5. BR/BLR/RET（间接跳转）
    else if op10 == 0b1101011000 {
        // BR
        let reg = ((swapped >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
    } else if op10 == 0b1101011001 {
        // BLR
        let reg = ((swapped >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
    } else if op10 == 0b1101011010 {
        // RET
        let reg = ((swapped >> 5) & 0x1F) as u8;
        usage.read_regs = reg;
    }

    usage
}
