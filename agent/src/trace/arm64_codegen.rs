/// 生成将64位地址加载到寄存器的指令序列（MOVZ + MOVK）
pub fn gen_mov_reg_addr(reg: u8, imm: usize) -> Vec<u32> {
    let mut code = Vec::new();
    for i in 0..4 {
        let imm16 = ((imm >> (i * 16)) & 0xFFFF) as u16;
        if i == 0 {
            // MOVZ
            if imm16 != 0 {
                let instr = 0xD2800000 | ((imm16 as u32) << 5) | ((reg as u32) & 0x1F) | ((i as u32) << 21);
                code.push(instr);
            }
        } else {
            // MOVK
            if imm16 != 0 {
                let instr = 0xF2800000 | ((imm16 as u32) << 5) | ((reg as u32) & 0x1F) | ((i as u32) << 21);
                code.push(instr);
            }
        }
    }
    code
}

/// 生成跳转到 transformer 的指令序列
pub fn gen_jump_to_transformer() -> Vec<u32> {
    let mut instruct = Vec::new();
    instruct.push(0xA9BF7BFD); // stp x29, x30, [sp, #-0x10]!
    instruct.append(&mut gen_mov_reg_addr(30, super::transformer::mtransform_addr()));
    instruct.push(0xD61F03C0); // BR X30
    instruct.push(0xA8C17BFD); // ldp x29, x30, [sp], #0x10
    instruct
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
    [gen_mov_x0_xn(reg_num), gen_mov_x1_xzr(), gen_mov_x1_imm(reg_num)]
}
