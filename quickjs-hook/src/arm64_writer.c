/*
 * arm64_writer.c - ARM64 Instruction Writer Implementation
 *
 * Provides an API for dynamically generating ARM64 machine code.
 */

#include "arm64_writer.h"
#include "arm64_common.h"
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * Initialization / Cleanup
 * ============================================================================ */

void arm64_writer_init(Arm64Writer* w, void* code, uint64_t pc, size_t size) {
    w->base = (uint8_t*)code;
    w->code = (uint8_t*)code;
    w->pc = pc;
    w->size = size;
    w->labels = NULL;
    w->label_refs = NULL;
    w->next_label_id = 1;
}

void arm64_writer_reset(Arm64Writer* w, void* code, uint64_t pc) {
    arm64_writer_clear(w);
    w->base = (uint8_t*)code;
    w->code = (uint8_t*)code;
    w->pc = pc;
}

void arm64_writer_clear(Arm64Writer* w) {
    /* Free labels */
    Arm64Label* label = w->labels;
    while (label) {
        Arm64Label* next = label->next;
        free(label);
        label = next;
    }
    w->labels = NULL;

    /* Free label references */
    Arm64LabelRef* ref = w->label_refs;
    while (ref) {
        Arm64LabelRef* next = ref->next;
        free(ref);
        ref = next;
    }
    w->label_refs = NULL;
}

/* ============================================================================
 * Label Support
 * ============================================================================ */

void arm64_writer_put_label(Arm64Writer* w, uint64_t id) {
    Arm64Label* label = (Arm64Label*)malloc(sizeof(Arm64Label));
    if (!label) return;

    label->id = id;
    label->address = w->pc;
    label->next = w->labels;
    w->labels = label;
}

uint64_t arm64_writer_new_label_id(Arm64Writer* w) {
    return w->next_label_id++;
}

static Arm64Label* find_label(Arm64Writer* w, uint64_t id) {
    Arm64Label* label = w->labels;
    while (label) {
        if (label->id == id) return label;
        label = label->next;
    }
    return NULL;
}

static void add_label_ref(Arm64Writer* w, uint64_t label_id, uint8_t* insn_addr, Arm64LabelRefType type) {
    Arm64LabelRef* ref = (Arm64LabelRef*)malloc(sizeof(Arm64LabelRef));
    if (!ref) return;

    ref->label_id = label_id;
    ref->insn_addr = insn_addr;
    ref->type = type;
    ref->next = w->label_refs;
    w->label_refs = ref;
}

int arm64_writer_can_branch_directly_between(uint64_t from, uint64_t to) {
    int64_t distance = (int64_t)to - (int64_t)from;
    /* B/BL: ±128MB (26-bit signed, scaled by 4) */
    return fits_signed(distance >> 2, 26);
}

int arm64_writer_flush(Arm64Writer* w) {
    Arm64LabelRef* ref = w->label_refs;

    while (ref) {
        Arm64Label* label = find_label(w, ref->label_id);
        if (!label) return -1; /* Unresolved label */

        uint32_t* insn_ptr = (uint32_t*)ref->insn_addr;
        uint32_t insn = *insn_ptr;
        int64_t offset = (int64_t)label->address - (int64_t)(uintptr_t)ref->insn_addr;

        switch (ref->type) {
            case ARM64_LABEL_REF_B:
            case ARM64_LABEL_REF_BL: {
                int64_t imm26 = offset >> 2;
                if (!fits_signed(imm26, 26)) return -1;
                *insn_ptr = SET_BITS(insn, 25, 0, (uint32_t)imm26 & 0x03FFFFFF);
                break;
            }

            case ARM64_LABEL_REF_B_COND:
            case ARM64_LABEL_REF_CBZ:
            case ARM64_LABEL_REF_CBNZ: {
                int64_t imm19 = offset >> 2;
                if (!fits_signed(imm19, 19)) return -1;
                *insn_ptr = SET_BITS(insn, 23, 5, (uint32_t)imm19 & 0x7FFFF);
                break;
            }

            case ARM64_LABEL_REF_TBZ:
            case ARM64_LABEL_REF_TBNZ: {
                int64_t imm14 = offset >> 2;
                if (!fits_signed(imm14, 14)) return -1;
                *insn_ptr = SET_BITS(insn, 18, 5, (uint32_t)imm14 & 0x3FFF);
                break;
            }

            case ARM64_LABEL_REF_ADR: {
                if (!fits_signed(offset, 21)) return -1;
                uint32_t u = (uint32_t)offset;
                uint32_t immlo = u & 0x3;
                uint32_t immhi = (u >> 2) & 0x7FFFF;
                *insn_ptr = SET_BITS(SET_BITS(insn, 30, 29, immlo), 23, 5, immhi);
                break;
            }
        }

        ref = ref->next;
    }

    return 0;
}

/* ============================================================================
 * Raw Writing
 * ============================================================================ */

void arm64_writer_put_insn(Arm64Writer* w, uint32_t insn) {
    if (!arm64_writer_can_write(w, 4)) abort();

    *(uint32_t*)w->code = insn;
    w->code += 4;
    w->pc += 4;
}

void arm64_writer_put_bytes(Arm64Writer* w, const uint8_t* data, size_t len) {
    if (!arm64_writer_can_write(w, len)) abort();

    memcpy(w->code, data, len);
    w->code += len;
    w->pc += len;
}

/* ============================================================================
 * Branch Instructions
 * ============================================================================ */

int arm64_writer_put_b_imm(Arm64Writer* w, uint64_t target) {
    int64_t offset = (int64_t)target - (int64_t)w->pc;
    int64_t imm26 = offset >> 2;

    if ((offset & 0x3) != 0 || !fits_signed(imm26, 26)) {
        return -1;
    }

    /* B: 000101 imm26 */
    uint32_t insn = 0x14000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    arm64_writer_put_insn(w, insn);
    return 0;
}

int arm64_writer_put_bl_imm(Arm64Writer* w, uint64_t target) {
    int64_t offset = (int64_t)target - (int64_t)w->pc;
    int64_t imm26 = offset >> 2;

    if ((offset & 0x3) != 0 || !fits_signed(imm26, 26)) {
        return -1;
    }

    /* BL: 100101 imm26 */
    uint32_t insn = 0x94000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    arm64_writer_put_insn(w, insn);
    return 0;
}

void arm64_writer_put_b_label(Arm64Writer* w, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_B);
    /* B: 000101 imm26 (placeholder with 0 offset) */
    arm64_writer_put_insn(w, 0x14000000);
}

void arm64_writer_put_bl_label(Arm64Writer* w, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_BL);
    /* BL: 100101 imm26 (placeholder with 0 offset) */
    arm64_writer_put_insn(w, 0x94000000);
}

int arm64_writer_put_b_cond_imm(Arm64Writer* w, Arm64Cond cond, uint64_t target) {
    int64_t offset = (int64_t)target - (int64_t)w->pc;
    int64_t imm19 = offset >> 2;

    if ((offset & 0x3) != 0 || !fits_signed(imm19, 19)) {
        return -1;
    }

    /* B.cond: 01010100 imm19 0 cond */
    uint32_t insn = 0x54000000 | (((uint32_t)imm19 & 0x7FFFF) << 5) | (cond & 0xF);
    arm64_writer_put_insn(w, insn);
    return 0;
}

void arm64_writer_put_b_cond_label(Arm64Writer* w, Arm64Cond cond, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_B_COND);
    /* B.cond: 01010100 imm19 0 cond (placeholder) */
    uint32_t insn = 0x54000000 | (cond & 0xF);
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_cbz_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_CBZ);
    uint32_t sf = ARM64_REG_SF(reg);
    uint32_t rt = ARM64_REG_NUM(reg);
    /* CBZ: sf 011010 0 imm19 Rt */
    uint32_t insn = (sf << 31) | 0x34000000 | rt;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_cbnz_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_CBNZ);
    uint32_t sf = ARM64_REG_SF(reg);
    uint32_t rt = ARM64_REG_NUM(reg);
    /* CBNZ: sf 011010 1 imm19 Rt */
    uint32_t insn = (sf << 31) | 0x35000000 | rt;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_tbz_reg_imm_label(Arm64Writer* w, Arm64Reg reg, uint32_t bit, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_TBZ);
    uint32_t rt = ARM64_REG_NUM(reg);
    uint32_t b5 = (bit >> 5) & 1;
    uint32_t b40 = bit & 0x1F;
    /* TBZ: b5 011011 0 b40 imm14 Rt */
    uint32_t insn = (b5 << 31) | 0x36000000 | (b40 << 19) | rt;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_tbnz_reg_imm_label(Arm64Writer* w, Arm64Reg reg, uint32_t bit, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_TBNZ);
    uint32_t rt = ARM64_REG_NUM(reg);
    uint32_t b5 = (bit >> 5) & 1;
    uint32_t b40 = bit & 0x1F;
    /* TBNZ: b5 011011 1 b40 imm14 Rt */
    uint32_t insn = (b5 << 31) | 0x37000000 | (b40 << 19) | rt;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Register Branch Instructions
 * ============================================================================ */

void arm64_writer_put_br_reg(Arm64Writer* w, Arm64Reg reg) {
    uint32_t rn = ARM64_REG_NUM(reg);
    /* BR: 1101011 0000 11111 000000 Rn 00000 */
    uint32_t insn = 0xD61F0000 | (rn << 5);
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_blr_reg(Arm64Writer* w, Arm64Reg reg) {
    uint32_t rn = ARM64_REG_NUM(reg);
    /* BLR: 1101011 0001 11111 000000 Rn 00000 */
    uint32_t insn = 0xD63F0000 | (rn << 5);
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_ret(Arm64Writer* w) {
    arm64_writer_put_ret_reg(w, ARM64_REG_LR);
}

void arm64_writer_put_ret_reg(Arm64Writer* w, Arm64Reg reg) {
    uint32_t rn = ARM64_REG_NUM(reg);
    /* RET: 1101011 0010 11111 000000 Rn 00000 */
    uint32_t insn = 0xD65F0000 | (rn << 5);
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Load Instructions
 * ============================================================================ */

void arm64_writer_put_ldr_reg_u64(Arm64Writer* w, Arm64Reg reg, uint64_t val) {
    uint32_t rt = ARM64_REG_NUM(reg);
    uint32_t sf = ARM64_REG_SF(reg);

    /* LDR (literal): opc 011 0 00 imm19 Rt
     * For 64-bit: opc = 01, for 32-bit: opc = 00
     * PC-relative offset to literal, imm19 is scaled by 4
     *
     * Generate: LDR Xt, [PC, #8]; B skip; .quad val; skip:
     */

    /* LDR Xt, [PC, #8] - load from 2 instructions ahead */
    uint32_t opc = sf ? 0x01 : 0x00;
    uint32_t imm19 = 2; /* 8 bytes / 4 = 2 */
    uint32_t insn = (opc << 30) | 0x18000000 | (imm19 << 5) | rt;
    arm64_writer_put_insn(w, insn);

    /* B +12 - skip over the 8-byte literal */
    arm64_writer_put_insn(w, 0x14000003);

    /* .quad val */
    arm64_writer_put_bytes(w, (const uint8_t*)&val, 8);
}

void arm64_writer_put_ldr_reg_address(Arm64Writer* w, Arm64Reg reg, uint64_t addr) {
    arm64_writer_put_ldr_reg_u64(w, reg, addr);
}

void arm64_writer_put_ldr_reg_reg_offset(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, int64_t offset) {
    uint32_t rt = ARM64_REG_NUM(dst);
    uint32_t rn = ARM64_REG_NUM(src);
    uint32_t sf = ARM64_REG_SF(dst);

    /* Check if we can use unsigned offset form (faster) */
    uint32_t scale = sf ? 3 : 2; /* 8 bytes for 64-bit, 4 for 32-bit */
    uint64_t scaled_offset = (uint64_t)offset >> scale;

    if (offset >= 0 && (offset & ((1 << scale) - 1)) == 0 && scaled_offset <= 0xFFF) {
        /* LDR (unsigned offset): size 111 0 01 00 imm12 Rn Rt */
        uint32_t size = sf ? 0x3 : 0x2;
        uint32_t insn = (size << 30) | 0x39400000 | ((uint32_t)scaled_offset << 10) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    } else if (fits_signed(offset, 9)) {
        /* LDR (signed offset / unscaled): size 111 0 00 00 imm9 00 Rn Rt */
        uint32_t size = sf ? 0x3 : 0x2;
        uint32_t imm9 = (uint32_t)offset & 0x1FF;
        uint32_t insn = (size << 30) | 0x38400000 | (imm9 << 12) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    }
    /* TODO: Handle larger offsets with scratch register */
}

void arm64_writer_put_ldrsw_reg_reg_offset(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, int64_t offset) {
    uint32_t rt = ARM64_REG_NUM(dst);
    uint32_t rn = ARM64_REG_NUM(src);

    /* Check if we can use unsigned offset form */
    uint64_t scaled_offset = (uint64_t)offset >> 2;

    if (offset >= 0 && (offset & 0x3) == 0 && scaled_offset <= 0xFFF) {
        /* LDRSW (unsigned offset): 10 111 0 01 10 imm12 Rn Rt */
        uint32_t insn = 0xB9800000 | ((uint32_t)scaled_offset << 10) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    } else if (fits_signed(offset, 9)) {
        /* LDRSW (signed offset / unscaled): 10 111 0 00 10 imm9 00 Rn Rt */
        uint32_t imm9 = (uint32_t)offset & 0x1FF;
        uint32_t insn = 0xB8800000 | (imm9 << 12) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    }
}

void arm64_writer_put_ldp_reg_reg_reg_offset(Arm64Writer* w, Arm64Reg a, Arm64Reg b,
                                              Arm64Reg base, int64_t offset,
                                              Arm64IndexMode mode) {
    uint32_t rt1 = ARM64_REG_NUM(a);
    uint32_t rt2 = ARM64_REG_NUM(b);
    uint32_t rn = ARM64_REG_NUM(base);
    uint32_t sf = ARM64_REG_SF(a);

    /* Scale offset: 8 bytes for 64-bit, 4 for 32-bit */
    uint32_t scale = sf ? 3 : 2;
    int64_t scaled = offset >> scale;

    if (!fits_signed(scaled, 7)) return;

    uint32_t imm7 = (uint32_t)scaled & 0x7F;
    uint32_t opc = sf ? 0x2 : 0x0;
    uint32_t op2;

    switch (mode) {
        case ARM64_INDEX_POST_ADJUST: op2 = 0x1; break;  /* opc 10 1 0001 */
        case ARM64_INDEX_SIGNED_OFFSET: op2 = 0x2; break; /* opc 10 1 0010 */
        case ARM64_INDEX_PRE_ADJUST: op2 = 0x3; break;    /* opc 10 1 0011 */
        default: return;
    }

    /* LDP: opc 10 1 op2 0 L imm7 Rt2 Rn Rt1 (L=1 for load) */
    uint32_t insn = (opc << 30) | (0x5 << 27) | (op2 << 23) | (1 << 22) |
                    (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_ldr_fp_reg_reg(Arm64Writer* w, uint32_t fp_reg, Arm64Reg base, uint32_t size) {
    uint32_t rn = ARM64_REG_NUM(base);
    uint32_t rt = fp_reg & 0x1F;
    uint32_t insn;

    /* LDR (unsigned offset) for SIMD/FP with offset 0:
     * size 111 1 01 opc imm12 Rn Rt
     * For offset 0, imm12 = 0
     */
    switch (size) {
        case 4:  /* 32-bit S register: size=10, opc=01 -> 0xBD400000 */
            insn = 0xBD400000 | (rn << 5) | rt;
            break;
        case 8:  /* 64-bit D register: size=11, opc=01 -> 0xFD400000 */
            insn = 0xFD400000 | (rn << 5) | rt;
            break;
        case 16: /* 128-bit Q register: size=00, opc=11 -> 0x3DC00000 */
            insn = 0x3DC00000 | (rn << 5) | rt;
            break;
        default:
            return; /* Invalid size */
    }
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Store Instructions
 * ============================================================================ */

void arm64_writer_put_str_reg_reg_offset(Arm64Writer* w, Arm64Reg src, Arm64Reg dst, int64_t offset) {
    uint32_t rt = ARM64_REG_NUM(src);
    uint32_t rn = ARM64_REG_NUM(dst);
    uint32_t sf = ARM64_REG_SF(src);

    uint32_t scale = sf ? 3 : 2;
    uint64_t scaled_offset = (uint64_t)offset >> scale;

    if (offset >= 0 && (offset & ((1 << scale) - 1)) == 0 && scaled_offset <= 0xFFF) {
        /* STR (unsigned offset): size 111 0 01 00 imm12 Rn Rt */
        uint32_t size = sf ? 0x3 : 0x2;
        uint32_t insn = (size << 30) | 0x39000000 | ((uint32_t)scaled_offset << 10) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    } else if (fits_signed(offset, 9)) {
        /* STR (signed offset / unscaled): size 111 0 00 00 imm9 00 Rn Rt */
        uint32_t size = sf ? 0x3 : 0x2;
        uint32_t imm9 = (uint32_t)offset & 0x1FF;
        uint32_t insn = (size << 30) | 0x38000000 | (imm9 << 12) | (rn << 5) | rt;
        arm64_writer_put_insn(w, insn);
    }
}

void arm64_writer_put_stp_reg_reg_reg_offset(Arm64Writer* w, Arm64Reg a, Arm64Reg b,
                                              Arm64Reg base, int64_t offset,
                                              Arm64IndexMode mode) {
    uint32_t rt1 = ARM64_REG_NUM(a);
    uint32_t rt2 = ARM64_REG_NUM(b);
    uint32_t rn = ARM64_REG_NUM(base);
    uint32_t sf = ARM64_REG_SF(a);

    uint32_t scale = sf ? 3 : 2;
    int64_t scaled = offset >> scale;

    if (!fits_signed(scaled, 7)) return;

    uint32_t imm7 = (uint32_t)scaled & 0x7F;
    uint32_t opc = sf ? 0x2 : 0x0;
    uint32_t op2;

    switch (mode) {
        case ARM64_INDEX_POST_ADJUST: op2 = 0x1; break;
        case ARM64_INDEX_SIGNED_OFFSET: op2 = 0x2; break;
        case ARM64_INDEX_PRE_ADJUST: op2 = 0x3; break;
        default: return;
    }

    /* STP: opc 10 1 op2 0 L imm7 Rt2 Rn Rt1 (L=0 for store) */
    uint32_t insn = (opc << 30) | (0x5 << 27) | (op2 << 23) | (0 << 22) |
                    (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Arithmetic Instructions
 * ============================================================================ */

/* Internal helper for ADD/SUB immediate encoding.
 * op_base: 0x11000000 for ADD, 0x51000000 for SUB
 * op_shift: 0x11400000 for ADD LSL#12, 0x51400000 for SUB LSL#12 */
static void arm64_writer_put_addsub_reg_reg_imm(Arm64Writer* w, Arm64Reg dst, Arm64Reg src,
                                                  uint64_t imm, uint32_t op_base, uint32_t op_shift) {
    uint32_t rd = ARM64_REG_NUM(dst);
    uint32_t rn = ARM64_REG_NUM(src);
    uint32_t sf = ARM64_REG_SF(dst);

    if (imm <= 0xFFF) {
        uint32_t insn = (sf << 31) | op_base | ((uint32_t)imm << 10) | (rn << 5) | rd;
        arm64_writer_put_insn(w, insn);
    } else if ((imm & 0xFFF) == 0 && (imm >> 12) <= 0xFFF) {
        uint32_t insn = (sf << 31) | op_shift | ((uint32_t)(imm >> 12) << 10) | (rn << 5) | rd;
        arm64_writer_put_insn(w, insn);
    } else if ((imm >> 12) <= 0xFFF) {
        uint32_t hi12 = (uint32_t)(imm >> 12) & 0xFFF;
        uint32_t lo12 = (uint32_t)(imm & 0xFFF);
        uint32_t insn1 = (sf << 31) | op_shift | (hi12 << 10) | (rn << 5) | rd;
        uint32_t insn2 = (sf << 31) | op_base  | (lo12 << 10) | (rd << 5) | rd;
        arm64_writer_put_insn(w, insn1);
        arm64_writer_put_insn(w, insn2);
    }
    /* Immediates > 24 bits are not handled; callers must use register form. */
}

void arm64_writer_put_add_reg_reg_imm(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, uint64_t imm) {
    arm64_writer_put_addsub_reg_reg_imm(w, dst, src, imm, 0x11000000, 0x11400000);
}

void arm64_writer_put_add_reg_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg left, Arm64Reg right) {
    uint32_t rd = ARM64_REG_NUM(dst);
    uint32_t rn = ARM64_REG_NUM(left);
    uint32_t rm = ARM64_REG_NUM(right);
    uint32_t sf = ARM64_REG_SF(dst);

    /* ADD (shifted register): sf 0 0 01011 shift 0 Rm imm6 Rn Rd */
    uint32_t insn = (sf << 31) | 0x0B000000 | (rm << 16) | (rn << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_sub_reg_reg_imm(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, uint64_t imm) {
    arm64_writer_put_addsub_reg_reg_imm(w, dst, src, imm, 0x51000000, 0x51400000);
}

void arm64_writer_put_sub_reg_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg left, Arm64Reg right) {
    uint32_t rd = ARM64_REG_NUM(dst);
    uint32_t rn = ARM64_REG_NUM(left);
    uint32_t rm = ARM64_REG_NUM(right);
    uint32_t sf = ARM64_REG_SF(dst);

    /* SUB (shifted register): sf 1 0 01011 shift 0 Rm imm6 Rn Rd */
    uint32_t insn = (sf << 31) | 0x4B000000 | (rm << 16) | (rn << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Data Movement Instructions
 * ============================================================================ */

void arm64_writer_put_mov_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg src) {
    uint32_t rd = ARM64_REG_NUM(dst);
    uint32_t rm = ARM64_REG_NUM(src);
    uint32_t sf = ARM64_REG_SF(dst);

    /* Check if we need special handling for SP */
    if (dst == ARM64_REG_SP || src == ARM64_REG_SP) {
        /* MOV to/from SP: ADD Xd, Xn, #0 */
        arm64_writer_put_add_reg_reg_imm(w, dst, src, 0);
    } else {
        /* MOV (register): ORR Xd, XZR, Xm */
        /* ORR (shifted register): sf 01 01010 shift 0 Rm imm6 Rn Rd */
        uint32_t insn = (sf << 31) | 0x2A000000 | (rm << 16) | (31 << 5) | rd;
        arm64_writer_put_insn(w, insn);
    }
}

void arm64_writer_put_movz_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift) {
    uint32_t rd = ARM64_REG_NUM(reg);
    uint32_t sf = ARM64_REG_SF(reg);
    uint32_t hw = shift / 16;

    /* MOVZ: sf 10 100101 hw imm16 Rd */
    uint32_t insn = (sf << 31) | 0x52800000 | (hw << 21) | ((uint32_t)imm << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_movk_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift) {
    uint32_t rd = ARM64_REG_NUM(reg);
    uint32_t sf = ARM64_REG_SF(reg);
    uint32_t hw = shift / 16;

    /* MOVK: sf 11 100101 hw imm16 Rd */
    uint32_t insn = (sf << 31) | 0x72800000 | (hw << 21) | ((uint32_t)imm << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_movn_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift) {
    uint32_t rd = ARM64_REG_NUM(reg);
    uint32_t sf = ARM64_REG_SF(reg);
    uint32_t hw = shift / 16;

    /* MOVN: sf 00 100101 hw imm16 Rd */
    uint32_t insn = (sf << 31) | 0x12800000 | (hw << 21) | ((uint32_t)imm << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_mov_reg_imm(Arm64Writer* w, Arm64Reg reg, uint64_t imm) {
    uint32_t sf = ARM64_REG_SF(reg);
    uint64_t mask = sf ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL;
    imm &= mask;

    /* Check for zero */
    if (imm == 0) {
        arm64_writer_put_movz_reg_imm(w, reg, 0, 0);
        return;
    }

    /* Check for all ones (can use MOVN) */
    if (imm == mask) {
        arm64_writer_put_movn_reg_imm(w, reg, 0, 0);
        return;
    }

    /* Count non-zero 16-bit chunks */
    int chunks[4];
    int nonzero_count = 0;
    for (int i = 0; i < 4; i++) {
        chunks[i] = (imm >> (i * 16)) & 0xFFFF;
        if (chunks[i] != 0) nonzero_count++;
    }

    /* If only one chunk is non-zero, use MOVZ */
    if (nonzero_count == 1) {
        for (int i = 0; i < 4; i++) {
            if (chunks[i] != 0) {
                arm64_writer_put_movz_reg_imm(w, reg, (uint16_t)chunks[i], i * 16);
                return;
            }
        }
    }

    /* Check if MOVN would be more efficient (mostly 1s) */
    uint64_t inverted = ~imm & mask;
    int inv_chunks[4];
    int inv_nonzero = 0;
    for (int i = 0; i < 4; i++) {
        inv_chunks[i] = (inverted >> (i * 16)) & 0xFFFF;
        if (inv_chunks[i] != 0) inv_nonzero++;
    }

    if (inv_nonzero < nonzero_count) {
        /* Use MOVN followed by MOVK */
        int first = 1;
        for (int i = 0; i < 4; i++) {
            if (first && inv_chunks[i] != 0xFFFF) {
                arm64_writer_put_movn_reg_imm(w, reg, (uint16_t)~inv_chunks[i], i * 16);
                first = 0;
            } else if (!first && inv_chunks[i] != 0xFFFF) {
                arm64_writer_put_movk_reg_imm(w, reg, (uint16_t)chunks[i], i * 16);
            }
        }
        if (first) {
            /* All chunks are 0xFFFF, should have been caught earlier */
            arm64_writer_put_movn_reg_imm(w, reg, 0, 0);
        }
    } else {
        /* Use MOVZ followed by MOVK */
        int first = 1;
        for (int i = 0; i < 4; i++) {
            if (chunks[i] != 0) {
                if (first) {
                    arm64_writer_put_movz_reg_imm(w, reg, (uint16_t)chunks[i], i * 16);
                    first = 0;
                } else {
                    arm64_writer_put_movk_reg_imm(w, reg, (uint16_t)chunks[i], i * 16);
                }
            }
        }
    }
}

/* ============================================================================
 * Address Generation Instructions
 * ============================================================================ */

void arm64_writer_put_adr_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id) {
    add_label_ref(w, label_id, w->code, ARM64_LABEL_REF_ADR);
    uint32_t rd = ARM64_REG_NUM(reg);
    /* ADR: 0 immlo 10000 immhi Rd (placeholder with 0 offset) */
    uint32_t insn = 0x10000000 | rd;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_adrp_reg_address(Arm64Writer* w, Arm64Reg reg, uint64_t addr) {
    uint32_t rd = ARM64_REG_NUM(reg);
    int64_t pc_page = (int64_t)w->pc & ~0xFFFLL;
    int64_t target_page = (int64_t)addr & ~0xFFFLL;
    int64_t offset_pages = (target_page - pc_page) >> 12;

    if (!fits_signed(offset_pages, 21)) return;

    uint32_t u = (uint32_t)offset_pages;
    uint32_t immlo = u & 0x3;
    uint32_t immhi = (u >> 2) & 0x7FFFF;

    /* ADRP: 1 immlo 10000 immhi Rd */
    uint32_t insn = 0x90000000 | (immlo << 29) | (immhi << 5) | rd;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Miscellaneous Instructions
 * ============================================================================ */

void arm64_writer_put_nop(Arm64Writer* w) {
    arm64_writer_put_insn(w, 0xD503201F);
}

void arm64_writer_put_brk_imm(Arm64Writer* w, uint16_t imm) {
    /* BRK: 1101 0100 001 imm16 000 00 */
    uint32_t insn = 0xD4200000 | ((uint32_t)imm << 5);
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_svc_imm(Arm64Writer* w, uint16_t imm) {
    /* SVC: 1101 0100 000 imm16 000 01 */
    uint32_t insn = 0xD4000001 | ((uint32_t)imm << 5);
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_mrs_reg(Arm64Writer* w, Arm64Reg reg, uint32_t sysreg) {
    uint32_t rt = ARM64_REG_NUM(reg);
    /* MRS: 1101 0101 0011 op0 op1 CRn CRm op2 Rt */
    uint32_t insn = 0xD5300000 | (sysreg << 5) | rt;
    arm64_writer_put_insn(w, insn);
}

void arm64_writer_put_msr_reg(Arm64Writer* w, uint32_t sysreg, Arm64Reg reg) {
    uint32_t rt = ARM64_REG_NUM(reg);
    /* MSR: 1101 0101 0001 op0 op1 CRn CRm op2 Rt */
    uint32_t insn = 0xD5100000 | (sysreg << 5) | rt;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Convenience Functions for Hooking
 * ============================================================================ */

void arm64_writer_put_push_reg_reg(Arm64Writer* w, Arm64Reg a, Arm64Reg b) {
    /* STP Xa, Xb, [SP, #-16]! */
    arm64_writer_put_stp_reg_reg_reg_offset(w, a, b, ARM64_REG_SP, -16, ARM64_INDEX_PRE_ADJUST);
}

void arm64_writer_put_pop_reg_reg(Arm64Writer* w, Arm64Reg a, Arm64Reg b) {
    /* LDP Xa, Xb, [SP], #16 */
    arm64_writer_put_ldp_reg_reg_reg_offset(w, a, b, ARM64_REG_SP, 16, ARM64_INDEX_POST_ADJUST);
}

void arm64_writer_put_push_all_regs(Arm64Writer* w) {
    /* Save x0-x30 (not SP itself, but we'll save it in context)
     * Use STP to save pairs of registers
     *
     * Stack layout (from high to low):
     *   x30, x29
     *   x28, x27
     *   ...
     *   x2, x1
     *   x0, xzr (padding)
     */

    /* First allocate stack space: 32 * 8 = 256 bytes */
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 256);

    /* Save registers using STP with signed offset */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X30, ARM64_REG_SP, 240);
}

void arm64_writer_put_pop_all_regs(Arm64Writer* w) {
    /* Restore x30 first */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore register pairs */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }

    /* Deallocate stack space */
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 256);
}

void arm64_writer_put_branch_address_reg(Arm64Writer* w, uint64_t target, Arm64Reg scratch) {
    arm64_writer_put_mov_reg_imm(w, scratch, target);
    arm64_writer_put_br_reg(w, scratch);
}

void arm64_writer_put_call_address_reg(Arm64Writer* w, uint64_t target, Arm64Reg scratch) {
    arm64_writer_put_mov_reg_imm(w, scratch, target);
    arm64_writer_put_blr_reg(w, scratch);
}

void arm64_writer_put_branch_address(Arm64Writer* w, uint64_t target) {
    arm64_writer_put_branch_address_reg(w, target, ARM64_REG_X16);
}

/* ADRP+ADD+BR: 12 字节 PC-relative 跳转（纯 ALU，wxshadow 安全）。
 * 要求 target 在 PC ±4GB 范围内。 */
void arm64_writer_put_adrp_add_br(Arm64Writer* w, Arm64Reg scratch, uint64_t target) {
    uint64_t pc = w->pc + arm64_writer_offset(w);
    uint64_t pc_page = pc & ~0xFFFULL;
    uint64_t target_page = target & ~0xFFFULL;
    int64_t page_delta = (int64_t)(target_page - pc_page);
    int32_t immhi = (int32_t)(page_delta >> 14) & 0x7FFFF; /* bits [32:14] */
    int32_t immlo = (int32_t)(page_delta >> 12) & 0x3;     /* bits [13:12] */
    uint32_t rd = scratch - ARM64_REG_X0;

    /* ADRP Xd, #page_delta */
    uint32_t adrp = (1 << 31) | ((uint32_t)immlo << 29) | (0x10 << 24) | ((uint32_t)immhi << 5) | rd;
    arm64_writer_put_insn(w, adrp);

    /* ADD Xd, Xd, #lo12
     * encoding: sf=1 | 00 | 10001 | shift=0 | imm12 | Rn | Rd
     * = 0x91000000 | (imm12 << 10) | (Rn << 5) | Rd */
    uint32_t lo12 = (uint32_t)(target & 0xFFF);
    uint32_t add = 0x91000000 | (lo12 << 10) | (rd << 5) | rd;
    arm64_writer_put_insn(w, add);

    /* BR Xd */
    arm64_writer_put_br_reg(w, scratch);
}

void arm64_writer_put_call_address(Arm64Writer* w, uint64_t target) {
    arm64_writer_put_call_address_reg(w, target, ARM64_REG_X16);
}

/* ============================================================================
 * FP/SIMD Pair Instructions
 * ============================================================================ */

/* STP Dt1, Dt2, [Xn, #offset] — signed offset mode
 * Encoding: opc=01 V=1 L=0 imm7 Rt2 Rn Rt1
 * opc=01 → 64-bit (D registers), V=1 → SIMD/FP
 * imm7 is offset / 8 (scale factor for 64-bit) */
void arm64_writer_put_fp_stp_offset(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                     Arm64Reg base, int32_t offset) {
    int32_t imm7 = offset / 8;
    uint32_t insn = (0x6D << 24)   /* opc=01 1 01 (STP, signed offset, V=1) */
                  | ((imm7 & 0x7F) << 15)
                  | (dt2 << 10)
                  | (ARM64_REG_NUM(base) << 5)
                  | dt1;
    arm64_writer_put_insn(w, insn);
}

/* STP Dt1, Dt2, [Xn, #offset]! — pre-index mode */
void arm64_writer_put_fp_stp_pre(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                  Arm64Reg base, int32_t offset) {
    int32_t imm7 = offset / 8;
    uint32_t insn = 0x6D800000
                  | ((imm7 & 0x7F) << 15)
                  | (dt2 << 10)
                  | (ARM64_REG_NUM(base) << 5)
                  | dt1;
    arm64_writer_put_insn(w, insn);
}

/* LDP Dt1, Dt2, [Xn, #offset] — signed offset mode */
void arm64_writer_put_fp_ldp_offset(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                     Arm64Reg base, int32_t offset) {
    int32_t imm7 = offset / 8;
    uint32_t insn = (0x6D << 24)   /* opc=01 1 01 (signed offset, V=1) */
                  | (1u << 22)     /* L=1 → load */
                  | ((imm7 & 0x7F) << 15)
                  | (dt2 << 10)
                  | (ARM64_REG_NUM(base) << 5)
                  | dt1;
    arm64_writer_put_insn(w, insn);
}

/* LDP Dt1, Dt2, [Xn], #offset — post-index mode */
void arm64_writer_put_fp_ldp_post(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                   Arm64Reg base, int32_t offset) {
    int32_t imm7 = offset / 8;
    uint32_t insn = 0x6CC00000     /* post-index LDP FP: 0110 1100 1 1 */
                  | ((imm7 & 0x7F) << 15)
                  | (dt2 << 10)
                  | (ARM64_REG_NUM(base) << 5)
                  | dt1;
    arm64_writer_put_insn(w, insn);
}

/* ============================================================================
 * Comparison Instructions
 * ============================================================================ */

/* CMP Xn, Xm — alias for SUBS XZR, Xn, Xm
 * Sets NZCV flags based on Xn - Xm. */
void arm64_writer_put_cmp_reg_reg(Arm64Writer* w, Arm64Reg rn, Arm64Reg rm) {
    uint32_t insn = 0xEB00001F
                  | (ARM64_REG_NUM(rm) << 16)
                  | (ARM64_REG_NUM(rn) << 5);
    arm64_writer_put_insn(w, insn);
}
