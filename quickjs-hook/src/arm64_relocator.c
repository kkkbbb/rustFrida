/*
 * arm64_relocator.c - ARM64 Instruction Relocator Implementation
 *
 * Provides an API for relocating ARM64 instructions from one address to another,
 * handling PC-relative instructions that need adjustment.
 */

#include "arm64_relocator.h"
#include "arm64_common.h"
#include <string.h>

/* ============================================================================
 * Initialization / Cleanup
 * ============================================================================ */

void arm64_relocator_init(Arm64Relocator* r, const void* input, uint64_t input_pc, Arm64Writer* output) {
    r->input_start = (const uint8_t*)input;
    r->input_cur = (const uint8_t*)input;
    r->input_pc = input_pc;
    r->output = output;
    r->current_insn = 0;
    memset(&r->current_info, 0, sizeof(r->current_info));
    r->eoi = 0;
    r->eob = 0;
    r->region_label_count = 0;
    r->region_end = 0;
    memset(r->region_labels, 0, sizeof(r->region_labels));
    r->written_regs = 0;
    r->preserve_call_return_to_original = 0;
    r->original_call_return_pc = 0;
    r->page_redirect_orig_base = 0;
    r->page_redirect_new_base = 0;
    r->page_redirect_size = 0;
}

void arm64_relocator_reset(Arm64Relocator* r, const void* input, uint64_t input_pc) {
    r->input_start = (const uint8_t*)input;
    r->input_cur = (const uint8_t*)input;
    r->input_pc = input_pc;
    r->current_insn = 0;
    memset(&r->current_info, 0, sizeof(r->current_info));
    r->eoi = 0;
    r->eob = 0;
    r->region_label_count = 0;
    r->region_end = 0;
    memset(r->region_labels, 0, sizeof(r->region_labels));
    r->written_regs = 0;
    r->preserve_call_return_to_original = 0;
    r->original_call_return_pc = 0;
    r->page_redirect_orig_base = 0;
    r->page_redirect_new_base = 0;
    r->page_redirect_size = 0;
}

void arm64_relocator_clear(Arm64Relocator* r) {
    /* No dynamic memory to free */
    (void)r;
}

/* ============================================================================
 * Instruction Analysis
 * ============================================================================ */

Arm64InsnInfo arm64_relocator_analyze_insn(uint64_t pc, uint32_t insn) {
    Arm64InsnInfo info;
    memset(&info, 0, sizeof(info));
    info.type = ARM64_INSN_OTHER;
    info.is_pc_relative = 0;

    /* B / BL: op0=00101 (B) or op0=10010 (BL)
     * Format: op 00101 imm26
     * B:  0 00101 imm26 (0x14000000)
     * BL: 1 00101 imm26 (0x94000000)
     */
    if ((insn & 0x7C000000) == 0x14000000) {
        info.is_pc_relative = 1;
        uint32_t imm26 = GET_BITS(insn, 25, 0);
        int64_t offset = sign_extend(imm26, 26) << 2;
        info.target = pc + offset;

        if (insn & 0x80000000) {
            info.type = ARM64_INSN_BL;
        } else {
            info.type = ARM64_INSN_B;
        }
        return info;
    }

    /* B.cond: 01010100 imm19 0 cond */
    if ((insn & 0xFF000010) == 0x54000000) {
        info.type = ARM64_INSN_B_COND;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.cond = (Arm64Cond)(insn & 0xF);
        return info;
    }

    /* CBZ / CBNZ: sf 011010 op imm19 Rt
     * CBZ:  sf 0110100 imm19 Rt (0x34000000)
     * CBNZ: sf 0110101 imm19 Rt (0x35000000)
     */
    if ((insn & 0x7E000000) == 0x34000000) {
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.reg = (Arm64Reg)(insn & 0x1F);
        if (insn & 0x80000000) {
            info.reg = (Arm64Reg)(info.reg); /* 64-bit */
        } else {
            info.reg = (Arm64Reg)(info.reg + 32); /* 32-bit W register */
        }

        if (insn & 0x01000000) {
            info.type = ARM64_INSN_CBNZ;
        } else {
            info.type = ARM64_INSN_CBZ;
        }
        return info;
    }

    /* TBZ / TBNZ: b5 011011 op b40 imm14 Rt
     * TBZ:  b5 0110110 b40 imm14 Rt (0x36000000)
     * TBNZ: b5 0110111 b40 imm14 Rt (0x37000000)
     */
    if ((insn & 0x7E000000) == 0x36000000) {
        info.is_pc_relative = 1;
        uint32_t imm14 = GET_BITS(insn, 18, 5);
        int64_t offset = sign_extend(imm14, 14) << 2;
        info.target = pc + offset;
        info.reg = (Arm64Reg)(insn & 0x1F);
        info.bit = (GET_BITS(insn, 31, 31) << 5) | GET_BITS(insn, 23, 19);

        if (insn & 0x01000000) {
            info.type = ARM64_INSN_TBNZ;
        } else {
            info.type = ARM64_INSN_TBZ;
        }
        return info;
    }

    /* ADR: 0 immlo 10000 immhi Rd */
    if ((insn & 0x9F000000) == 0x10000000) {
        info.type = ARM64_INSN_ADR;
        info.is_pc_relative = 1;
        uint32_t immlo = GET_BITS(insn, 30, 29);
        uint32_t immhi = GET_BITS(insn, 23, 5);
        uint32_t imm21 = (immhi << 2) | immlo;
        int64_t offset = sign_extend(imm21, 21);
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        return info;
    }

    /* ADRP: 1 immlo 10000 immhi Rd */
    if ((insn & 0x9F000000) == 0x90000000) {
        info.type = ARM64_INSN_ADRP;
        info.is_pc_relative = 1;
        uint32_t immlo = GET_BITS(insn, 30, 29);
        uint32_t immhi = GET_BITS(insn, 23, 5);
        uint32_t imm21 = (immhi << 2) | immlo;
        int64_t offset_pages = sign_extend(imm21, 21);
        info.target = (pc & ~0xFFFULL) + (offset_pages << 12);
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        return info;
    }

    /* LDR literal (GPR): opc 011 0 00 imm19 Rt
     * opc=00: 32-bit (0x18000000)
     * opc=01: 64-bit (0x58000000)
     */
    if ((insn & 0xBF000000) == 0x18000000) {
        info.type = ARM64_INSN_LDR_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        info.is_signed = 0;
        return info;
    }

    /* LDRSW literal: 10 011 0 00 imm19 Rt (0x98000000) */
    if ((insn & 0xFF000000) == 0x98000000) {
        info.type = ARM64_INSN_LDRSW_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        info.is_signed = 1;
        return info;
    }

    /* LDR literal (FP/SIMD): opc 011 1 00 imm19 Rt
     * opc=00: 32-bit S register (0x1C000000)
     * opc=01: 64-bit D register (0x5C000000)
     * opc=10: 128-bit Q register (0x9C000000)
     */
    if ((insn & 0x3F000000) == 0x1C000000) {
        info.type = ARM64_INSN_LDR_LITERAL_FP;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        uint32_t opc = GET_BITS(insn, 31, 30);
        info.fp_size = (opc == 0) ? 4 : (opc == 1) ? 8 : 16;
        return info;
    }

    /* PRFM literal: 11 011 0 00 imm19 Rt (0xD8000000) */
    if ((insn & 0xFF000000) == 0xD8000000) {
        info.type = ARM64_INSN_PRFM_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        return info;
    }

    /* BR: 1101011 0000 11111 000000 Rn 00000 (0xD61F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
        info.type = ARM64_INSN_BR;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    /* BLR: 1101011 0001 11111 000000 Rn 00000 (0xD63F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) {
        info.type = ARM64_INSN_BLR;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    /* RET: 1101011 0010 11111 000000 Rn 00000 (0xD65F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        info.type = ARM64_INSN_RET;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    return info;
}

/* ============================================================================
 * Reading Instructions
 * ============================================================================ */

int arm64_relocator_read_one(Arm64Relocator* r) {
    if (r->eoi) return 0;

    r->current_insn = *(const uint32_t*)r->input_cur;
    uint64_t current_pc = r->input_pc + (uint64_t)(r->input_cur - r->input_start);
    r->current_info = arm64_relocator_analyze_insn(current_pc, r->current_insn);

    r->input_cur += 4;

    /* Check for end-of-block (unconditional branch without link) */
    if (r->current_info.type == ARM64_INSN_B ||
        r->current_info.type == ARM64_INSN_BR ||
        r->current_info.type == ARM64_INSN_RET) {
        r->eob = 1;
    }

    return 4;
}

/* ============================================================================
 * Instruction Relocation
 * ============================================================================ */

/* Generic helper: relocate a PC-relative instruction with a single contiguous
 * immediate field.  Covers B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, LDR literal
 * (GPR/LDRSW/FP), and PRFM literal.
 *
 * Parameters:
 *   match_mask/match_val  — instruction identification
 *   hi/lo                 — bit range of the immediate field
 *   width                 — sign-extension width of the raw immediate
 *   imm_mask              — mask for the relocated immediate bits
 */
static Arm64RelocResult try_relocate_pcrel_imm(
        uint64_t src_pc, uint64_t dst_pc, uint32_t insn, uint32_t* out,
        uint32_t match_mask, uint32_t match_val,
        int hi, int lo, int width, uint32_t imm_mask) {
    if ((insn & match_mask) != match_val) return ARM64_RELOC_ERROR;

    uint32_t imm = GET_BITS(insn, hi, lo);
    int64_t offset = sign_extend(imm, width) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm = new_offset >> 2;
    if (!fits_signed(new_imm, width)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, hi, lo, (uint32_t)new_imm & imm_mask);
    return ARM64_RELOC_OK;
}

/* ADR: split immediate (immhi:immlo), no shift */
static Arm64RelocResult try_relocate_adr(uint64_t src_pc, uint64_t dst_pc,
                                          uint32_t insn, uint32_t* out) {
    if ((insn & 0x9F000000) != 0x10000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t immlo = GET_BITS(insn, 30, 29);
    uint32_t immhi = GET_BITS(insn, 23, 5);
    uint32_t imm21 = (immhi << 2) | immlo;
    int64_t offset = sign_extend(imm21, 21);
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if (!fits_signed(new_offset, 21)) return ARM64_RELOC_OUT_OF_RANGE;

    uint32_t u = (uint32_t)new_offset;
    uint32_t new_immlo = u & 0x3;
    uint32_t new_immhi = (u >> 2) & 0x7FFFF;

    *out = SET_BITS(SET_BITS(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    return ARM64_RELOC_OK;
}

/* ADRP: split immediate, page-aligned */
static Arm64RelocResult try_relocate_adrp(uint64_t src_pc, uint64_t dst_pc,
                                           uint32_t insn, uint32_t* out) {
    if ((insn & 0x9F000000) != 0x90000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t immlo = GET_BITS(insn, 30, 29);
    uint32_t immhi = GET_BITS(insn, 23, 5);
    uint32_t imm21 = (immhi << 2) | immlo;
    int64_t offset_pages = sign_extend(imm21, 21);

    int64_t src_page = (int64_t)src_pc & ~0xFFFLL;
    int64_t target = src_page + (offset_pages << 12);

    int64_t dst_page = (int64_t)dst_pc & ~0xFFFLL;
    int64_t new_offset_pages = (target - dst_page) >> 12;

    if (!fits_signed(new_offset_pages, 21)) return ARM64_RELOC_OUT_OF_RANGE;

    uint32_t u = (uint32_t)new_offset_pages;
    uint32_t new_immlo = u & 0x3;
    uint32_t new_immhi = (u >> 2) & 0x7FFFF;

    *out = SET_BITS(SET_BITS(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    return ARM64_RELOC_OK;
}

/* Instruction relocation dispatch table — all single-field PC-relative types */
typedef struct {
    uint32_t match_mask;
    uint32_t match_val;
    int hi, lo, width;
    uint32_t imm_mask;
} PcrelImmDesc;

static const PcrelImmDesc pcrel_table[] = {
    { 0x7C000000, 0x14000000, 25, 0, 26, 0x03FFFFFF }, /* B / BL          */
    { 0xFF000010, 0x54000000, 23, 5, 19, 0x7FFFF },    /* B.cond          */
    { 0x7E000000, 0x34000000, 23, 5, 19, 0x7FFFF },    /* CBZ / CBNZ      */
    { 0x7E000000, 0x36000000, 18, 5, 14, 0x3FFF },     /* TBZ / TBNZ      */
    { 0xBF000000, 0x18000000, 23, 5, 19, 0x7FFFF },    /* LDR literal GPR */
    { 0xFF000000, 0x98000000, 23, 5, 19, 0x7FFFF },    /* LDRSW literal   */
    { 0x3F000000, 0x1C000000, 23, 5, 19, 0x7FFFF },    /* LDR literal FP  */
    { 0xFF000000, 0xD8000000, 23, 5, 19, 0x7FFFF },    /* PRFM literal    */
};

#define PCREL_TABLE_SIZE (sizeof(pcrel_table) / sizeof(pcrel_table[0]))

Arm64RelocResult arm64_relocator_relocate_insn(uint64_t src_pc, uint64_t dst_pc,
                                                uint32_t insn, uint32_t* out) {
    Arm64RelocResult result;

    /* Try table-driven relocation for single-field PC-relative instructions */
    for (int i = 0; i < (int)PCREL_TABLE_SIZE; i++) {
        const PcrelImmDesc* d = &pcrel_table[i];
        result = try_relocate_pcrel_imm(src_pc, dst_pc, insn, out,
                                         d->match_mask, d->match_val,
                                         d->hi, d->lo, d->width, d->imm_mask);
        if (result != ARM64_RELOC_ERROR) return result;
    }

    /* ADR / ADRP — split immediate fields, handled separately */
    result = try_relocate_adr(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_adrp(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    /* Not a PC-relative instruction, copy as-is */
    *out = insn;
    return ARM64_RELOC_OK;
}

/* ============================================================================
 * Writing Instructions
 * ============================================================================ */

/* Track which GPRs are written by the current instruction.
 *
 * For PC-relative instructions (which the relocator modifies), we precisely
 * track the destination register.  For OTHER instructions (copied as-is),
 * we conservatively check if bits[4:0] (Rd/Rt) is X16 or X17 and the
 * instruction is not a store (where Rt is a source, not destination).
 *
 * Only X16/X17 matter for scratch register selection, but we track all
 * PC-relative dst_regs for completeness. */
static void track_written_regs(Arm64Relocator* r, uint32_t insn, const Arm64InsnInfo* info) {
    switch (info->type) {
        case ARM64_INSN_ADR:
        case ARM64_INSN_ADRP:
        case ARM64_INSN_LDR_LITERAL:
        case ARM64_INSN_LDRSW_LITERAL:
        case ARM64_INSN_LDR_LITERAL_FP:
            r->written_regs |= (1u << (info->dst_reg & 31));
            break;
        case ARM64_INSN_BL:
            r->written_regs |= (1u << 30);  /* X30 (LR) */
            break;
        case ARM64_INSN_OTHER: {
            /* For non-PC-relative instructions, only check if X16 or X17
             * might be written (our scratch register candidates).
             * Rd/Rt is typically in bits[4:0]. */
            uint32_t rd = insn & 0x1F;
            if (rd == 16 || rd == 17) {
                /* Exclude store instructions where Rt in bits[4:0] is a source.
                 * Load/store encoding: bits[27:25] indicate the major group.
                 * Group 4 (0b0100): load/store — bit 22 (L) distinguishes load vs store.
                 * Group 6 (0b0110): load/store pair — bit 22 (L) distinguishes.
                 * For stores (L=0), Rt is read, not written. */
                uint32_t op0 = (insn >> 25) & 0xF;
                if (op0 == 0x4 || op0 == 0x6 || op0 == 0xC || op0 == 0xE) {
                    /* Load/store group: check L bit (bit 22) */
                    if ((insn >> 22) & 1) {
                        /* L=1: load — Rt IS written */
                        r->written_regs |= (1u << rd);
                    }
                    /* L=0: store — Rt is read, not written → don't mark */
                } else {
                    /* Non-load/store instruction: Rd in bits[4:0] is likely written */
                    r->written_regs |= (1u << rd);
                }
            }
            break;
        }
        default:
            break;
    }
}

/* Look up the writer label for a source address within the hook region.
 * Returns the label_id if found, 0 if not found (0 is never a valid label ID
 * because arm64_writer_init sets next_label_id = 1). */
static uint64_t find_region_label(const Arm64Relocator* r, uint64_t src_target) {
    for (int i = 0; i < r->region_label_count; i++) {
        if (r->region_labels[i].src_pc == src_target)
            return r->region_labels[i].label_id;
    }
    return 0;
}

Arm64RelocResult arm64_relocator_write_one(Arm64Relocator* r) {
    uint64_t src_pc = r->input_pc + (uint64_t)(r->input_cur - r->input_start - 4);
    uint64_t dst_pc = arm64_writer_pc(r->output);

    /* Track which GPRs this instruction writes (for scratch register selection) */
    track_written_regs(r, r->current_insn, &r->current_info);

    /* Single-instruction trampoline mode:
     * BL/BLR must not leak the relocated/trampoline PC into LR. */
    if (r->preserve_call_return_to_original) {
        switch (r->current_info.type) {
            case ARM64_INSN_BL:
                arm64_writer_put_mov_reg_imm(r->output, ARM64_REG_X30, r->original_call_return_pc);
                arm64_writer_put_branch_address_reg(r->output, r->current_info.target, ARM64_REG_X17);
                return ARM64_RELOC_OK;

            case ARM64_INSN_BLR:
                if (r->current_info.reg == ARM64_REG_X30) {
                    arm64_writer_put_mov_reg_reg(r->output, ARM64_REG_X17, ARM64_REG_X30);
                    arm64_writer_put_mov_reg_imm(r->output, ARM64_REG_X30, r->original_call_return_pc);
                    arm64_writer_put_br_reg(r->output, ARM64_REG_X17);
                } else {
                    arm64_writer_put_mov_reg_imm(r->output, ARM64_REG_X30, r->original_call_return_pc);
                    arm64_writer_put_br_reg(r->output, r->current_info.reg);
                }
                return ARM64_RELOC_OK;

            default:
                break;
        }
    }

    if (!r->current_info.is_pc_relative) {
        /* Non-PC-relative instruction, just copy it */
        arm64_writer_put_insn(r->output, r->current_insn);
        return ARM64_RELOC_OK;
    }

    /* --- Within-region branch fixup (MUST be checked before direct relocation) ---
     *
     * If the branch target falls inside [input_pc, region_end) it is within
     * the bytes that we are relocating into the trampoline.  The caller has
     * pre-created a writer label for every source instruction in this range and
     * placed each label just before writing that instruction.  We must use those
     * labels instead of the original source addresses because:
     *   1. Direct relocation would still point to the original address, which is
     *      now overwritten by the hook jump sequence → wrong bytes, likely SIGSEGV.
     *   2. The absolute-branch fallback also uses the original address → same problem.
     *
     * Branch-type instructions that are within-region are emitted directly using
     * a label reference (the offset within the trampoline is always tiny, so the
     * narrow-range CBZ/TBZ/B.cond forms are always sufficient). */
    if (r->region_end != 0) {
        uint64_t target = r->current_info.target;
        if (target >= r->input_pc && target < r->region_end) {
            uint64_t lbl = find_region_label(r, target);
            if (lbl != 0) {
                switch (r->current_info.type) {
                    case ARM64_INSN_B:
                        arm64_writer_put_b_label(r->output, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_BL:
                        arm64_writer_put_bl_label(r->output, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_B_COND:
                        arm64_writer_put_b_cond_label(r->output, r->current_info.cond, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_CBZ:
                        arm64_writer_put_cbz_reg_label(r->output, r->current_info.reg, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_CBNZ:
                        arm64_writer_put_cbnz_reg_label(r->output, r->current_info.reg, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_TBZ:
                        arm64_writer_put_tbz_reg_imm_label(r->output, r->current_info.reg,
                                                            r->current_info.bit, lbl);
                        return ARM64_RELOC_OK;
                    case ARM64_INSN_TBNZ:
                        arm64_writer_put_tbnz_reg_imm_label(r->output, r->current_info.reg,
                                                             r->current_info.bit, lbl);
                        return ARM64_RELOC_OK;
                    default:
                        /* ADR/ADRP/LDR-literal to within-region: unusual; fall through to
                         * normal relocation (best-effort; data may be overwritten). */
                        break;
                }
            }
        }
    }

    /* --- Page-redirect optimization ---
     *
     * If caller set page_redirect_size and the branch/ADRP target falls inside
     * [page_redirect_orig_base, page_redirect_orig_base + page_redirect_size),
     * the original page has a 1:1 copy at page_redirect_new_base — we can emit
     * a single direct branch/ADRP to that copy instead of a 20-byte MOVZ/BR
     * absolute-jump stub back to the original (now-redirected) code range.
     *
     * Keep fall-through untouched if the writer's put_*_imm fails range
     * (caller may relocate slot elsewhere); the normal path below still runs. */
    if (r->page_redirect_size != 0) {
        uint64_t tgt = r->current_info.target;
        uint64_t orig_end = r->page_redirect_orig_base + r->page_redirect_size;
        if (tgt >= r->page_redirect_orig_base && tgt < orig_end) {
            uint64_t new_tgt = r->page_redirect_new_base +
                               (tgt - r->page_redirect_orig_base);
            switch (r->current_info.type) {
                case ARM64_INSN_B:
                    if (arm64_writer_put_b_imm(r->output, new_tgt) == 0)
                        return ARM64_RELOC_OK;
                    break;
                case ARM64_INSN_BL:
                    if (arm64_writer_put_bl_imm(r->output, new_tgt) == 0)
                        return ARM64_RELOC_OK;
                    break;
                case ARM64_INSN_B_COND:
                    if (arm64_writer_put_b_cond_imm(r->output, r->current_info.cond, new_tgt) == 0)
                        return ARM64_RELOC_OK;
                    break;
                case ARM64_INSN_ADRP:
                    arm64_writer_put_adrp_reg_address(r->output,
                                                       r->current_info.dst_reg, new_tgt);
                    return ARM64_RELOC_OK;
                default:
                    /* CBZ/TBZ/ADR/LDR-literal: fall through to default path below
                     * (direct reloc works when target-dst_pc fits imm19/imm14/imm21).
                     * Since recomp page is adjacent to slot, direct reloc usually
                     * succeeds for these too. */
                    break;
            }
        }
    }

    /* Try direct relocation first */
    uint32_t relocated_insn;
    Arm64RelocResult result = arm64_relocator_relocate_insn(
        src_pc, dst_pc, r->current_insn, &relocated_insn);

    if (result == ARM64_RELOC_OK) {
        arm64_writer_put_insn(r->output, relocated_insn);
        return ARM64_RELOC_OK;
    }

    /* Direct relocation failed, need to generate multi-instruction sequence */
    switch (r->current_info.type) {
        case ARM64_INSN_B:
        case ARM64_INSN_BL: {
            /* Generate: MOVZ/MOVK sequence into X16; BR/BLR X16 */
            if (r->current_info.type == ARM64_INSN_BL) {
                arm64_writer_put_call_address(r->output, r->current_info.target);
            } else {
                arm64_writer_put_branch_address(r->output, r->current_info.target);
            }
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_B_COND: {
            /* Generate: B.!cond skip; MOVZ/MOVK/BR X16; skip: */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);
            Arm64Cond inv_cond = (Arm64Cond)(r->current_info.cond ^ 1); /* Invert condition */
            arm64_writer_put_b_cond_label(r->output, inv_cond, skip_label);
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ: {
            /* Generate: C(N)BZ reg, skip; MOVZ/MOVK/BR X16 (far target); skip: */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);

            /* Invert the condition to fall through to the far-branch sequence */
            if (r->current_info.type == ARM64_INSN_CBZ) {
                arm64_writer_put_cbnz_reg_label(r->output, r->current_info.reg, skip_label);
            } else {
                arm64_writer_put_cbz_reg_label(r->output, r->current_info.reg, skip_label);
            }
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ: {
            /* Similar to CBZ/CBNZ */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);

            if (r->current_info.type == ARM64_INSN_TBZ) {
                arm64_writer_put_tbnz_reg_imm_label(r->output, r->current_info.reg,
                                                     r->current_info.bit, skip_label);
            } else {
                arm64_writer_put_tbz_reg_imm_label(r->output, r->current_info.reg,
                                                    r->current_info.bit, skip_label);
            }
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_ADR: {
            /* Generate: MOVZ/MOVK sequence to load target address */
            arm64_writer_put_mov_reg_imm(r->output, r->current_info.dst_reg,
                                          r->current_info.target);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_ADRP: {
            /* Generate: MOVZ/MOVK sequence to load page address */
            arm64_writer_put_mov_reg_imm(r->output, r->current_info.dst_reg,
                                          r->current_info.target);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_LDR_LITERAL: {
            /* Self-load mode: use dst_reg itself as address intermediate.
             * Avoids clobbering X16 which may be needed by subsequent code.
             * Sequence: LDR Xd, =literal_addr → LDR Xd, [Xd] */
            arm64_writer_put_ldr_reg_address(r->output, r->current_info.dst_reg,
                                              r->current_info.target);
            arm64_writer_put_ldr_reg_reg_offset(r->output, r->current_info.dst_reg,
                                                 r->current_info.dst_reg, 0);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_LDRSW_LITERAL: {
            /* Self-load mode for LDRSW: LDR Xd, =literal_addr → LDRSW Xd, [Xd] */
            arm64_writer_put_ldr_reg_address(r->output, r->current_info.dst_reg,
                                              r->current_info.target);
            arm64_writer_put_ldrsw_reg_reg_offset(r->output, r->current_info.dst_reg,
                                                    r->current_info.dst_reg, 0);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_LDR_LITERAL_FP: {
            /* For FP literal loads, load address into X16, then use LDR [X16] */
            arm64_writer_put_ldr_reg_address(r->output, ARM64_REG_X16,
                                              r->current_info.target);
            /* Use appropriate FP load based on size */
            arm64_writer_put_ldr_fp_reg_reg(r->output,
                                             (uint32_t)r->current_info.dst_reg,
                                             ARM64_REG_X16,
                                             r->current_info.fp_size);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_PRFM_LITERAL: {
            /* Prefetch - can be dropped or converted to NOP for simplicity */
            arm64_writer_put_nop(r->output);
            return ARM64_RELOC_OK;
        }

        default:
            /* Should not reach here, but copy as-is */
            arm64_writer_put_insn(r->output, r->current_insn);
            return ARM64_RELOC_OUT_OF_RANGE;
    }
}

void arm64_relocator_write_all(Arm64Relocator* r) {
    while (!r->eoi) {
        if (arm64_relocator_read_one(r) == 0) break;
        arm64_relocator_write_one(r);
    }
}

void arm64_relocator_skip_one(Arm64Relocator* r) {
    /* Just advance without writing */
    /* The instruction has already been read */
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int arm64_relocator_can_relocate_directly(uint64_t src_pc, uint64_t dst_pc, uint32_t insn) {
    uint32_t out;
    return arm64_relocator_relocate_insn(src_pc, dst_pc, insn, &out) == ARM64_RELOC_OK;
}

size_t arm64_relocator_get_safe_boundary(const void* addr, size_t min_bytes) {
    const uint32_t* code = (const uint32_t*)addr;
    size_t offset = 0;

    while (offset < min_bytes) {
        uint32_t insn = code[offset / 4];
        Arm64InsnInfo info = arm64_relocator_analyze_insn((uint64_t)addr + offset, insn);

        offset += 4;

        /* Check for ADRP + ADD/LDR sequence that shouldn't be split */
        if (info.type == ARM64_INSN_ADRP && offset < min_bytes) {
            /* ADRP is often followed by ADD or LDR that uses the result */
            /* Include the next instruction as well */
            offset += 4;
        }
    }

    return offset;
}
