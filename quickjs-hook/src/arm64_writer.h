/*
 * arm64_writer.h - ARM64 Instruction Writer
 *
 * Provides an API for dynamically generating ARM64 machine code.
 */

#ifndef ARM64_WRITER_H
#define ARM64_WRITER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Enumerations
 * ============================================================================ */

/* ARM64 General Purpose Registers */
typedef enum {
    ARM64_REG_X0 = 0,
    ARM64_REG_X1,
    ARM64_REG_X2,
    ARM64_REG_X3,
    ARM64_REG_X4,
    ARM64_REG_X5,
    ARM64_REG_X6,
    ARM64_REG_X7,
    ARM64_REG_X8,
    ARM64_REG_X9,
    ARM64_REG_X10,
    ARM64_REG_X11,
    ARM64_REG_X12,
    ARM64_REG_X13,
    ARM64_REG_X14,
    ARM64_REG_X15,
    ARM64_REG_X16,
    ARM64_REG_X17,
    ARM64_REG_X18,
    ARM64_REG_X19,
    ARM64_REG_X20,
    ARM64_REG_X21,
    ARM64_REG_X22,
    ARM64_REG_X23,
    ARM64_REG_X24,
    ARM64_REG_X25,
    ARM64_REG_X26,
    ARM64_REG_X27,
    ARM64_REG_X28,
    ARM64_REG_X29,
    ARM64_REG_X30,
    ARM64_REG_SP = 31,      /* Stack Pointer (when used as base) */
    ARM64_REG_XZR = 31,     /* Zero Register (when used as operand) */
    ARM64_REG_LR = 30,      /* Link Register (alias for X30) */
    ARM64_REG_FP = 29,      /* Frame Pointer (alias for X29) */

    /* W registers (32-bit) - offset by 32 for easy identification */
    ARM64_REG_W0 = 32,
    ARM64_REG_W1,
    ARM64_REG_W2,
    ARM64_REG_W3,
    ARM64_REG_W4,
    ARM64_REG_W5,
    ARM64_REG_W6,
    ARM64_REG_W7,
    ARM64_REG_W8,
    ARM64_REG_W9,
    ARM64_REG_W10,
    ARM64_REG_W11,
    ARM64_REG_W12,
    ARM64_REG_W13,
    ARM64_REG_W14,
    ARM64_REG_W15,
    ARM64_REG_W16,
    ARM64_REG_W17,
    ARM64_REG_W18,
    ARM64_REG_W19,
    ARM64_REG_W20,
    ARM64_REG_W21,
    ARM64_REG_W22,
    ARM64_REG_W23,
    ARM64_REG_W24,
    ARM64_REG_W25,
    ARM64_REG_W26,
    ARM64_REG_W27,
    ARM64_REG_W28,
    ARM64_REG_W29,
    ARM64_REG_W30,
    ARM64_REG_WSP = 63,     /* 32-bit Stack Pointer */
    ARM64_REG_WZR = 63,     /* 32-bit Zero Register */

    ARM64_REG_NONE = -1
} Arm64Reg;

/* ARM64 Condition Codes */
typedef enum {
    ARM64_COND_EQ = 0,      /* Equal (Z == 1) */
    ARM64_COND_NE = 1,      /* Not equal (Z == 0) */
    ARM64_COND_CS = 2,      /* Carry set / Unsigned higher or same (C == 1) */
    ARM64_COND_HS = 2,      /* Alias for CS */
    ARM64_COND_CC = 3,      /* Carry clear / Unsigned lower (C == 0) */
    ARM64_COND_LO = 3,      /* Alias for CC */
    ARM64_COND_MI = 4,      /* Minus / Negative (N == 1) */
    ARM64_COND_PL = 5,      /* Plus / Positive or zero (N == 0) */
    ARM64_COND_VS = 6,      /* Overflow (V == 1) */
    ARM64_COND_VC = 7,      /* No overflow (V == 0) */
    ARM64_COND_HI = 8,      /* Unsigned higher (C == 1 && Z == 0) */
    ARM64_COND_LS = 9,      /* Unsigned lower or same (C == 0 || Z == 1) */
    ARM64_COND_GE = 10,     /* Signed greater or equal (N == V) */
    ARM64_COND_LT = 11,     /* Signed less than (N != V) */
    ARM64_COND_GT = 12,     /* Signed greater than (Z == 0 && N == V) */
    ARM64_COND_LE = 13,     /* Signed less or equal (Z == 1 || N != V) */
    ARM64_COND_AL = 14,     /* Always */
    ARM64_COND_NV = 15      /* Never (reserved, behaves like AL) */
} Arm64Cond;

/* Index modes for load/store */
typedef enum {
    ARM64_INDEX_POST_ADJUST,    /* [base], #offset - post-indexed */
    ARM64_INDEX_SIGNED_OFFSET,  /* [base, #offset] - signed offset */
    ARM64_INDEX_PRE_ADJUST      /* [base, #offset]! - pre-indexed */
} Arm64IndexMode;

/* Label reference types */
typedef enum {
    ARM64_LABEL_REF_B,          /* B <label> - 26-bit imm */
    ARM64_LABEL_REF_BL,         /* BL <label> - 26-bit imm */
    ARM64_LABEL_REF_B_COND,     /* B.cond <label> - 19-bit imm */
    ARM64_LABEL_REF_CBZ,        /* CBZ Rt, <label> - 19-bit imm */
    ARM64_LABEL_REF_CBNZ,       /* CBNZ Rt, <label> - 19-bit imm */
    ARM64_LABEL_REF_TBZ,        /* TBZ Rt, #bit, <label> - 14-bit imm */
    ARM64_LABEL_REF_TBNZ,       /* TBNZ Rt, #bit, <label> - 14-bit imm */
    ARM64_LABEL_REF_ADR         /* ADR Xd, <label> - 21-bit imm */
} Arm64LabelRefType;

/* ============================================================================
 * Structures
 * ============================================================================ */

/* Label definition */
typedef struct Arm64Label {
    uint64_t id;                /* Unique label identifier */
    uint64_t address;           /* Address where label is defined */
    struct Arm64Label* next;    /* Next label in list */
} Arm64Label;

/* Pending label reference */
typedef struct Arm64LabelRef {
    uint64_t label_id;          /* ID of referenced label */
    uint8_t* insn_addr;         /* Address of instruction to patch */
    Arm64LabelRefType type;     /* Type of reference */
    struct Arm64LabelRef* next; /* Next reference in list */
} Arm64LabelRef;

/* ARM64 Code Writer */
typedef struct {
    uint8_t* base;              /* Buffer start address */
    uint8_t* code;              /* Current write position */
    uint64_t pc;                /* Current PC value */
    size_t size;                /* Buffer capacity */

    Arm64Label* labels;         /* Defined labels */
    Arm64LabelRef* label_refs;  /* Pending label references */

    uint64_t next_label_id;     /* Next auto-generated label ID */
} Arm64Writer;

/* ============================================================================
 * Initialization / Cleanup
 * ============================================================================ */

/*
 * Initialize an ARM64 writer
 *
 * @param w         Writer instance to initialize
 * @param code      Buffer to write code into
 * @param pc        PC value at start of buffer
 * @param size      Buffer capacity in bytes
 */
void arm64_writer_init(Arm64Writer* w, void* code, uint64_t pc, size_t size);

/*
 * Reset writer to a new location
 *
 * @param w         Writer instance
 * @param code      New buffer address
 * @param pc        New PC value
 */
void arm64_writer_reset(Arm64Writer* w, void* code, uint64_t pc);

/*
 * Free internal resources (labels)
 *
 * @param w         Writer instance
 */
void arm64_writer_clear(Arm64Writer* w);

/*
 * Resolve all pending label references
 *
 * @param w         Writer instance
 * @return          0 on success, -1 if any label unresolved or out of range
 */
int arm64_writer_flush(Arm64Writer* w);

/* ============================================================================
 * State Queries
 * ============================================================================ */

/* Get current PC value */
static inline uint64_t arm64_writer_pc(Arm64Writer* w) {
    return w->pc;
}

/* Get current offset from base */
static inline size_t arm64_writer_offset(Arm64Writer* w) {
    return (size_t)(w->code - w->base);
}

/* Get current write cursor */
static inline uint8_t* arm64_writer_cursor(Arm64Writer* w) {
    return w->code;
}

/* Check if buffer has space for more bytes */
static inline int arm64_writer_can_write(Arm64Writer* w, size_t bytes) {
    return arm64_writer_offset(w) + bytes <= w->size;
}

/* ============================================================================
 * Label Support
 * ============================================================================ */

/*
 * Define a label at current position
 *
 * @param w         Writer instance
 * @param id        Label identifier
 */
void arm64_writer_put_label(Arm64Writer* w, uint64_t id);

/*
 * Allocate a new unique label ID
 *
 * @param w         Writer instance
 * @return          New unique label ID
 */
uint64_t arm64_writer_new_label_id(Arm64Writer* w);

/*
 * Check if direct branch is possible between two addresses
 *
 * @param from      Source address
 * @param to        Target address
 * @return          1 if direct branch possible, 0 otherwise
 */
int arm64_writer_can_branch_directly_between(uint64_t from, uint64_t to);

/* ============================================================================
 * Raw Writing
 * ============================================================================ */

/*
 * Write a raw 32-bit instruction
 *
 * @param w         Writer instance
 * @param insn      Instruction word
 */
void arm64_writer_put_insn(Arm64Writer* w, uint32_t insn);

/*
 * Write raw bytes
 *
 * @param w         Writer instance
 * @param data      Data to write
 * @param len       Number of bytes
 */
void arm64_writer_put_bytes(Arm64Writer* w, const uint8_t* data, size_t len);

/* ============================================================================
 * Branch Instructions
 * ============================================================================ */

/* B <target> - Unconditional branch (±128MB range) */
int arm64_writer_put_b_imm(Arm64Writer* w, uint64_t target);

/* BL <target> - Branch with link (±128MB range) */
int arm64_writer_put_bl_imm(Arm64Writer* w, uint64_t target);

/* B <label> - Branch to label */
void arm64_writer_put_b_label(Arm64Writer* w, uint64_t label_id);

/* BL <label> - Branch with link to label */
void arm64_writer_put_bl_label(Arm64Writer* w, uint64_t label_id);

/* B.cond <label> - Conditional branch (±1MB range) */
void arm64_writer_put_b_cond_label(Arm64Writer* w, Arm64Cond cond, uint64_t label_id);

/* B.cond <target> - Conditional branch to immediate */
int arm64_writer_put_b_cond_imm(Arm64Writer* w, Arm64Cond cond, uint64_t target);

/* CBZ Rt, <label> - Compare and branch if zero */
void arm64_writer_put_cbz_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id);

/* CBNZ Rt, <label> - Compare and branch if not zero */
void arm64_writer_put_cbnz_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id);

/* TBZ Rt, #bit, <label> - Test bit and branch if zero */
void arm64_writer_put_tbz_reg_imm_label(Arm64Writer* w, Arm64Reg reg, uint32_t bit, uint64_t label_id);

/* TBNZ Rt, #bit, <label> - Test bit and branch if not zero */
void arm64_writer_put_tbnz_reg_imm_label(Arm64Writer* w, Arm64Reg reg, uint32_t bit, uint64_t label_id);

/* ============================================================================
 * Register Branch Instructions
 * ============================================================================ */

/* BR Xn - Branch to register */
void arm64_writer_put_br_reg(Arm64Writer* w, Arm64Reg reg);

/* BLR Xn - Branch with link to register */
void arm64_writer_put_blr_reg(Arm64Writer* w, Arm64Reg reg);

/* RET - Return (branch to LR) */
void arm64_writer_put_ret(Arm64Writer* w);

/* RET Xn - Return to specific register */
void arm64_writer_put_ret_reg(Arm64Writer* w, Arm64Reg reg);

/* ============================================================================
 * Load Instructions
 * ============================================================================ */

/* LDR Xt, =value - Load 64-bit immediate using literal pool */
void arm64_writer_put_ldr_reg_u64(Arm64Writer* w, Arm64Reg reg, uint64_t val);

/* LDR Xt, =addr - Load address (same as ldr_reg_u64 but semantic) */
void arm64_writer_put_ldr_reg_address(Arm64Writer* w, Arm64Reg reg, uint64_t addr);

/* LDR Xt, [Xn, #offset] - Load with signed offset */
void arm64_writer_put_ldr_reg_reg_offset(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, int64_t offset);

/* LDRSW Xt, [Xn, #offset] - Load signed word */
void arm64_writer_put_ldrsw_reg_reg_offset(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, int64_t offset);

/* LDP Xt1, Xt2, [Xn, #offset] - Load pair */
void arm64_writer_put_ldp_reg_reg_reg_offset(Arm64Writer* w, Arm64Reg a, Arm64Reg b,
                                              Arm64Reg base, int64_t offset,
                                              Arm64IndexMode mode);

/* LDR St/Dt/Qt, [Xn] - Load FP/SIMD register from base (offset 0) */
void arm64_writer_put_ldr_fp_reg_reg(Arm64Writer* w, uint32_t fp_reg, Arm64Reg base, uint32_t size);

/* ============================================================================
 * Store Instructions
 * ============================================================================ */

/* STR Xt, [Xn, #offset] - Store with signed offset */
void arm64_writer_put_str_reg_reg_offset(Arm64Writer* w, Arm64Reg src, Arm64Reg dst, int64_t offset);

/* STP Xt1, Xt2, [Xn, #offset] - Store pair */
void arm64_writer_put_stp_reg_reg_reg_offset(Arm64Writer* w, Arm64Reg a, Arm64Reg b,
                                              Arm64Reg base, int64_t offset,
                                              Arm64IndexMode mode);

/* ============================================================================
 * Arithmetic Instructions
 * ============================================================================ */

/* ADD Xd, Xn, #imm */
void arm64_writer_put_add_reg_reg_imm(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, uint64_t imm);

/* ADD Xd, Xn, Xm */
void arm64_writer_put_add_reg_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg left, Arm64Reg right);

/* SUB Xd, Xn, #imm */
void arm64_writer_put_sub_reg_reg_imm(Arm64Writer* w, Arm64Reg dst, Arm64Reg src, uint64_t imm);

/* SUB Xd, Xn, Xm */
void arm64_writer_put_sub_reg_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg left, Arm64Reg right);

/* ============================================================================
 * Data Movement Instructions
 * ============================================================================ */

/* MOV Xd, Xn - Register to register */
void arm64_writer_put_mov_reg_reg(Arm64Writer* w, Arm64Reg dst, Arm64Reg src);

/* MOV Xd, #imm - Load immediate (auto-selects MOVZ/MOVK sequence) */
void arm64_writer_put_mov_reg_imm(Arm64Writer* w, Arm64Reg reg, uint64_t imm);

/* MOVZ Xd, #imm, LSL #shift - Move wide with zero */
void arm64_writer_put_movz_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift);

/* MOVK Xd, #imm, LSL #shift - Move wide with keep */
void arm64_writer_put_movk_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift);

/* MOVN Xd, #imm, LSL #shift - Move wide with NOT */
void arm64_writer_put_movn_reg_imm(Arm64Writer* w, Arm64Reg reg, uint16_t imm, uint32_t shift);

/* ============================================================================
 * Address Generation Instructions
 * ============================================================================ */

/* ADR Xd, <label> - PC-relative address (±1MB range) */
void arm64_writer_put_adr_reg_label(Arm64Writer* w, Arm64Reg reg, uint64_t label_id);

/* ADRP Xd, <page> - PC-relative page address */
void arm64_writer_put_adrp_reg_address(Arm64Writer* w, Arm64Reg reg, uint64_t addr);

/* ============================================================================
 * Miscellaneous Instructions
 * ============================================================================ */

/* NOP */
void arm64_writer_put_nop(Arm64Writer* w);

/* BRK #imm - Breakpoint */
void arm64_writer_put_brk_imm(Arm64Writer* w, uint16_t imm);

/* SVC #imm - Supervisor call */
void arm64_writer_put_svc_imm(Arm64Writer* w, uint16_t imm);

/* MRS Xt, <sysreg> - Move system register to general register */
void arm64_writer_put_mrs_reg(Arm64Writer* w, Arm64Reg reg, uint32_t sysreg);

/* MSR <sysreg>, Xt - Move general register to system register */
void arm64_writer_put_msr_reg(Arm64Writer* w, uint32_t sysreg, Arm64Reg reg);

/* ============================================================================
 * Convenience Functions for Hooking
 * ============================================================================ */

/* Push register pair (STP with pre-decrement SP) */
void arm64_writer_put_push_reg_reg(Arm64Writer* w, Arm64Reg a, Arm64Reg b);

/* Pop register pair (LDP with post-increment SP) */
void arm64_writer_put_pop_reg_reg(Arm64Writer* w, Arm64Reg a, Arm64Reg b);

/* Save all general-purpose registers (x0-x30 + sp) */
void arm64_writer_put_push_all_regs(Arm64Writer* w);

/* Restore all general-purpose registers */
void arm64_writer_put_pop_all_regs(Arm64Writer* w);

/* Generate absolute jump using MOVZ/MOVK sequence + BR X16 (up to 20 bytes) */
void arm64_writer_put_branch_address(Arm64Writer* w, uint64_t target);

/* Generate absolute call using MOVZ/MOVK sequence + BLR X16 (up to 20 bytes) */
void arm64_writer_put_call_address(Arm64Writer* w, uint64_t target);

/* Generate absolute jump using MOVZ/MOVK sequence + BR with specified scratch register */
void arm64_writer_put_branch_address_reg(Arm64Writer* w, uint64_t target, Arm64Reg scratch);

/* Generate absolute call using MOVZ/MOVK sequence + BLR with specified scratch register */
void arm64_writer_put_call_address_reg(Arm64Writer* w, uint64_t target, Arm64Reg scratch);

/* ADRP+ADD+BR: 12-byte PC-relative jump (pure ALU, wxshadow safe, ±4GB range) */
void arm64_writer_put_adrp_add_br(Arm64Writer* w, Arm64Reg scratch, uint64_t target);

/* ============================================================================
 * FP/SIMD Pair Instructions
 * ============================================================================ */

/* STP Dt1, Dt2, [Xn, #offset] - Store FP pair (signed offset) */
void arm64_writer_put_fp_stp_offset(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                     Arm64Reg base, int32_t offset);

/* STP Dt1, Dt2, [Xn, #offset]! - Store FP pair (pre-index) */
void arm64_writer_put_fp_stp_pre(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                  Arm64Reg base, int32_t offset);

/* LDP Dt1, Dt2, [Xn, #offset] - Load FP pair (signed offset) */
void arm64_writer_put_fp_ldp_offset(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                     Arm64Reg base, int32_t offset);

/* LDP Dt1, Dt2, [Xn], #offset - Load FP pair (post-index) */
void arm64_writer_put_fp_ldp_post(Arm64Writer* w, uint32_t dt1, uint32_t dt2,
                                   Arm64Reg base, int32_t offset);

/* ============================================================================
 * Comparison Instructions
 * ============================================================================ */

/* CMP Xn, Xm - Compare registers (alias for SUBS XZR, Xn, Xm) */
void arm64_writer_put_cmp_reg_reg(Arm64Writer* w, Arm64Reg rn, Arm64Reg rm);

/* ============================================================================
 * Helper Macros
 * ============================================================================ */

/* Check if register is a 64-bit X register */
#define ARM64_REG_IS_X(r) ((r) >= ARM64_REG_X0 && (r) <= ARM64_REG_SP)

/* Check if register is a 32-bit W register */
#define ARM64_REG_IS_W(r) ((r) >= ARM64_REG_W0 && (r) <= ARM64_REG_WSP)

/* Get register number (0-31) from Arm64Reg */
#define ARM64_REG_NUM(r) ((r) & 0x1F)

/* Get sf bit (size flag): 1 for 64-bit, 0 for 32-bit */
#define ARM64_REG_SF(r) (ARM64_REG_IS_X(r) ? 1 : 0)

#ifdef __cplusplus
}
#endif

#endif /* ARM64_WRITER_H */
