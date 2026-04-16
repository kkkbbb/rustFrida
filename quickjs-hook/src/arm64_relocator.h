/*
 * arm64_relocator.h - ARM64 Instruction Relocator
 *
 * Provides an API for relocating ARM64 instructions from one address to another,
 * handling PC-relative instructions that need adjustment.
 */

#ifndef ARM64_RELOCATOR_H
#define ARM64_RELOCATOR_H

#include <stdint.h>
#include <stddef.h>
#include "arm64_writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Enumerations
 * ============================================================================ */

/* Instruction classification */
typedef enum {
    ARM64_INSN_UNKNOWN = 0,

    /* Branch instructions */
    ARM64_INSN_B,               /* B <target> */
    ARM64_INSN_BL,              /* BL <target> */
    ARM64_INSN_B_COND,          /* B.cond <target> */
    ARM64_INSN_CBZ,             /* CBZ Rt, <target> */
    ARM64_INSN_CBNZ,            /* CBNZ Rt, <target> */
    ARM64_INSN_TBZ,             /* TBZ Rt, #bit, <target> */
    ARM64_INSN_TBNZ,            /* TBNZ Rt, #bit, <target> */
    ARM64_INSN_BR,              /* BR Xn */
    ARM64_INSN_BLR,             /* BLR Xn */
    ARM64_INSN_RET,             /* RET [Xn] */

    /* Address computation */
    ARM64_INSN_ADR,             /* ADR Xd, <label> */
    ARM64_INSN_ADRP,            /* ADRP Xd, <page> */

    /* PC-relative loads */
    ARM64_INSN_LDR_LITERAL,     /* LDR Xt, <label> (GPR) */
    ARM64_INSN_LDRSW_LITERAL,   /* LDRSW Xt, <label> */
    ARM64_INSN_LDR_LITERAL_FP,  /* LDR St/Dt/Qt, <label> (FP/SIMD) */
    ARM64_INSN_PRFM_LITERAL,    /* PRFM <prfop>, <label> */

    /* Other instructions (not PC-relative) */
    ARM64_INSN_OTHER
} Arm64InsnType;

/* Relocation result */
typedef enum {
    ARM64_RELOC_OK,             /* Successfully relocated */
    ARM64_RELOC_OUT_OF_RANGE,   /* Target out of range, cannot relocate directly */
    ARM64_RELOC_ERROR           /* Error during relocation */
} Arm64RelocResult;

/* ============================================================================
 * Structures
 * ============================================================================ */

/* Information about an analyzed instruction */
typedef struct {
    Arm64InsnType type;         /* Instruction classification */
    uint64_t target;            /* Branch/load target address (if applicable) */
    int is_pc_relative;         /* Non-zero if instruction uses PC-relative addressing */

    /* For branch instructions */
    Arm64Cond cond;             /* Condition code (for B.cond) */
    Arm64Reg reg;               /* Register operand (for CBZ/CBNZ/TBZ/TBNZ/BR/BLR/RET) */
    uint32_t bit;               /* Bit number (for TBZ/TBNZ) */

    /* For load literal */
    Arm64Reg dst_reg;           /* Destination register */
    int is_signed;              /* Non-zero for LDRSW */
    int fp_size;                /* Size for FP literal: 4, 8, or 16 bytes */
} Arm64InsnInfo;

/* Region label entry: maps one source instruction address to a writer label.
 * Used to fix up within-region branches so they target the relocated copy in
 * the trampoline rather than the original (now-overwritten) address.
 *
 * 64 entries × 16 bytes = 1KB stack footprint per Arm64Relocator; covers
 * 256-byte patches which is plenty for any sane writest use case. */
#define ARM64_RELOC_MAX_REGION 64
typedef struct {
    uint64_t src_pc;    /* original source address of the instruction */
    uint64_t label_id;  /* writer label ID placed at its destination */
} Arm64RegionLabel;

/* ARM64 Relocator state */
typedef struct {
    const uint8_t* input_start;  /* Start of input buffer */
    const uint8_t* input_cur;    /* Current read position */
    uint64_t input_pc;           /* PC at start of input */

    Arm64Writer* output;         /* Output writer */

    /* Current instruction state */
    uint32_t current_insn;       /* Raw instruction word */
    Arm64InsnInfo current_info;  /* Analyzed instruction info */

    int eoi;                     /* End-of-input flag */
    int eob;                     /* End-of-block flag (unconditional branch encountered) */

    /* Within-region branch fixup: maps each source instruction to a writer
     * label placed at its relocated destination.  Populated by the caller
     * (hook_relocate_instructions) before the write loop so that forward
     * references can be resolved even before the target instruction is written. */
    Arm64RegionLabel region_labels[ARM64_RELOC_MAX_REGION];
    int region_label_count;  /* number of valid entries */
    uint64_t region_end;     /* one-past-last byte of the hook region (src) */

    /* Bitmask of GPRs written by relocated instructions (bit N = XN written).
     * Used to dynamically select a scratch register for the jump-back sequence
     * that won't clobber a value set by the relocated code. */
    uint32_t written_regs;

    /* Single-instruction trampoline mode:
     * relocate exactly one overwritten instruction, and if it is BL/BLR to an
     * external target, preserve the original return PC instead of returning to
     * the relocated copy. This is required by stealth2 recomp trampolines so
     * LR/quick-frame metadata stays in the original code range. */
    int preserve_call_return_to_original;
    uint64_t original_call_return_pc;

    /* Page-redirect optimization (stealth2 writest / trampoline):
     * If the current branch/ADRP target falls inside
     *   [page_redirect_orig_base, page_redirect_orig_base + page_redirect_size)
     * emit the instruction targeting
     *   page_redirect_new_base + (target - page_redirect_orig_base)
     * instead of an absolute MOVZ/BR back to the original code range.
     * This collapses 20-byte stubs into a single 4-byte direct branch when the
     * recomp copy of the original page is within ±128MB of the output. */
    uint64_t page_redirect_orig_base;
    uint64_t page_redirect_new_base;
    size_t   page_redirect_size;
} Arm64Relocator;

/* ============================================================================
 * Initialization / Cleanup
 * ============================================================================ */

/*
 * Initialize an ARM64 relocator
 *
 * @param r         Relocator instance to initialize
 * @param input     Input buffer (original code)
 * @param input_pc  PC value at start of input
 * @param output    Writer for relocated code
 */
void arm64_relocator_init(Arm64Relocator* r, const void* input, uint64_t input_pc, Arm64Writer* output);

/*
 * Reset relocator to new input
 *
 * @param r         Relocator instance
 * @param input     New input buffer
 * @param input_pc  New PC value
 */
void arm64_relocator_reset(Arm64Relocator* r, const void* input, uint64_t input_pc);

/*
 * Clear relocator state (no dynamic memory to free currently)
 *
 * @param r         Relocator instance
 */
void arm64_relocator_clear(Arm64Relocator* r);

/* ============================================================================
 * Reading Instructions
 * ============================================================================ */

/*
 * Read and analyze the next instruction
 *
 * @param r         Relocator instance
 * @return          Number of bytes read (4) or 0 if no more instructions
 */
int arm64_relocator_read_one(Arm64Relocator* r);

/*
 * Check if end of input reached
 *
 * @param r         Relocator instance
 * @return          Non-zero if at end of input
 */
static inline int arm64_relocator_eoi(Arm64Relocator* r) {
    return r->eoi;
}

/*
 * Check if end of block reached (unconditional branch)
 *
 * @param r         Relocator instance
 * @return          Non-zero if end of block
 */
static inline int arm64_relocator_eob(Arm64Relocator* r) {
    return r->eob;
}

/*
 * Get current input PC
 *
 * @param r         Relocator instance
 * @return          PC at current read position
 */
static inline uint64_t arm64_relocator_input_pc(Arm64Relocator* r) {
    return r->input_pc + (uint64_t)(r->input_cur - r->input_start);
}

/* ============================================================================
 * Writing Instructions
 * ============================================================================ */

/*
 * Relocate and write the current instruction
 *
 * @param r         Relocator instance
 * @return          ARM64_RELOC_OK on success, error code otherwise
 */
Arm64RelocResult arm64_relocator_write_one(Arm64Relocator* r);

/*
 * Relocate and write all remaining instructions
 *
 * @param r         Relocator instance
 */
void arm64_relocator_write_all(Arm64Relocator* r);

/*
 * Skip the current instruction without writing
 *
 * @param r         Relocator instance
 */
void arm64_relocator_skip_one(Arm64Relocator* r);

/* ============================================================================
 * Analysis Functions
 * ============================================================================ */

/*
 * Analyze a single instruction
 *
 * @param pc        PC value at instruction
 * @param insn      Raw instruction word
 * @return          Instruction information
 */
Arm64InsnInfo arm64_relocator_analyze_insn(uint64_t pc, uint32_t insn);

/*
 * Try to relocate an instruction directly (adjusting offset)
 *
 * @param src_pc    Original PC
 * @param dst_pc    New PC
 * @param insn      Original instruction
 * @param out       Output for relocated instruction
 * @return          ARM64_RELOC_OK if successful
 */
Arm64RelocResult arm64_relocator_relocate_insn(uint64_t src_pc, uint64_t dst_pc,
                                                uint32_t insn, uint32_t* out);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/*
 * Check if an instruction can be relocated directly between two addresses
 *
 * @param src_pc    Source PC
 * @param dst_pc    Destination PC
 * @param insn      Instruction to check
 * @return          Non-zero if can be relocated directly
 */
int arm64_relocator_can_relocate_directly(uint64_t src_pc, uint64_t dst_pc, uint32_t insn);

/*
 * Get the minimum number of bytes needed for hooking at an address
 * (accounts for multi-instruction sequences that shouldn't be split)
 *
 * @param addr      Start address
 * @param min_bytes Minimum bytes needed for the hook
 * @return          Actual bytes needed (may be larger)
 */
size_t arm64_relocator_get_safe_boundary(const void* addr, size_t min_bytes);

#ifdef __cplusplus
}
#endif

#endif /* ARM64_RELOCATOR_H */
