/*
 * native_call.S - ARM64 AAPCS64 variadic native function call shim
 *
 * Loads up to 8 integer args into x0-x7 and up to 8 float args into d0-d7,
 * plus an arbitrary number of overflow args into stack slots, then branches
 * to the target. The target function reads whatever registers/stack slots
 * it needs by its declared signature.
 *
 * Signature (from Rust/C):
 *   uint64_t native_call_shim(
 *       void *fn,                   // x0: target function pointer
 *       const uint64_t *gpr,        // x1: length-8 array for x0-x7
 *       const double   *fpr,        // x2: length-8 array for d0-d7
 *       const uint64_t *stk,        // x3: overflow stack args (u64 slots)
 *       size_t          stk_count   // x4: number of overflow args
 *   );
 *
 * Three Rust extern declarations point to this same symbol:
 *   -> u64 reads x0 (integer/pointer return)
 *   -> f64 reads d0 (double return)
 *   -> f32 reads s0 (float return)
 *
 * Stack layout for overflow args (AAPCS64 §6.8.2 C.14):
 *   - Each overflow arg is padded to 8 bytes regardless of type
 *   - float: low 4 bytes = f32 bits, high 4 bytes = 0
 *   - double/int/pointer: full 8 bytes
 *   - Caller (this shim) allocates, copies, and deallocates the stack area
 */

.text
.global native_call_shim
.type native_call_shim, @function
.align 4
native_call_shim:
    /* Prologue: save FP/LR.
     * After this, x29 (FP) points to [saved_x29, saved_x30] on the stack.
     * We use x29 to restore sp after the call (callee preserves x29). */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    /* Stash fn pointer in x8 (IP0, intra-procedure scratch) */
    mov     x8, x0

    /* ── Load FPRs into d0-d7 from fpr array (x2) ── */
    ldp     d0, d1, [x2, #0]
    ldp     d2, d3, [x2, #16]
    ldp     d4, d5, [x2, #32]
    ldp     d6, d7, [x2, #48]

    /* ── Handle stack spill from x3 (stk), x4 (stk_count) ── */
    cbz     x4, 2f                  /* if no overflow args, skip spill */

    /* Allocate stack space: round up (stk_count * 8) to 16-byte alignment */
    lsl     x9, x4, #3              /* x9 = stk_count * 8 */
    add     x9, x9, #15
    and     x9, x9, #~15            /* x9 = aligned bytes */
    sub     sp, sp, x9              /* allocate */

    /* Copy stk[0..stk_count] to [sp, sp+8, ..., sp+(stk_count-1)*8] */
    mov     x10, #0                 /* index i */
1:
    ldr     x11, [x3, x10, lsl #3]  /* x11 = stk[i] */
    str     x11, [sp, x10, lsl #3]  /* [sp + i*8] = x11 */
    add     x10, x10, #1
    cmp     x10, x4
    b.lt    1b

2:
    /* ── Load GPRs into x0-x7 LAST (we're about to overwrite x1) ── */
    ldp     x6, x7, [x1, #48]
    ldp     x4, x5, [x1, #32]
    ldp     x2, x3, [x1, #16]
    ldp     x0, x1, [x1, #0]

    /* Call target. Return value (int in x0, float in d0/s0) stays intact. */
    blr     x8

    /* Epilogue: restore sp from x29 (undoes any stack spill), then pop FP/LR.
     * AAPCS64 guarantees x29 is callee-saved, so it's still our frame ptr. */
    mov     sp, x29
    ldp     x29, x30, [sp], #16
    ret
.size native_call_shim, .-native_call_shim

/* GNU-stack note: mark stack non-executable (prevents W^X warnings). */
#if defined(__linux__) || defined(__ANDROID__)
.section .note.GNU-stack,"",%progbits
#endif
