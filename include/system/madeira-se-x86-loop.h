/*
 * Madeira-SE x86 memory-loop decoder.
 *
 * Copyright (C) 2026 The Madeira contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef SYSTEM_MADEIRA_SE_X86_LOOP_H
#define SYSTEM_MADEIRA_SE_X86_LOOP_H

/*
 * Compilers lower memcpy()/memset() and bitmap blits into a handful of
 * straight-line "load, store, advance pointers, loop" shapes.  Under TCTI
 * every one of those iterations costs a full gadget queue, so the Madeira-SE
 * loop guard recognises the shapes at run time and replays the bulk of the
 * iterations as a host memcpy()/fill instead.
 *
 * This header is intentionally free of QEMU dependencies: the host-side unit
 * tests compile the matching source file directly.
 */

#include <stdbool.h>
#include <stdint.h>

/* Longest idiom the decoder will match, in bytes. */
#define MADEIRA_SE_X86_LOOP_MAX_BYTES 24

typedef enum MadeiraSeX86LoopKind {
    /* Copies [src] -> [dst] element by element. */
    MADEIRA_SE_X86_LOOP_KIND_COPY = 0,
    /* Writes one repeating element to [dst]. */
    MADEIRA_SE_X86_LOOP_KIND_FILL,
} MadeiraSeX86LoopKind;

typedef enum MadeiraSeX86LoopValue {
    /* Copies take their value from the source pointer. */
    MADEIRA_SE_X86_LOOP_VALUE_NONE = 0,
    MADEIRA_SE_X86_LOOP_VALUE_GPR,
    MADEIRA_SE_X86_LOOP_VALUE_MMX,
    MADEIRA_SE_X86_LOOP_VALUE_XMM,
    MADEIRA_SE_X86_LOOP_VALUE_IMM32,
} MadeiraSeX86LoopValue;

/* x86 general purpose register numbers, as used by CPUX86State.regs[]. */
enum {
    MADEIRA_SE_X86_REG_EAX = 0,
    MADEIRA_SE_X86_REG_ECX = 1,
    MADEIRA_SE_X86_REG_EDX = 2,
    MADEIRA_SE_X86_REG_EBX = 3,
    MADEIRA_SE_X86_REG_ESP = 4,
    MADEIRA_SE_X86_REG_EBP = 5,
    MADEIRA_SE_X86_REG_ESI = 6,
    MADEIRA_SE_X86_REG_EDI = 7,
};

typedef struct MadeiraSeX86LoopPattern {
    /* Bytes consumed from the loop head, including the terminating branch. */
    uint8_t length;
    /* Guest instructions per iteration; used for icount accounting. */
    uint8_t insns;
    /* Bytes moved per iteration. */
    uint8_t elem_size;
    uint8_t kind;       /* MadeiraSeX86LoopKind */
    uint8_t src_reg;    /* pointer register of the load (copy only) */
    uint8_t dst_reg;    /* pointer register of the store */
    uint8_t count_reg;  /* loop counter register */
    uint8_t value_kind; /* MadeiraSeX86LoopValue (fill only) */
    uint8_t value_reg;  /* register holding the fill element (fill only) */
    uint8_t reserved;
    uint32_t value_imm; /* immediate fill element, for VALUE_IMM32 */
} MadeiraSeX86LoopPattern;

/*
 * Decode the guest instructions at @code (a loop head) as a memory idiom.
 *
 * @length is the number of readable bytes at @code; the decoder never reads
 * past it, and fails when the pattern would be cut short.  @code64 selects
 * the long-mode decodings.
 *
 * Returns true and fills @pattern when the bytes are exactly a copy/fill loop
 * whose backward branch targets the loop head.  Anything else - a conditional
 * inside the body, an unsupported addressing mode, a tail that is not
 * self-targeting - is rejected, which is always safe: the caller then leaves
 * the block to the interpreter.
 */
bool madeira_se_x86_loop_decode(const uint8_t *code, unsigned length,
                                bool code64,
                                MadeiraSeX86LoopPattern *pattern);

#endif /* SYSTEM_MADEIRA_SE_X86_LOOP_H */
