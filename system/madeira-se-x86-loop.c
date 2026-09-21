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

#include "system/madeira-se-x86-loop.h"

#include <stddef.h>

/*
 * Everything the decoder learns about one candidate loop.  The body may only
 * contain the memory operations, pointer advances and the terminating branch;
 * anything else makes the pattern unusable, because replaying iterations
 * natively would then have to reproduce effects that are not a plain copy.
 */
typedef struct MadeiraSeX86LoopScan {
    bool have_load;
    bool have_store;
    bool load_mem;      /* load operand was [reg] (copy patterns) */
    bool store_mem;     /* store operand was [reg] */
    bool store_is_imm;  /* store operand was an immediate */
    uint8_t load_reg;   /* value register of the load */
    uint8_t load_kind;  /* MadeiraSeX86LoopValue */
    uint8_t load_size;
    uint8_t load_base;  /* pointer register of the load */
    uint8_t store_reg;  /* value register of the store */
    uint8_t store_kind; /* MadeiraSeX86LoopValue */
    uint8_t store_size;
    uint8_t store_base; /* pointer register of the store */
    uint32_t store_imm; /* immediate value of an immediate store */
    int32_t advance[8]; /* pointer advance per guest register */
    unsigned insns;
} MadeiraSeX86LoopScan;

typedef struct MadeiraSeX86LoopTail {
    bool found;
    uint8_t count_reg;
    unsigned length;
} MadeiraSeX86LoopTail;

/* True for a mod=00 memory operand with a plain base register: [reg]. */
static bool madeira_se_x86_base_operand(uint8_t modrm, uint8_t *base,
                                        uint8_t *reg)
{
    uint8_t rm = modrm & 0x07;

    /* mod=00 -> no displacement; SIB and disp32/RIP-relative are rejected. */
    if ((modrm & 0xc0) != 0x00 || rm == 4 || rm == 5) {
        return false;
    }
    *base = rm;
    *reg = (uint8_t)((modrm >> 3) & 0x07);
    return true;
}

/* True for a mod=11 register operand; @reg receives the r/m register. */
static bool madeira_se_x86_reg_operand(uint8_t modrm, uint8_t *reg,
                                      uint8_t *opcode_ext)
{
    if ((modrm & 0xc0) != 0xc0) {
        return false;
    }
    *reg = modrm & 0x07;
    *opcode_ext = (uint8_t)((modrm >> 3) & 0x07);
    return true;
}

/*
 * Decode a "dec/jnz" or "sub/jnz" style loop tail, which compilers emit when
 * they do not want the (slow) loop instruction.  @pos points just past the
 * first opcode byte; @opcode and @modrm/ext are already parsed by the caller.
 */
static bool madeira_se_x86_loop_tail_jnz(const uint8_t *code, unsigned length,
                                         unsigned immediate_end,
                                         uint8_t count_reg,
                                         MadeiraSeX86LoopTail *tail)
{
    unsigned pos = immediate_end;

    /* jnz rel8 */
    if (pos + 2 > length || code[pos] != 0x75) {
        return false;
    }
    if ((int8_t)code[pos + 1] != -(int32_t)(pos + 2)) {
        return false;
    }
    tail->found = true;
    tail->count_reg = count_reg;
    tail->length = pos + 2;
    return true;
}

static bool madeira_se_x86_loop_decode_insn(const uint8_t *code,
                                            unsigned length, unsigned *pos,
                                            bool code64,
                                            MadeiraSeX86LoopScan *scan,
                                            MadeiraSeX86LoopTail *tail)
{
    unsigned at = *pos;
    uint8_t legacy = 0;
    uint8_t rex = 0;
    uint8_t op;
    uint8_t modrm;

    while (at < length && (code[at] == 0x66 || code[at] == 0xf2 ||
                           code[at] == 0xf3)) {
        if (legacy != 0 && legacy != code[at]) {
            return false; /* conflicting mandatory prefixes */
        }
        legacy = code[at++];
    }
    if (code64 && at < length && (code[at] & 0xf0) == 0x40) {
        rex = code[at++];
        /* REX.R/X/B would select registers the decoder does not model. */
        if ((rex & 0x07) != 0) {
            return false;
        }
    }
    if (at >= length) {
        return false;
    }
    op = code[at++];

    /*
     * inc/dec r32 in 32-bit mode; both double as REX prefixes in long mode,
     * where the FF /0 and FF /1 forms are handled below instead.
     */
    if (!code64 && op >= 0x40 && op <= 0x4f) {
        if (legacy != 0) {
            return false;
        }
        scan->advance[op & 0x07] += 1;
        scan->insns++;
        *pos = at;
        return true;
    }

    switch (op) {
    case 0x0f: {
        uint8_t op2;
        uint8_t base;
        uint8_t reg;
        uint8_t kind;
        uint8_t size;
        bool is_store;

        if (at >= length) {
            return false;
        }
        op2 = code[at++];
        switch (op2) {
        case 0x6f: /* movq mm, m64 / movdqa / movdqu */
        case 0x7f: /* the same, storing */
            if (legacy == 0) {
                kind = MADEIRA_SE_X86_LOOP_VALUE_MMX;
                size = 8;
            } else {
                kind = MADEIRA_SE_X86_LOOP_VALUE_XMM;
                size = 16;
            }
            is_store = op2 == 0x7f;
            break;
        case 0x10: /* movups / movupd / movss / movsd */
        case 0x11:
        case 0x28: /* movaps / movapd */
        case 0x29:
            if (legacy == 0x66) {
                kind = MADEIRA_SE_X86_LOOP_VALUE_XMM;
                size = 16;
            } else if (legacy == 0) {
                kind = MADEIRA_SE_X86_LOOP_VALUE_XMM;
                size = 16;
            } else if (legacy == 0xf2) {
                kind = MADEIRA_SE_X86_LOOP_VALUE_XMM;
                size = 8;
            } else if (legacy == 0xf3) {
                kind = MADEIRA_SE_X86_LOOP_VALUE_XMM;
                size = 4;
            } else {
                return false;
            }
            is_store = (op2 & 1) != 0;
            break;
        default:
            return false;
        }

        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        if (!madeira_se_x86_base_operand(modrm, &base, &reg)) {
            return false;
        }
        if (is_store) {
            if (scan->have_store) {
                return false;
            }
            scan->have_store = true;
            scan->store_mem = true;
            scan->store_is_imm = false;
            scan->store_base = base;
            scan->store_reg = reg;
            scan->store_kind = kind;
            scan->store_size = size;
        } else {
            if (scan->have_load || scan->have_store) {
                return false;
            }
            scan->have_load = true;
            scan->load_mem = true;
            scan->load_base = base;
            scan->load_reg = reg;
            scan->load_kind = kind;
            scan->load_size = size;
        }
        scan->insns++;
        *pos = at;
        return true;
    }
    case 0x8b: /* mov r32, [reg] */
    case 0x8a: /* mov r8, [reg] */
        if (legacy != 0 || scan->have_load || scan->have_store) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        if (!madeira_se_x86_base_operand(modrm, &scan->load_base,
                                         &scan->load_reg)) {
            return false;
        }
        scan->have_load = true;
        scan->load_mem = true;
        scan->load_kind = MADEIRA_SE_X86_LOOP_VALUE_GPR;
        scan->load_size = (op == 0x8b) ? ((rex & 0x08) ? 8 : 4) : 1;
        scan->insns++;
        *pos = at;
        return true;
    case 0x89: /* mov [reg], r32 */
    case 0x88: /* mov [reg], r8 */
        if (legacy != 0 || scan->have_store) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        if (!madeira_se_x86_base_operand(modrm, &scan->store_base,
                                         &scan->store_reg)) {
            return false;
        }
        scan->have_store = true;
        scan->store_mem = true;
        scan->store_is_imm = false;
        scan->store_kind = MADEIRA_SE_X86_LOOP_VALUE_GPR;
        scan->store_size = (op == 0x89) ? ((rex & 0x08) ? 8 : 4) : 1;
        scan->insns++;
        *pos = at;
        return true;
    case 0xc7: /* mov [reg], imm32 */
    {
        uint8_t reg;

        if (legacy != 0 || rex != 0 || scan->have_store) {
            return false;
        }
        if (at + 5 > length) {
            return false;
        }
        modrm = code[at];
        if (!madeira_se_x86_base_operand(modrm, &scan->store_base,
                                         &reg)) {
            return false;
        }
        if (reg != 0) { /* /0 only */
            return false;
        }
        scan->store_is_imm = true;
        scan->have_store = true;
        scan->store_mem = true;
        scan->store_kind = MADEIRA_SE_X86_LOOP_VALUE_IMM32;
        scan->store_size = 4;
        scan->store_imm = (uint32_t)code[at + 1] |
            ((uint32_t)code[at + 2] << 8) |
            ((uint32_t)code[at + 3] << 16) |
            ((uint32_t)code[at + 4] << 24);
        at += 5;
        scan->insns++;
        *pos = at;
        return true;
    }
    case 0x83: /* add/sub r/m32, imm8 */
    case 0x81: { /* add r/m32, imm32 */
        uint8_t ext;
        uint8_t reg;
        int32_t imm;
        bool is_sub;

        if (legacy != 0) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        if (!madeira_se_x86_reg_operand(modrm, &reg, &ext)) {
            return false;
        }
        if (op == 0x83) {
            if (at >= length) {
                return false;
            }
            imm = (int8_t)code[at++];
        } else {
            if (at + 4 > length) {
                return false;
            }
            imm = (int32_t)((uint32_t)code[at] |
                            ((uint32_t)code[at + 1] << 8) |
                            ((uint32_t)code[at + 2] << 16) |
                            ((uint32_t)code[at + 3] << 24));
            at += 4;
        }
        is_sub = ext == 5;
        if (ext == 0) {
            scan->advance[reg] += imm;
            scan->insns++;
            *pos = at;
            return true;
        }
        if (is_sub && imm == 1) {
            MadeiraSeX86LoopTail sub_tail;

            if (!madeira_se_x86_loop_tail_jnz(code, length, at, reg,
                                              &sub_tail)) {
                return false;
            }
            /* The counter update and the conditional branch are two
             * instructions, and both are guest instructions the block would
             * have retired. */
            scan->insns += 2;
            tail->found = true;
            tail->count_reg = sub_tail.count_reg;
            tail->length = sub_tail.length;
            *pos = sub_tail.length;
            return true;
        }
        return false;
    }
    case 0x8d: { /* lea reg, [base + disp] */
        uint8_t reg;
        uint8_t base;
        int32_t disp;

        if (legacy != 0) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        base = modrm & 0x07;
        reg = (uint8_t)((modrm >> 3) & 0x07);
        if ((modrm & 0xc0) != 0x40 && (modrm & 0xc0) != 0x80) {
            return false;
        }
        if (base == 4) { /* SIB */
            return false;
        }
        if ((modrm & 0xc0) == 0x40) {
            if (at + 1 > length) {
                return false;
            }
            disp = (int8_t)code[at];
            at += 1;
        } else {
            if (at + 4 > length) {
                return false;
            }
            disp = (int32_t)((uint32_t)code[at] |
                             ((uint32_t)code[at + 1] << 8) |
                             ((uint32_t)code[at + 2] << 16) |
                             ((uint32_t)code[at + 3] << 24));
            at += 4;
        }
        /* Only "advance this pointer by a constant" is replayable. */
        if (reg != base) {
            return false;
        }
        scan->advance[reg] += disp;
        scan->insns++;
        *pos = at;
        return true;
    }
    case 0xff: { /* inc/dec r/m32 */
        uint8_t ext;
        uint8_t reg;

        if (legacy != 0) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        modrm = code[at++];
        if (!madeira_se_x86_reg_operand(modrm, &reg, &ext)) {
            return false;
        }
        if (ext == 0) { /* inc */
            scan->advance[reg] += 1;
            scan->insns++;
            *pos = at;
            return true;
        }
        if (ext == 1) { /* dec, only valid as a loop tail */
            MadeiraSeX86LoopTail dec_tail;

            if (!madeira_se_x86_loop_tail_jnz(code, length, at, reg,
                                              &dec_tail)) {
                return false;
            }
            scan->insns += 2;
            tail->found = true;
            tail->count_reg = dec_tail.count_reg;
            tail->length = dec_tail.length;
            *pos = dec_tail.length;
            return true;
        }
        return false;
    }
    case 0xe2: { /* loop rel8 */
        uint8_t rel;

        if (legacy != 0 || rex != 0) {
            return false;
        }
        if (at >= length) {
            return false;
        }
        rel = code[at];
        if ((int8_t)rel != -(int32_t)(at + 1)) {
            return false; /* the branch must target the loop head */
        }
        scan->insns++;
        tail->found = true;
        tail->count_reg = MADEIRA_SE_X86_REG_ECX;
        tail->length = at + 1;
        *pos = tail->length;
        return true;
    }
    default:
        return false;
    }
}

bool madeira_se_x86_loop_decode(const uint8_t *code, unsigned length,
                                bool code64,
                                MadeiraSeX86LoopPattern *pattern)
{
    MadeiraSeX86LoopScan scan = { 0 };
    MadeiraSeX86LoopTail tail = { 0 };
    unsigned pos = 0;
    unsigned r;
    uint8_t elem_size;
    uint8_t src_reg = 0;

    if (pattern == NULL || code == NULL || length == 0) {
        return false;
    }

    while (pos < length && !tail.found) {
        if (!madeira_se_x86_loop_decode_insn(code, length, &pos, code64,
                                             &scan, &tail)) {
            return false;
        }
    }
    if (!tail.found || !scan.have_store || pos > MADEIRA_SE_X86_LOOP_MAX_BYTES) {
        return false;
    }

    /*
     * Both shapes write exactly one element per iteration; the copy shape
     * also reads one, and the value must travel from the load to the store
     * unchanged.
     */
    if (scan.have_load) {
        if (!scan.load_mem || !scan.store_mem ||
            scan.load_reg != scan.store_reg ||
            scan.load_kind != scan.store_kind ||
            scan.load_size != scan.store_size) {
            return false;
        }
        /* A pointer register may not double as the copied value. */
        if (scan.load_kind == MADEIRA_SE_X86_LOOP_VALUE_GPR &&
            (scan.load_reg == scan.load_base ||
             scan.load_reg == scan.store_base)) {
            return false;
        }
        src_reg = scan.load_base;
    } else {
        if (scan.store_kind == MADEIRA_SE_X86_LOOP_VALUE_IMM32 &&
            !scan.store_is_imm) {
            return false;
        }
    }

    elem_size = scan.store_size;
    if (elem_size != 1 && elem_size != 4 && elem_size != 8 &&
        elem_size != 16) {
        return false;
    }

    /*
     * Every pointer has to advance by exactly one element, and no other
     * register may be touched: that is what makes "run N-1 iterations with a
     * host memcpy" the same as running them one at a time.
     */
    for (r = 0; r < 8; r++) {
        if (r == scan.store_base ||
            (scan.have_load && r == src_reg)) {
            if (scan.advance[r] != (int32_t)elem_size) {
                return false;
            }
        } else if (scan.advance[r] != 0) {
            return false;
        }
    }

    if (tail.count_reg == scan.store_base ||
        (scan.have_load && tail.count_reg == src_reg) ||
        scan.advance[tail.count_reg] != 0) {
        return false;
    }
    if (!scan.have_load &&
        scan.store_kind == MADEIRA_SE_X86_LOOP_VALUE_GPR &&
        (scan.store_reg == scan.store_base ||
         scan.store_reg == tail.count_reg)) {
        return false;
    }

    pattern->length = (uint8_t)pos;
    pattern->insns = (uint8_t)scan.insns;
    pattern->elem_size = elem_size;
    pattern->kind = scan.have_load ? MADEIRA_SE_X86_LOOP_KIND_COPY
                                   : MADEIRA_SE_X86_LOOP_KIND_FILL;
    pattern->src_reg = scan.have_load ? src_reg : scan.store_base;
    pattern->dst_reg = scan.store_base;
    pattern->count_reg = tail.count_reg;
    pattern->value_kind = scan.have_load ? MADEIRA_SE_X86_LOOP_VALUE_NONE
                                         : scan.store_kind;
    pattern->value_reg = scan.store_reg;
    pattern->reserved = 0;
    pattern->value_imm = scan.store_imm;
    return true;
}
