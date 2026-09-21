/*
 * Madeira-SE TCTI throughput counters.
 *
 * Copyright (C) 2026 The Madeira contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef SYSTEM_MADEIRA_SE_TCTI_PERF_H
#define SYSTEM_MADEIRA_SE_TCTI_PERF_H

/*
 * Counters fold guest work that QEMU's icount subsystem cannot measure on
 * Madeira-SE: icount also drives the guest's virtual clock, so enabling it
 * stalls titles that block on host events while waiting for a timer. These
 * counters are updated by TCTI itself and leave guest time alone.
 */
typedef struct MadeiraSeTctiPerfState {
    /* Offset 0 and 8 are read by gadget_tb_enter; keep their order stable. */
    uint64_t guest_instructions;
    uint64_t tb_entries;
    /* Updated by the translator instead of the gadget stream. */
    uint64_t tb_translations;
    uint64_t translated_instructions;
    /*
     * Loop guard (see madeira-se-tcti-loop.c).  These are counted whether or
     * not the instruction probe is enabled, because they say how much guest
     * work left the interpreter - which is what the fps budget turns on.
     */
    uint64_t loop_guard_calls;     /* times a block asked the helper */
    uint64_t loop_accelerated;     /* times the helper replayed iterations */
    uint64_t loop_iterations;      /* guest iterations replayed natively */
    uint64_t loop_bytes;           /* bytes moved by those iterations */
    uint64_t loop_backoffs;        /* helper declined, block may ask again */
    uint64_t loop_pattern_misses;  /* not a memory idiom; block marked dead */
    /* Why the helper declined, so a coverage gap can be attributed. */
    uint64_t loop_reject_no_code;   /* code page not directly readable */
    uint64_t loop_reject_short;     /* too few iterations to be worth a call */
    uint64_t loop_reject_small_count; /* counter says the loop is done */
    uint64_t loop_reject_overlap;   /* source and destination overlap */
    uint64_t loop_reject_map;       /* a piece is MMIO, watchpointed or unmapped */
    uint64_t loop_reject_other;     /* wrapping range, 16-bit code, bad value */
    uint64_t loop_reject_align;     /* an element would straddle a page */
    uint64_t loop_move_calls;       /* ranges handed to the bulk mover */
} MadeiraSeTctiPerfState;

extern MadeiraSeTctiPerfState madeira_se_tcti_perf_state;

/* True when MADEIRA_SE_PERF_STATS asks for instrumentation. Resolved once. */
bool madeira_se_tcti_perf_enabled(void);

/* Called once per translation block when profiling is enabled. */
void madeira_se_tcti_perf_note_translation(uint32_t guest_instructions);

/*
 * Called from the translation-block entry probe. It folds the block's guest
 * instruction count into the cumulative counters and records the block's guest
 * PC in a histogram, which is what tells us *which* guest code the budget is
 * spent on (engine, Wine, the D3D9 layer, ...) instead of only how much.
 */
void madeira_se_tcti_perf_note_tb(const void *cpu_env, uint64_t guest_instructions);

/* Prints the hottest translation-block PCs seen so far (once per interval). */
void madeira_se_tcti_perf_dump_pc_histogram(void);

/* Cumulative counters; any argument may be NULL. */
void madeira_se_tcti_perf_read(uint64_t *guest_instructions,
                               uint64_t *tb_entries,
                               uint64_t *tb_translations,
                               uint64_t *translated_instructions);

#endif /* SYSTEM_MADEIRA_SE_TCTI_PERF_H */
