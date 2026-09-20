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
