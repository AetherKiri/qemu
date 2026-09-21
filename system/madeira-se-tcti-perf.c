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

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "cpu.h"
#include "system/madeira-se-tcti-perf.h"

MadeiraSeTctiPerfState madeira_se_tcti_perf_state;

bool madeira_se_tcti_perf_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = getenv("MADEIRA_SE_PERF_STATS");

        enabled = value != NULL && value[0] != '\0'
            && strcmp(value, "0") != 0
            && strcasecmp(value, "off") != 0
            && strcasecmp(value, "no") != 0
            && strcasecmp(value, "false") != 0;
    }
    return enabled != 0;
}

/*
 * Guest-PC histogram: translation blocks are keyed by their start address so a
 * dump can be attributed to a module and, with the help of a disassembler, to a
 * function.
 *
 * A plain open-addressed table cannot be used here: a title executes tens of
 * thousands of distinct translation blocks per second, and silently dropping
 * the ones that arrive after the table is full would both under-report the
 * interval and bias the ranking towards whatever ran first.  Instead the table
 * keeps the "space saving" invariant - when a probe sequence is full, the least
 * frequent of the probed buckets is evicted and its count is folded into a
 * spill counter.  Heavy hitters are then preserved (each recorded count is off
 * by at most total/probes), and the dump reports the spilled total so the
 * coverage of the interval is known.
 */
#define MADEIRA_SE_TCTI_PC_BUCKETS 65536u
#define MADEIRA_SE_TCTI_PC_PROBES 8u

typedef struct MadeiraSeTctiPcBucket {
    uint64_t epoch;
    uint64_t pc;
    uint64_t count;
    uint64_t insns;
} MadeiraSeTctiPcBucket;

static MadeiraSeTctiPcBucket madeira_se_tcti_pc_buckets[MADEIRA_SE_TCTI_PC_BUCKETS];
static uint64_t madeira_se_tcti_pc_spilled_insns;
static uint64_t madeira_se_tcti_pc_spilled_count;
/*
 * Buckets are invalidated by bumping the epoch instead of clearing 2 MB of
 * memory on every dump: an entry belongs to the current interval only when its
 * stamp matches, so no window can ever inherit the previous one's counts (the
 * failure mode a memset-based reset has when the dump races with the CPU
 * thread).
 */
static uint64_t madeira_se_tcti_pc_epoch = 1;

static inline uint32_t madeira_se_tcti_pc_hash(uint64_t pc)
{
    return (uint32_t)((pc >> 2) * 0x9E3779B97F4A7C15ull >> 51) &
           (MADEIRA_SE_TCTI_PC_BUCKETS - 1);
}

void madeira_se_tcti_perf_note_tb(const void *cpu_env, uint64_t guest_instructions)
{
    uint32_t slot;
    uint32_t probes;
    uint32_t victim = 0;
    uint64_t victim_count = UINT64_MAX;
    uint64_t guest_pc = (uint64_t)((const CPUX86State *)cpu_env)->eip;

    madeira_se_tcti_perf_state.guest_instructions += guest_instructions;
    madeira_se_tcti_perf_state.tb_entries++;

    slot = madeira_se_tcti_pc_hash(guest_pc);
    uint64_t epoch = madeira_se_tcti_pc_epoch;

    for (probes = 0; probes < MADEIRA_SE_TCTI_PC_PROBES; probes++) {
        MadeiraSeTctiPcBucket *bucket = &madeira_se_tcti_pc_buckets[slot];

        if (bucket->epoch != epoch) {
            bucket->epoch = epoch;
            bucket->pc = guest_pc;
            bucket->count = 1;
            bucket->insns = guest_instructions;
            return;
        }
        if (bucket->pc == guest_pc) {
            bucket->count++;
            bucket->insns += guest_instructions;
            return;
        }
        if (bucket->count < victim_count) {
            victim_count = bucket->count;
            victim = slot;
        }
        slot = (slot + 1) & (MADEIRA_SE_TCTI_PC_BUCKETS - 1);
    }

    madeira_se_tcti_pc_spilled_insns += madeira_se_tcti_pc_buckets[victim].insns;
    madeira_se_tcti_pc_spilled_count += madeira_se_tcti_pc_buckets[victim].count;
    madeira_se_tcti_pc_buckets[victim].pc = guest_pc;
    madeira_se_tcti_pc_buckets[victim].count = 1;
    madeira_se_tcti_pc_buckets[victim].insns = guest_instructions;
}

void madeira_se_tcti_perf_dump_pc_histogram(void)
{
    enum { kTop = 32 };
    uint64_t best_insns[kTop] = {0};
    uint64_t best_count[kTop] = {0};
    uint64_t best_pc[kTop] = {0};
    uint64_t total = 0;
    unsigned i, j;
    static uint64_t dump_seq;
    static uint64_t last_loop[14];
    uint64_t loop[14];
    uint64_t cum_insns;
    uint64_t cum_tb;

    if (!madeira_se_tcti_perf_enabled())
        return;

    /*
     * Self-check: the histogram covers the interval since the previous dump,
     * so its total has to match the *cumulative* counters read in the same
     * call.  Printing both makes a histogram that silently accumulates two
     * windows (or one that drops counts) impossible to mistake for real data.
     */
    cum_insns = qatomic_read(&madeira_se_tcti_perf_state.guest_instructions);
    cum_tb = qatomic_read(&madeira_se_tcti_perf_state.tb_entries);

    /*
     * The loop guard counters are cumulative, like the instruction counters,
     * but a window is what the budget is expressed in - so report both.
     */
    loop[0] = qatomic_read(&madeira_se_tcti_perf_state.loop_guard_calls);
    loop[1] = qatomic_read(&madeira_se_tcti_perf_state.loop_accelerated);
    loop[2] = qatomic_read(&madeira_se_tcti_perf_state.loop_iterations);
    loop[3] = qatomic_read(&madeira_se_tcti_perf_state.loop_bytes);
    loop[4] = qatomic_read(&madeira_se_tcti_perf_state.loop_backoffs);
    loop[5] = qatomic_read(&madeira_se_tcti_perf_state.loop_pattern_misses);
    loop[6] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_no_code);
    loop[7] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_short);
    loop[8] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_small_count);
    loop[9] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_overlap);
    loop[10] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_map);
    loop[11] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_other);
    loop[12] = qatomic_read(&madeira_se_tcti_perf_state.loop_reject_align);
    loop[13] = qatomic_read(&madeira_se_tcti_perf_state.loop_move_calls);

    for (i = 0; i < MADEIRA_SE_TCTI_PC_BUCKETS; i++) {
        if (madeira_se_tcti_pc_buckets[i].epoch != madeira_se_tcti_pc_epoch)
            continue;
        uint64_t insns = madeira_se_tcti_pc_buckets[i].insns;

        if (!insns)
            continue;
        total += insns;
        for (j = 0; j < kTop; j++) {
            if (insns > best_insns[j]) {
                memmove(&best_insns[j + 1], &best_insns[j],
                        (kTop - j - 1) * sizeof(best_insns[0]));
                memmove(&best_count[j + 1], &best_count[j],
                        (kTop - j - 1) * sizeof(best_count[0]));
                memmove(&best_pc[j + 1], &best_pc[j],
                        (kTop - j - 1) * sizeof(best_pc[0]));
                best_insns[j] = insns;
                best_count[j] = madeira_se_tcti_pc_buckets[i].count;
                best_pc[j] = madeira_se_tcti_pc_buckets[i].pc;
                break;
            }
        }
    }

    fprintf(stderr,
            "MADEIRA_SE_PERF_PC seq=%llu cum_insns=%llu cum_tb=%llu "
            "total_insns=%llu spilled_insns=%llu "
            "spilled_tb=%llu coverage_pct=%.2f "
            "loop_calls=%llu loop_accel=%llu loop_iters=%llu "
            "loop_bytes=%llu loop_backoff=%llu loop_dead=%llu "
            "rej_no_code=%llu rej_short=%llu rej_small_count=%llu "
            "rej_overlap=%llu rej_map=%llu rej_other=%llu rej_align=%llu "
            "move_calls=%llu\n",
            (unsigned long long)++dump_seq,
            (unsigned long long)cum_insns, (unsigned long long)cum_tb,
            (unsigned long long)total,
            (unsigned long long)madeira_se_tcti_pc_spilled_insns,
            (unsigned long long)madeira_se_tcti_pc_spilled_count,
            total ? 100.0 * (double)total /
                        (double)(total + madeira_se_tcti_pc_spilled_insns)
                  : 0.0,
            (unsigned long long)(loop[0] - last_loop[0]),
            (unsigned long long)(loop[1] - last_loop[1]),
            (unsigned long long)(loop[2] - last_loop[2]),
            (unsigned long long)(loop[3] - last_loop[3]),
            (unsigned long long)(loop[4] - last_loop[4]),
            (unsigned long long)(loop[5] - last_loop[5]),
            (unsigned long long)(loop[6] - last_loop[6]),
            (unsigned long long)(loop[7] - last_loop[7]),
            (unsigned long long)(loop[8] - last_loop[8]),
            (unsigned long long)(loop[9] - last_loop[9]),
            (unsigned long long)(loop[10] - last_loop[10]),
            (unsigned long long)(loop[11] - last_loop[11]),
            (unsigned long long)(loop[12] - last_loop[12]),
            (unsigned long long)(loop[13] - last_loop[13]));
    memcpy(last_loop, loop, sizeof(last_loop));
    for (j = 0; j < kTop; j++) {
        if (!best_insns[j])
            break;
        fprintf(stderr, "MADEIRA_SE_PERF_PC   pc=0x%08llx insns=%llu tb=%llu\n",
                (unsigned long long)best_pc[j], (unsigned long long)best_insns[j],
                (unsigned long long)best_count[j]);
    }

    /* Each dump covers the interval since the previous one. */
    madeira_se_tcti_pc_epoch++;
    madeira_se_tcti_pc_spilled_insns = 0;
    madeira_se_tcti_pc_spilled_count = 0;
}

void madeira_se_tcti_perf_note_translation(uint32_t guest_instructions)
{
    madeira_se_tcti_perf_state.tb_translations++;
    madeira_se_tcti_perf_state.translated_instructions += guest_instructions;
}

void madeira_se_tcti_perf_read(uint64_t *guest_instructions,
                               uint64_t *tb_entries,
                               uint64_t *tb_translations,
                               uint64_t *translated_instructions)
{
    /*
     * A single CPU thread updates the counters with plain, naturally aligned
     * stores; the reader only needs a consistent snapshot per field.
     */
    if (guest_instructions != NULL)
        *guest_instructions = qatomic_read(&madeira_se_tcti_perf_state
                                           .guest_instructions);
    if (tb_entries != NULL)
        *tb_entries = qatomic_read(&madeira_se_tcti_perf_state.tb_entries);
    if (tb_translations != NULL)
        *tb_translations = qatomic_read(
            &madeira_se_tcti_perf_state.tb_translations);
    if (translated_instructions != NULL)
        *translated_instructions = qatomic_read(
            &madeira_se_tcti_perf_state.translated_instructions);
}
