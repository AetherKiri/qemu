/*
 * Madeira-SE TCTI loop guard.
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
#include "exec/cpu-common.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/mmu-access-type.h"
#include "exec/target_page.h"
#include "hw/core/cpu.h"
#include "system/cpu-timers.h"

#include "system/madeira-se-tcti-loop.h"
#include "system/madeira-se-tcti-perf.h"
#include "system/madeira-se-x86-loop.h"

/*
 * Acceleration is bounded by the number of page-sized pieces we are willing
 * to describe up front.  The copy itself only starts once every source and
 * destination piece has been shown to be directly addressable, so a rejected
 * range leaves the guest state - and the guest's fault semantics - untouched.
 */
#define MADEIRA_SE_LOOP_MAX_CHUNKS 64u
/*
 * A range rarely starts on a page boundary, so the first piece can be partial
 * and the range has to stop one page short of what the chunk array could hold.
 */
#define MADEIRA_SE_LOOP_MAX_BYTES \
    ((MADEIRA_SE_LOOP_MAX_CHUNKS - 1u) * (uint64_t)TARGET_PAGE_SIZE)

#define MADEIRA_SE_LOOP_DEFAULT_THRESHOLD 2u
#define MADEIRA_SE_LOOP_MAX_THRESHOLD 4096u
#define MADEIRA_SE_LOOP_MIN_THRESHOLD 2u
#define MADEIRA_SE_LOOP_MIN_ITERATIONS 6u
#define MADEIRA_SE_LOOP_MAX_ICOUNT UINT32_C(0xffff)

typedef struct MadeiraSeLoopChunk {
    void *src;
    void *dst;
    unsigned len;
} MadeiraSeLoopChunk;

/*
 * Debug aid: MADEIRA_SE_LOOP_TRACE=1 prints the guard's decisions, for the
 * first few dozen calls.  Off by default, and resolved once.
 */
static void madeira_se_tcti_loop_trace(const char *reason, uint64_t pc,
                                       uint64_t count, uint64_t iterations,
                                       uint64_t extra)
{
    static int enabled = -1;
    static unsigned printed;

    if (enabled < 0) {
        const char *value = getenv("MADEIRA_SE_LOOP_TRACE");

        enabled = value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
    }
    /*
     * Blocks that are simply not idioms are by far the most common result and
     * the least interesting; keep the log readable by limiting those.
     */
    if (enabled != 1 ||
        printed >= (strcmp(reason, "not-idiom") == 0 ? 8u : 64u)) {
        return;
    }
    printed++;
    fprintf(stderr,
            "MADEIRA_SE_LOOP_TRACE %-16s pc=0x%08llx count=%llu "
            "iterations=%llu other=0x%llx\n",
            reason, (unsigned long long)pc, (unsigned long long)count,
            (unsigned long long)iterations, (unsigned long long)extra);
}

static void madeira_se_tcti_loop_note_map_failure(uint64_t pc, uint64_t addr,
                                                 unsigned size, bool write,
                                                 int flags)
{
    madeira_se_tcti_perf_state.loop_reject_map++;
    madeira_se_tcti_loop_trace(write ? "map-write" : "map-read", pc, addr,
                               size, (uint64_t)(uint32_t)flags);
}

bool madeira_se_tcti_loop_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = getenv("MADEIRA_SE_LOOP_GUARD");

        enabled = !(value != NULL
                    && (strcmp(value, "0") == 0
                        || strcasecmp(value, "off") == 0
                        || strcasecmp(value, "no") == 0
                        || strcasecmp(value, "false") == 0));
    }
    return enabled != 0;
}

uint16_t madeira_se_tcti_loop_default_threshold(void)
{
    static int threshold = -1;

    if (threshold < 0) {
        const char *value = getenv("MADEIRA_SE_LOOP_THRESHOLD");
        long parsed = 0;

        if (value != NULL && value[0] != '\0') {
            parsed = strtol(value, NULL, 0);
        }
        if (parsed < (long)MADEIRA_SE_LOOP_MIN_THRESHOLD) {
            parsed = MADEIRA_SE_LOOP_DEFAULT_THRESHOLD;
        }
        if (parsed > (long)MADEIRA_SE_LOOP_MAX_THRESHOLD) {
            parsed = MADEIRA_SE_LOOP_MAX_THRESHOLD;
        }
        threshold = (int)parsed;
    }
    return (uint16_t)threshold;
}

/*
 * How many iterations of a block are worth one helper call?  Interpreted, a
 * copy/fill iteration costs on the order of a hundred host instructions; the
 * call, its decode and its mapping probes cost a few hundred, so a handful of
 * iterations already pays for the call.  Anything below that is left to the
 * interpreter, and the block's threshold doubles so it is not asked again
 * soon.
 */
static uint64_t madeira_se_tcti_loop_min_iterations(void)
{
    static int64_t cached = -1;

    if (cached < 0) {
        const char *value = getenv("MADEIRA_SE_LOOP_MIN_ITERATIONS");
        int64_t parsed = MADEIRA_SE_LOOP_MIN_ITERATIONS;

        if (value != NULL && value[0] != '\0') {
            parsed = strtoll(value, NULL, 0);
        }
        if (parsed < 0) {
            parsed = 0;
        }
        cached = parsed;
    }
    return (uint64_t)cached;
}

/*
 * The guard asks for the guest instructions at the block's start PC.  Reading
 * them through the code TLB keeps this non-faulting: when the page is not
 * directly addressable the helper simply backs off, and the interpreter
 * produces whatever fault the guest would have seen.
 */
static const uint8_t *madeira_se_tcti_loop_code(CPUArchState *env, uint64_t pc,
                                                unsigned *length)
{
    unsigned page_left = (unsigned)(TARGET_PAGE_SIZE -
                                    (pc & (TARGET_PAGE_SIZE - 1)));
    void *host;

    host = tlb_vaddr_to_host(env, pc, MMU_INST_FETCH,
                             cpu_mmu_index(env_cpu(env), true));
    if (host == NULL) {
        return NULL;
    }
    *length = MIN(page_left, (unsigned)MADEIRA_SE_X86_LOOP_MAX_BYTES);
    return host;
}

static uint64_t madeira_se_tcti_loop_read(const CPUX86State *env, uint8_t reg,
                                          bool code64)
{
    uint64_t value = (uint64_t)env->regs[reg];

    return code64 ? value : (value & 0xffffffffu);
}

static void madeira_se_tcti_loop_write(CPUX86State *env, uint8_t reg,
                                       uint64_t value, bool code64)
{
    env->regs[reg] = code64 ? (target_ulong)value
                            : (target_ulong)(value & 0xffffffffu);
}

/*
 * Effective address of a memory operand whose base is a plain register.  The
 * default segment is DS, except for the stack pointer and frame pointer, which
 * default to SS; long mode ignores both bases.
 */
static uint64_t madeira_se_tcti_loop_address(const CPUX86State *env, uint8_t reg,
                                             bool code64)
{
    uint64_t value = (uint64_t)env->regs[reg];
    unsigned seg = (reg == R_ESP || reg == R_EBP) ? R_SS : R_DS;

    if (code64) {
        return value;
    }
    return (uint32_t)(value + (uint64_t)env->segs[seg].base);
}

/*
 * Translate one page-sized piece into a host pointer.
 *
 * probe_access_flags() with nonfault set is the non-raising counterpart of
 * what the interpreter itself would do for a store: a clean (write-tracked)
 * page is marked dirty here and its translations are invalidated, exactly as
 * they would be for a single guest store, while MMIO, watchpoints and
 * unmapped pages come back as flags and leave the piece to the interpreter.
 */
static bool madeira_se_tcti_loop_map(CPUArchState *env, uint64_t pc,
                                     uint64_t addr, unsigned size, bool write,
                                     void **host)
{
    int flags = probe_access_flags(env, addr, (int)size,
                                   write ? MMU_DATA_STORE : MMU_DATA_LOAD,
                                   cpu_mmu_index(env_cpu(env), false), true,
                                   host, 0);

    if (flags != 0 || *host == NULL) {
        madeira_se_tcti_loop_note_map_failure(pc, addr, size, write, flags);
    }
    return flags == 0 && *host != NULL;
}

static void madeira_se_tcti_loop_repeat(void *dst, const uint8_t *pattern,
                                        unsigned elem_size, unsigned len)
{
    uint8_t *out = dst;
    unsigned done = 0;

    if (elem_size == 1) {
        memset(out, pattern[0], len);
        return;
    }
    while (done < len) {
        memcpy(out + done, pattern, elem_size);
        done += elem_size;
    }
}

/*
 * Map the whole range, then move it.  Mapping first is what makes a rejected
 * range harmless: when any piece is MMIO, write-tracked, or not yet in the
 * TLB, nothing has been written and the interpreter takes over from the
 * unmodified guest state.
 */
static bool madeira_se_tcti_loop_move(CPUArchState *env,
                                      const MadeiraSeX86LoopPattern *pattern,
                                      uint64_t pc, const uint8_t *value,
                                      uint64_t src, uint64_t dst,
                                      uint64_t bytes)
{
    MadeiraSeLoopChunk chunks[MADEIRA_SE_LOOP_MAX_CHUNKS];
    bool fill = pattern->kind == MADEIRA_SE_X86_LOOP_KIND_FILL;
    unsigned elem_size = pattern->elem_size;
    unsigned count = 0;
    uint64_t done = 0;
    unsigned i;

    madeira_se_tcti_perf_state.loop_move_calls++;

    while (done < bytes) {
        uint64_t src_at = src + done;
        uint64_t dst_at = dst + done;
        uint64_t remain = bytes - done;
        unsigned chunk = (unsigned)(TARGET_PAGE_SIZE -
                                    (dst_at & (TARGET_PAGE_SIZE - 1)));

        if (!fill) {
            unsigned src_left = (unsigned)(TARGET_PAGE_SIZE -
                                           (src_at & (TARGET_PAGE_SIZE - 1)));

            if (src_left < chunk) {
                chunk = src_left;
            }
        }
        if ((uint64_t)chunk > remain) {
            chunk = (unsigned)remain;
        }
        /*
         * Pieces may split an element: the loop moves bytes, and moving the
         * same bytes in different pieces leaves the same result.  Only the
         * pointer and counter updates care about element size.
         */
        if (chunk == 0 || count == MADEIRA_SE_LOOP_MAX_CHUNKS) {
            madeira_se_tcti_perf_state.loop_reject_align++;
            return false;
        }
        if (!madeira_se_tcti_loop_map(env, pc, dst_at, chunk, true,
                                      &chunks[count].dst)) {
            return false;
        }
        chunks[count].src = NULL;
        if (!fill &&
            !madeira_se_tcti_loop_map(env, pc, src_at, chunk, false,
                                      &chunks[count].src)) {
            return false;
        }
        chunks[count].len = chunk;
        count++;
        done += chunk;
    }

    for (i = 0; i < count; i++) {
        if (fill) {
            madeira_se_tcti_loop_repeat(chunks[i].dst, value, elem_size,
                                        chunks[i].len);
        } else {
            memcpy(chunks[i].dst, chunks[i].src, chunks[i].len);
        }
    }
    return true;
}

/* Build the repeating element a fill loop stores. */
static bool madeira_se_tcti_loop_fill_value(const CPUX86State *env,
                                            const MadeiraSeX86LoopPattern *pat,
                                            bool code64, uint8_t *out)
{
    switch (pat->value_kind) {
    case MADEIRA_SE_X86_LOOP_VALUE_GPR: {
        uint64_t value = madeira_se_tcti_loop_read(env, pat->value_reg, code64);

        memcpy(out, &value, pat->elem_size);
        return true;
    }
    case MADEIRA_SE_X86_LOOP_VALUE_MMX: {
        uint64_t value = env->fpregs[pat->value_reg].mmx.MMX_Q(0);

        memcpy(out, &value, sizeof(value));
        return true;
    }
    case MADEIRA_SE_X86_LOOP_VALUE_XMM: {
        uint64_t low = env->xmm_regs[pat->value_reg].ZMM_Q(0);
        uint64_t high = env->xmm_regs[pat->value_reg].ZMM_Q(1);

        memcpy(out, &low, sizeof(low));
        memcpy(out + sizeof(low), &high, sizeof(high));
        return true;
    }
    case MADEIRA_SE_X86_LOOP_VALUE_IMM32:
        memcpy(out, &pat->value_imm, sizeof(pat->value_imm));
        return true;
    default:
        return false;
    }
}

/*
 * Two kinds of "not now".
 *
 * A transient miss - the loop is short right now, its pages are not mappable
 * yet, its ranges overlap - must be retried soon, because the very next
 * invocation of the same loop may look completely different.  A loop whose
 * invocations are consistently too short to be worth a call is asked about
 * far less often instead.
 */
static void madeira_se_tcti_loop_defer(MadeiraSeTctiLoopState *state,
                                       unsigned ceiling)
{
    uint32_t threshold = state->threshold;

    madeira_se_tcti_perf_state.loop_backoffs++;
    if (threshold == 0) {
        threshold = madeira_se_tcti_loop_default_threshold();
    }
    threshold *= 2;
    if (threshold > ceiling) {
        threshold = ceiling;
    }
    state->threshold = (uint16_t)threshold;
}

/* Retry soon: the block may qualify on its next invocation. */
#define MADEIRA_SE_LOOP_TRANSIENT_THRESHOLD 16u

static void madeira_se_tcti_loop_defer_transient(MadeiraSeTctiLoopState *state)
{
    madeira_se_tcti_loop_defer(state, MADEIRA_SE_LOOP_TRANSIENT_THRESHOLD);
}

/* This block's loops are too short to batch; ask rarely from now on. */
static void madeira_se_tcti_loop_defer_short(MadeiraSeTctiLoopState *state)
{
    madeira_se_tcti_loop_defer(state, MADEIRA_SE_LOOP_MAX_THRESHOLD);
}

void madeira_se_tcti_loop_guard(CPUArchState *env, MadeiraSeTctiLoopState *state)
{
    MadeiraSeX86LoopPattern pattern;
    uint8_t value[16];
    const uint8_t *code;
    unsigned code_len = 0;
    uint64_t count, iterations, bytes, src, dst;
    uint64_t pc = (uint64_t)(target_ulong)env->eip;
    bool code64, fill;

    madeira_se_tcti_perf_state.loop_guard_calls++;
    state->counter = 0;

    /*
     * The decoder models 32-bit and 64-bit addressing; 16-bit code segments
     * would decode to entirely different operands, so leave them alone.
     */
    if ((env->hflags & (HF_CS32_MASK | HF_CS64_MASK)) == 0) {
        madeira_se_tcti_loop_trace("16-bit-code", pc, 0, 0, 0);
        madeira_se_tcti_perf_state.loop_reject_other++;
        state->flags |= MADEIRA_SE_TCTI_LOOP_FLAG_DEAD;
        return;
    }
    code64 = (env->hflags & HF_CS64_MASK) != 0;

    code = madeira_se_tcti_loop_code(env, pc, &code_len);
    if (code == NULL) {
        madeira_se_tcti_loop_trace("no-code", pc, 0, 0, 0);
        madeira_se_tcti_perf_state.loop_reject_no_code++;
        madeira_se_tcti_loop_defer_transient(state);
        return;
    }
    if (!madeira_se_x86_loop_decode(code, code_len, code64, &pattern)) {
        /*
         * Not a memory idiom: the bytes do not change until the block is
         * invalidated, so stop consulting the helper for this block.
         */
        madeira_se_tcti_loop_trace("not-idiom", pc, 0, 0, 0);
        state->flags |= MADEIRA_SE_TCTI_LOOP_FLAG_DEAD;
        madeira_se_tcti_perf_state.loop_pattern_misses++;
        return;
    }

    fill = pattern.kind == MADEIRA_SE_X86_LOOP_KIND_FILL;
    count = madeira_se_tcti_loop_read(env, pattern.count_reg, code64);
    if (count < 2) {
        /*
         * A count of zero means the loop writes its way around the address
         * space (loop decrements before testing); there is nothing to batch.
         */
        madeira_se_tcti_loop_trace("count-small", pc, count, 0, 0);
        madeira_se_tcti_perf_state.loop_reject_small_count++;
        madeira_se_tcti_loop_defer_transient(state);
        return;
    }

    iterations = count - 1; /* the block itself runs the last iteration */
    if (icount_enabled()) {
        uint64_t budget = MADEIRA_SE_LOOP_MAX_ICOUNT / pattern.insns;

        iterations = MIN(iterations, budget);
    }
    iterations = MIN(iterations,
                     MADEIRA_SE_LOOP_MAX_BYTES / pattern.elem_size);
    bytes = iterations * pattern.elem_size;
    if (iterations < madeira_se_tcti_loop_min_iterations()) {
        madeira_se_tcti_loop_trace("too-short", pc, count, iterations, 0);
        madeira_se_tcti_perf_state.loop_reject_short++;
        madeira_se_tcti_loop_defer_short(state);
        return;
    }

    src = madeira_se_tcti_loop_address(env, pattern.src_reg, code64);
    dst = madeira_se_tcti_loop_address(env, pattern.dst_reg, code64);
    if (!code64 && (src + bytes > UINT32_MAX + UINT64_C(1) ||
                    dst + bytes > UINT32_MAX + UINT64_C(1))) {
        madeira_se_tcti_loop_trace("wrap", pc, count, iterations, 0);
        madeira_se_tcti_perf_state.loop_reject_other++;
        madeira_se_tcti_loop_defer_short(state);
        return;
    }
    /*
     * Overlapping ranges would make the loop's per-element load/store order
     * observable, which a bulk copy cannot reproduce.  Such copies are rare.
     */
    if (!fill && src < dst + bytes && dst < src + bytes) {
        madeira_se_tcti_loop_trace("overlap", pc, count, iterations, 0);
        madeira_se_tcti_perf_state.loop_reject_overlap++;
        madeira_se_tcti_loop_defer_short(state);
        return;
    }
    if (fill) {
        memset(value, 0, sizeof(value));
        if (!madeira_se_tcti_loop_fill_value(env, &pattern, code64, value)) {
            madeira_se_tcti_loop_trace("bad-value", pc, count, iterations, 0);
            madeira_se_tcti_perf_state.loop_reject_other++;
            state->flags |= MADEIRA_SE_TCTI_LOOP_FLAG_DEAD;
            return;
        }
    }
    if (!madeira_se_tcti_loop_move(env, &pattern, pc, value, src, dst,
                                   bytes)) {
        madeira_se_tcti_loop_defer_transient(state);
        return;
    }

    madeira_se_tcti_loop_write(env, pattern.src_reg, src + bytes, code64);
    madeira_se_tcti_loop_write(env, pattern.dst_reg, dst + bytes, code64);
    madeira_se_tcti_loop_write(env, pattern.count_reg, count - iterations,
                               code64);

    if (icount_enabled()) {
        /*
         * Keep the virtual clock honest: the replayed iterations are guest
         * instructions that the block prologue will never see.  Subtracting
         * them from the decrementer is exactly what running them would have
         * done, including underflow, which forces the main loop to account
         * and refill.
         */
        CPUState *cpu = env_cpu(env);
        uint32_t skipped = (uint32_t)(pattern.insns * iterations);

        cpu->neg.icount_decr.u16.low =
            (uint16_t)(cpu->neg.icount_decr.u16.low - skipped);
    }

    madeira_se_tcti_perf_state.loop_accelerated++;
    madeira_se_tcti_perf_state.loop_iterations += iterations;
    madeira_se_tcti_perf_state.loop_bytes += bytes;
    madeira_se_tcti_loop_trace("replayed", pc, count, iterations, bytes);

    /*
     * The block is a memory idiom and replaying it pays; keep it on a short
     * leash so that later invocations of the same loop are replayed after a
     * couple of interpreted iterations.
     */
    state->threshold = MADEIRA_SE_LOOP_DEFAULT_THRESHOLD;
}
