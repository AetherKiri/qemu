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

#ifndef SYSTEM_MADEIRA_SE_TCTI_LOOP_H
#define SYSTEM_MADEIRA_SE_TCTI_LOOP_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Per-translation-block guard state.
 *
 * The translator reserves this structure inline in the block's bytecode
 * stream, directly after the guard gadget's address, so the gadget reaches it
 * with the stream pointer alone.  The gadget only reads the counter,
 * threshold and flag half-words; field offsets are part of the gadget in
 * tcti-gadget-gen.py ("tb_loop_guard") and must be kept in sync.
 */
typedef struct MadeiraSeTctiLoopState {
    uint16_t counter;   /* block entries since the last consultation */
    uint16_t threshold; /* entries required before asking the helper again */
    uint16_t flags;     /* MADEIRA_SE_TCTI_LOOP_FLAG_* */
    uint16_t reserved;
} MadeiraSeTctiLoopState;

/* Bytecode bytes the guard gadget owns: the state plus the helper address. */
#define MADEIRA_SE_TCTI_LOOP_SLOT_BYTES 16u

/* The helper already rejected this block; it must not be asked again. */
#define MADEIRA_SE_TCTI_LOOP_FLAG_DEAD 0x0001u

/* True when MADEIRA_SE_LOOP_GUARD asks for the guard. Resolved once. */
bool madeira_se_tcti_loop_enabled(void);

/* Entry count a freshly translated block starts with. */
uint16_t madeira_se_tcti_loop_default_threshold(void);

/*
 * Called from gadget_tb_loop_guard when a block has been entered
 * @threshold times.  Either replays the remaining iterations of a recognised
 * guest memory idiom natively - leaving the final iteration to the block
 * itself, so the interpreter still produces the exit state, flags and faults
 * exactly as before - or backs this block off.
 */
void madeira_se_tcti_loop_guard(CPUArchState *env,
                                MadeiraSeTctiLoopState *state);

#endif /* SYSTEM_MADEIRA_SE_TCTI_LOOP_H */
