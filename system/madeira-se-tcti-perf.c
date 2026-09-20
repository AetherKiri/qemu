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
