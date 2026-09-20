/*
 * Madeira-SE embedded x86/TCTI execution adapter
 *
 * Copyright (C) 2026 The Madeira contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"

#include "cpu.h"
#include "exec/address-spaces.h"
#include "exec/cpu-common.h"
#include "exec/cputlb.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/tb-flush.h"
#include "hw/core/cpu.h"
#include "qemu/main-loop.h"
#include "qemu/rcu.h"
#include "system/cpus.h"
#include "tcg/helper-tcg.h"
#include "accel/tcg/tcg-accel-ops-icount.h"

#include "madeira_se_cpu.h"
#include "system/madeira-se-tcti-perf.h"

typedef struct MadeiraSEQemuInstance {
    madeira_se_architecture_t architecture;
    madeira_se_memory_t memory;
    bool interrupted;
    uint8_t *xsave_buffer;
    uint32_t xsave_buffer_size;
    bool stats_enabled;
    uint64_t stats_runs;
    uint64_t stats_instructions;
    uint64_t stats_dispatch_us;
    uint64_t stats_reasons[MADEIRA_SE_CPU_EXIT_INTERRUPTED + 1];
} MadeiraSEQemuInstance;

typedef struct MadeiraSEQemuMapping {
    struct rcu_head rcu;
    uint64_t guest_address;
    uint64_t size;
    void *host_address;
    uint32_t protection;
    MemoryRegion region;
    struct MadeiraSEQemuMapping *next;
} MadeiraSEQemuMapping;

typedef struct MadeiraSERun {
    MadeiraSEQemuInstance *instance;
    const madeira_se_cpu_run_request_t *request;
    madeira_se_x86_context_t *context;
    madeira_se_cpu_run_result_t *result;
    int status;
} MadeiraSERun;

typedef struct MadeiraSESmokeRun {
    uint64_t guest_address;
    uint64_t eax;
    uint64_t fault_address;
    uint32_t error_code;
    int cpu_result;
} MadeiraSESmokeRun;

static MadeiraSEQemuMapping *madeira_se_mappings;
static unsigned int madeira_se_instance_count;
static unsigned int madeira_se_mapping_serial;
static MadeiraSEQemuInstance *madeira_se_active_instance;
/* QEMU's shared-library adapter owns one CPU object.  Track which Wine
 * thread's state is currently resident before honoring context reuse. */
static MadeiraSEQemuInstance *madeira_se_context_instance;

int madeira_se_qemu_tcti_smoke(void);
const madeira_se_cpu_backend_t *madeira_se_qemu_tcti_backend(void);

static bool madeira_se_architecture_supported(madeira_se_architecture_t architecture)
{
#ifdef TARGET_X86_64
    return architecture == MADEIRA_SE_ARCH_X86_64;
#else
    return architecture == MADEIRA_SE_ARCH_X86_32;
#endif
}

static bool madeira_se_range_overlaps(uint64_t left_address, uint64_t left_size,
                                      uint64_t right_address, uint64_t right_size)
{
    uint64_t left_end;
    uint64_t right_end;

    if (left_size == 0 || right_size == 0) {
        return false;
    }
    left_end = left_address + left_size;
    right_end = right_address + right_size;
    if (left_end < left_address || right_end < right_address) {
        return false;
    }
    return left_address < right_end && right_address < left_end;
}

static bool madeira_se_range_matches(uint64_t guest_address, uint64_t size,
                                     void *host_address, uint32_t protection)
{
    uint64_t cursor = guest_address;
    uint64_t range_end = guest_address + size;

    while (cursor < range_end) {
        MadeiraSEQemuMapping *mapping;
        uint64_t mapping_end;

        for (mapping = madeira_se_mappings; mapping != NULL;
             mapping = mapping->next) {
            if (cursor >= mapping->guest_address &&
                cursor - mapping->guest_address < mapping->size) {
                break;
            }
        }
        if (mapping == NULL || mapping->protection != protection ||
            (uint8_t *)mapping->host_address +
                (cursor - mapping->guest_address) !=
                (uint8_t *)host_address + (cursor - guest_address)) {
            return false;
        }
        mapping_end = mapping->guest_address + mapping->size;
        cursor = MIN(mapping_end, range_end);
    }
    return true;
}

static bool madeira_se_range_has_mapping(uint64_t guest_address, uint64_t size,
                                         uint32_t protection,
                                         bool check_protection)
{
    MadeiraSEQemuMapping *mapping;

    for (mapping = madeira_se_mappings; mapping != NULL;
         mapping = mapping->next) {
        if (madeira_se_range_overlaps(mapping->guest_address, mapping->size,
                                      guest_address, size) &&
            (!check_protection || mapping->protection != protection)) {
            return true;
        }
    }
    return false;
}

/*
 * Copies guest memory through the Wine-provided mappings. Callers run on the
 * CPU thread with the BQL held, which is the same context that maintains the
 * mapping list.
 */
static bool madeira_se_read_guest(uint64_t guest_address, void *destination,
                                  size_t size)
{
    uint8_t *out = destination;
    uint64_t cursor = guest_address;
    uint64_t remaining = size;

    while (remaining > 0) {
        MadeiraSEQemuMapping *mapping;
        uint64_t offset;
        size_t chunk;

        for (mapping = madeira_se_mappings; mapping != NULL;
             mapping = mapping->next) {
            if (cursor >= mapping->guest_address &&
                cursor - mapping->guest_address < mapping->size)
                break;
        }
        if (mapping == NULL) return false;
        offset = cursor - mapping->guest_address;
        chunk = (size_t)MIN(remaining, mapping->size - offset);
        memcpy(out, (const uint8_t *)mapping->host_address + offset, chunk);
        out += chunk;
        cursor += chunk;
        remaining -= chunk;
    }
    return true;
}

static void madeira_se_remove_mapping(MadeiraSEQemuMapping **link)
{
    MadeiraSEQemuMapping *mapping = *link;

    *link = mapping->next;
    memory_region_del_subregion(get_system_memory(), &mapping->region);
    object_unparent(OBJECT(&mapping->region));
    g_free_rcu(mapping, rcu);
}

static void madeira_se_add_mapping(MadeiraSEQemuMapping **list,
                                   uint64_t guest_address, uint64_t size,
                                   void *host_address, uint32_t protection)
{
    MadeiraSEQemuMapping *mapping;
    char *name;

    if (size == 0) {
        return;
    }
    mapping = g_new0(MadeiraSEQemuMapping, 1);
    mapping->guest_address = guest_address;
    mapping->size = size;
    mapping->host_address = host_address;
    mapping->protection = protection;
    name = g_strdup_printf("madeira-se-%u", ++madeira_se_mapping_serial);
    memory_region_init_ram_ptr(&mapping->region, NULL, name, size,
                               host_address);
    g_free(name);
    memory_region_set_readonly(&mapping->region,
                               (protection & MADEIRA_SE_MEMORY_WRITE) == 0);
    memory_region_add_subregion_overlap(get_system_memory(), guest_address,
                                        &mapping->region, 1);
    mapping->next = *list;
    *list = mapping;
}

static void madeira_se_rewrite_range(uint64_t guest_address, uint64_t size,
                                     bool keep_overlap, uint32_t protection)
{
    MadeiraSEQemuMapping *mapping = madeira_se_mappings;
    MadeiraSEQemuMapping *rewritten = NULL;
    uint64_t range_end = guest_address + size;

    madeira_se_mappings = NULL;
    while (mapping != NULL) {
        MadeiraSEQemuMapping *next = mapping->next;
        uint64_t mapping_end = mapping->guest_address + mapping->size;

        if (!madeira_se_range_overlaps(mapping->guest_address, mapping->size,
                                       guest_address, size)) {
            mapping->next = rewritten;
            rewritten = mapping;
            mapping = next;
            continue;
        }

        memory_region_del_subregion(get_system_memory(), &mapping->region);
        if (mapping->guest_address < guest_address) {
            madeira_se_add_mapping(
                &rewritten, mapping->guest_address,
                guest_address - mapping->guest_address,
                mapping->host_address, mapping->protection);
        }
        if (keep_overlap) {
            uint64_t overlap_start = MAX(mapping->guest_address,
                                         guest_address);
            uint64_t overlap_end = MIN(mapping_end, range_end);

            madeira_se_add_mapping(
                &rewritten, overlap_start, overlap_end - overlap_start,
                (uint8_t *)mapping->host_address +
                    (overlap_start - mapping->guest_address),
                protection);
        }
        if (mapping_end > range_end) {
            madeira_se_add_mapping(
                &rewritten, range_end, mapping_end - range_end,
                (uint8_t *)mapping->host_address +
                    (range_end - mapping->guest_address),
                mapping->protection);
        }
        object_unparent(OBJECT(&mapping->region));
        g_free_rcu(mapping, rcu);
        mapping = next;
    }
    madeira_se_mappings = rewritten;
}

static int madeira_se_map(MadeiraSEQemuInstance *instance,
                          uint64_t guest_address, uint64_t size,
                          uint32_t protection, bool *changed)
{
    void *host_address;

    if (size == 0 || guest_address + size < guest_address ||
        size > (uint64_t)SIZE_MAX || instance->memory.translate == NULL) {
        return -1;
    }
    host_address = instance->memory.translate(instance->memory.userdata,
                                               guest_address, (size_t)size,
                                               protection);
    if (host_address == NULL) {
        return -1;
    }
    if (madeira_se_range_matches(guest_address, size, host_address,
                                 protection)) {
        *changed = false;
        return 0;
    }
    madeira_se_rewrite_range(guest_address, size, false, 0);
    madeira_se_add_mapping(&madeira_se_mappings, guest_address, size,
                           host_address, protection);
    *changed = true;
    return 0;
}

static bool madeira_se_unmap(uint64_t guest_address, uint64_t size)
{
    if (size == 0) {
        MadeiraSEQemuMapping *mapping;

        for (mapping = madeira_se_mappings; mapping != NULL;
             mapping = mapping->next) {
            if (guest_address >= mapping->guest_address &&
                guest_address - mapping->guest_address < mapping->size) {
                guest_address = mapping->guest_address;
                size = mapping->size;
                break;
            }
        }
    }
    if (size != 0 && guest_address + size >= guest_address) {
        if (!madeira_se_range_has_mapping(guest_address, size, 0, false)) {
            return false;
        }
        madeira_se_rewrite_range(guest_address, size, false, 0);
        return true;
    }
    return false;
}

static bool madeira_se_protect(uint64_t guest_address, uint64_t size,
                               uint32_t protection)
{
    if (size != 0 && guest_address + size >= guest_address) {
        if (!madeira_se_range_has_mapping(guest_address, size, protection,
                                          true)) {
            return false;
        }
        madeira_se_rewrite_range(guest_address, size, true, protection);
        return true;
    }
    return false;
}

static void madeira_se_unmap_all(void)
{
    while (madeira_se_mappings != NULL) {
        madeira_se_remove_mapping(&madeira_se_mappings);
    }
}

static void madeira_se_flush_translations(void)
{
    if (first_cpu != NULL) {
        tb_flush(first_cpu);
    }
}

static void madeira_se_invalidate_translations(uint64_t guest_address,
                                               uint64_t size)
{
    MadeiraSEQemuMapping *mapping;
    uint64_t range_end;

    if (size == 0 || guest_address + size < guest_address) {
        return;
    }
    range_end = guest_address + size;
    for (mapping = madeira_se_mappings; mapping != NULL;
         mapping = mapping->next) {
        if (madeira_se_range_overlaps(mapping->guest_address, mapping->size,
                                      guest_address, size) &&
            (!QEMU_IS_ALIGNED(mapping->guest_address, TARGET_PAGE_SIZE) ||
             !QEMU_IS_ALIGNED(mapping->size, TARGET_PAGE_SIZE))) {
            /*
             * SoftMMU gives code in a sub-page MemoryRegion a physical page
             * address of -1.  Those one-shot TBs are absent from the physical
             * page index and cannot be removed by tb_invalidate_phys_range().
             */
            madeira_se_flush_translations();
            return;
        }
    }
    for (mapping = madeira_se_mappings; mapping != NULL;
         mapping = mapping->next) {
        uint64_t mapping_end = mapping->guest_address + mapping->size;
        uint64_t overlap_start;
        uint64_t overlap_end;
        ram_addr_t ram_address;

        if (!madeira_se_range_overlaps(mapping->guest_address, mapping->size,
                                       guest_address, size)) {
            continue;
        }
        overlap_start = MAX(mapping->guest_address, guest_address);
        overlap_end = MIN(mapping_end, range_end);
        /*
         * Match get_page_addr_code_hostp(), which derives the TB page from
         * the backing host pointer.  A protection rewrite can temporarily
         * leave multiple RAMBlocks referring to slices of the same host
         * allocation, so using this MemoryRegion's block offset may name a
         * different page than the one recorded in the TB.
         */
        ram_address = qemu_ram_addr_from_host(
            (uint8_t *)mapping->host_address +
            (overlap_start - mapping->guest_address));
        if (ram_address == RAM_ADDR_INVALID) {
            continue;
        }
        tb_invalidate_phys_range(ram_address,
                                 ram_address + overlap_end - overlap_start - 1);
    }
}

static void madeira_se_import_xsave(X86CPU *cpu,
                                    const madeira_se_x86_context_t *context,
                                    uint8_t *buffer, uint32_t buffer_size)
{
    const ExtSaveArea *ymm = &x86_ext_save_areas[XSTATE_YMM_BIT];
    X86XSaveHeader *header;

    memcpy(buffer, context->fxsave, sizeof(context->fxsave));
    header = (X86XSaveHeader *)(buffer + sizeof(X86LegacyXSaveArea));
    header->xstate_bv = XSTATE_FP_MASK | XSTATE_SSE_MASK | XSTATE_YMM_MASK;
    if (ymm->offset != 0 && ymm->offset + sizeof(XSaveAVX) <= buffer_size) {
        XSaveAVX *avx = (XSaveAVX *)(buffer + ymm->offset);
        memcpy(avx->ymmh, context->ymm_hi, sizeof(context->ymm_hi));
    }
    x86_cpu_xrstor_all_areas(cpu, buffer, buffer_size);
}

static void madeira_se_export_xsave(X86CPU *cpu,
                                    madeira_se_x86_context_t *context,
                                    uint8_t *buffer, uint32_t buffer_size)
{
    const ExtSaveArea *ymm = &x86_ext_save_areas[XSTATE_YMM_BIT];

    x86_cpu_xsave_all_areas(cpu, buffer, buffer_size);
    memcpy(context->fxsave, buffer, sizeof(context->fxsave));
    if (ymm->offset != 0 && ymm->offset + sizeof(XSaveAVX) <= buffer_size) {
        const XSaveAVX *avx = (const XSaveAVX *)(buffer + ymm->offset);
        memcpy(context->ymm_hi, avx->ymmh, sizeof(context->ymm_hi));
    }
}

static void madeira_se_import_context(X86CPU *cpu,
                                      const madeira_se_x86_context_t *context,
                                      uint8_t *xsave_buffer,
                                      uint32_t xsave_buffer_size)
{
    static const X86Seg qemu_segments[MADEIRA_SE_X86_SEGMENT_COUNT] = {
        [MADEIRA_SE_X86_SEGMENT_CS] = R_CS,
        [MADEIRA_SE_X86_SEGMENT_SS] = R_SS,
        [MADEIRA_SE_X86_SEGMENT_DS] = R_DS,
        [MADEIRA_SE_X86_SEGMENT_ES] = R_ES,
        [MADEIRA_SE_X86_SEGMENT_FS] = R_FS,
        [MADEIRA_SE_X86_SEGMENT_GS] = R_GS,
    };
    CPUX86State *env = &cpu->env;
    unsigned int index;
    unsigned int code_flags;
    unsigned int data_flags = DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
        DESC_A_MASK | DESC_B_MASK | (3U << DESC_DPL_SHIFT);

    cpu_x86_update_cr0(env, (env->cr[0] | CR0_PE_MASK) & ~CR0_PG_MASK);
#ifdef TARGET_X86_64
    env->efer |= MSR_EFER_LME | MSR_EFER_LMA | MSR_EFER_SCE;
    env->hflags |= HF_LMA_MASK;
    code_flags = DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
        DESC_A_MASK | DESC_L_MASK | (3U << DESC_DPL_SHIFT);
#else
    code_flags = DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
        DESC_A_MASK | DESC_B_MASK | (3U << DESC_DPL_SHIFT);
#endif
    cpu_x86_update_cr4(env, env->cr[4] | CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK);

    for (index = 0; index < CPU_NB_REGS; ++index) {
        env->regs[index] = context->gpr[index];
    }
    env->eip = context->rip;
    cpu_load_eflags(env, (int)context->rflags, UINT32_MAX);
    for (index = 0; index < MADEIRA_SE_X86_SEGMENT_COUNT; ++index) {
        X86Seg segment = qemu_segments[index];
        unsigned int flags = segment == R_CS ? code_flags : data_flags;

        cpu_x86_load_seg_cache(env, segment, context->segment[index],
                               context->segment_base[index], UINT32_MAX,
                               flags);
    }
    for (index = 0; index < 8; ++index) {
        env->dr[index] = context->debug_register[index];
    }
    env->cr[2] = context->fault_address;
    madeira_se_import_xsave(cpu, context, xsave_buffer, xsave_buffer_size);
}

static void madeira_se_export_context(X86CPU *cpu,
                                      madeira_se_x86_context_t *context,
                                      uint8_t *xsave_buffer,
                                      uint32_t xsave_buffer_size)
{
    static const X86Seg qemu_segments[MADEIRA_SE_X86_SEGMENT_COUNT] = {
        [MADEIRA_SE_X86_SEGMENT_CS] = R_CS,
        [MADEIRA_SE_X86_SEGMENT_SS] = R_SS,
        [MADEIRA_SE_X86_SEGMENT_DS] = R_DS,
        [MADEIRA_SE_X86_SEGMENT_ES] = R_ES,
        [MADEIRA_SE_X86_SEGMENT_FS] = R_FS,
        [MADEIRA_SE_X86_SEGMENT_GS] = R_GS,
    };
    CPUX86State *env = &cpu->env;
    unsigned int index;

    for (index = 0; index < CPU_NB_REGS; ++index) {
        context->gpr[index] = env->regs[index];
    }
    context->rip = env->eip;
    context->rflags = cpu_compute_eflags(env);
    for (index = 0; index < MADEIRA_SE_X86_SEGMENT_COUNT; ++index) {
        const SegmentCache *segment = &env->segs[qemu_segments[index]];

        context->segment[index] = segment->selector;
        context->segment_base[index] = segment->base;
    }
    for (index = 0; index < 8; ++index) {
        context->debug_register[index] = env->dr[index];
    }
    context->fault_address = env->cr[2];
    madeira_se_export_xsave(cpu, context, xsave_buffer, xsave_buffer_size);
}

static void madeira_se_run_on_cpu(CPUState *cs, run_on_cpu_data data)
{
    MadeiraSERun *run = data.host_ptr;
    MadeiraSEQemuInstance *instance = run->instance;
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int64_t prepared_budget;
    int64_t remaining_budget;
    int cpu_result;
    bool reuse_context =
        (run->request->flags & MADEIRA_SE_CPU_RUN_REUSE_CONTEXT) != 0 &&
        madeira_se_context_instance == instance;

    if (qatomic_xchg(&instance->interrupted, false)) {
        madeira_se_context_instance = NULL;
        run->result->reason = MADEIRA_SE_CPU_EXIT_INTERRUPTED;
        return;
    }

    if (!reuse_context) {
        madeira_se_import_context(cpu, run->context, instance->xsave_buffer,
                                  instance->xsave_buffer_size);
    }
    cs->halted = false;
    cs->exception_index = -1;
    cs->madeira_se_user_mode = true;
    qatomic_set(&cs->exit_request, 0);
    qatomic_set(&cs->interrupt_request, 0);
    qatomic_set(&cs->neg.icount_decr.u16.high, 0);
    cs->madeira_se_syscall_dispatcher = run->request->syscall_dispatcher;
    cs->madeira_se_unix_call_dispatcher = run->request->unix_call_dispatcher;
    cs->madeira_se_dispatchers_enabled = true;

    qatomic_set(&madeira_se_active_instance, instance);
    bql_unlock();
    icount_prepare_for_run(cs, (int64_t)MIN(run->request->max_instructions,
                                            (uint64_t)INT64_MAX));
    prepared_budget = cs->icount_budget;
    do {
        cpu_result = cpu_exec(cs);
        if (cpu_result == EXCP_ATOMIC) {
            cpu_exec_step_atomic(cs);
        }
    } while (cpu_result == EXCP_ATOMIC);
    remaining_budget = cs->neg.icount_decr.u16.low + cs->icount_extra;
    run->result->instructions_executed =
        (uint64_t)MAX((int64_t)0, prepared_budget - remaining_budget);
    icount_process_data(cs);
    bql_lock();
    qatomic_cmpxchg(&madeira_se_active_instance, instance, NULL);
    cs->madeira_se_dispatchers_enabled = false;

    /* The bridge is a data-only sentinel (0x2ecd2ecd), not executable guest
     * code.  Classify the exact architectural RIP selected by the fast
     * dispatcher check above. */
    if (env->eip == run->request->syscall_dispatcher) {
        run->result->reason = MADEIRA_SE_CPU_EXIT_SYSCALL;
        run->result->service_number = env->regs[R_EAX];
    } else if (env->eip == run->request->unix_call_dispatcher) {
        run->result->reason = MADEIRA_SE_CPU_EXIT_UNIX_CALL;
        /*
         * The dispatcher was called as a function: the guest stack holds the
         * return address followed by Wine's struct guest_unix_call
         * { unixlib_handle, id, args }. The unixlib function index is what
         * identifies the service; %eax only holds whatever the caller left
         * behind. Fall back to the register so the exit is still recorded if
         * the stack is not mapped yet.
         */
        {
            uint32_t frame[3];
            uint32_t stack_pointer = (uint32_t)env->regs[R_ESP];

            if (madeira_se_read_guest(stack_pointer + sizeof(uint32_t),
                                      frame, sizeof(frame))) {
                run->result->service_number =
                    ((uint64_t)frame[0] << 32) | frame[1];
            } else {
                run->result->service_number = env->regs[R_EAX];
            }
        }
    } else if (cpu_result == EXCP_HLT || cpu_result == EXCP_HALTED) {
        run->result->reason = MADEIRA_SE_CPU_EXIT_HALT;
    } else if (cpu_result >= 0 && cpu_result < EXCP_INTERRUPT) {
        run->result->reason = MADEIRA_SE_CPU_EXIT_EXCEPTION;
        run->result->exception_vector = (uint32_t)cpu_result;
        run->result->exception_error_code = (uint32_t)env->error_code;
        run->result->fault_address = env->cr[2];
    } else if (qatomic_xchg(&instance->interrupted, false)) {
        run->result->reason = MADEIRA_SE_CPU_EXIT_INTERRUPTED;
    } else {
        run->result->reason = MADEIRA_SE_CPU_EXIT_BUDGET;
    }

    if (run->result->reason == MADEIRA_SE_CPU_EXIT_BUDGET) {
        madeira_se_context_instance = instance;
        if (reuse_context) {
            run->result->reserved[0] |= MADEIRA_SE_CPU_RESULT_CONTEXT_UNCHANGED;
        } else {
            madeira_se_export_context(cpu, run->context, instance->xsave_buffer,
                                      instance->xsave_buffer_size);
        }
    } else {
        madeira_se_context_instance = NULL;
        madeira_se_export_context(cpu, run->context, instance->xsave_buffer,
                                  instance->xsave_buffer_size);
    }

    if (instance->stats_enabled) {
        instance->stats_runs++;
        instance->stats_instructions += run->result->instructions_executed;
        if (run->result->reason <= MADEIRA_SE_CPU_EXIT_INTERRUPTED)
            instance->stats_reasons[run->result->reason]++;
    }
}

static int madeira_se_backend_create(void *userdata,
                                     madeira_se_architecture_t architecture,
                                     const madeira_se_memory_t *memory,
                                     void **out_instance)
{
    MadeiraSEQemuInstance *instance;

    (void)userdata;
    if (out_instance == NULL || memory == NULL || first_cpu == NULL ||
        !madeira_se_architecture_supported(architecture)) {
        return -1;
    }
    instance = g_new0(MadeiraSEQemuInstance, 1);
    instance->architecture = architecture;
    instance->memory = *memory;
    instance->xsave_buffer_size = xsave_area_size(UINT64_MAX, false);
    instance->xsave_buffer = g_malloc0(instance->xsave_buffer_size);
    if (instance->xsave_buffer == NULL) {
        g_free(instance);
        return -1;
    }
    instance->stats_enabled = getenv("MADEIRA_SE_CPU_STATS") != NULL;

    bql_lock();
    madeira_se_instance_count++;
    bql_unlock();
    *out_instance = instance;
    return 0;
}

static int madeira_se_backend_run(void *userdata, void *opaque,
                                  const madeira_se_cpu_run_request_t *request,
                                  madeira_se_x86_context_t *context,
                                  madeira_se_cpu_run_result_t *result)
{
    MadeiraSERun run = {
        .instance = opaque,
        .request = request,
        .context = context,
        .result = result,
        .status = 0,
    };

    (void)userdata;
    if (opaque == NULL || request == NULL || context == NULL || result == NULL ||
        request->max_instructions == 0 || request->max_instructions > INT64_MAX) {
        return -1;
    }
    bql_lock();
    if (((MadeiraSEQemuInstance *)opaque)->stats_enabled) {
        gint64 started = g_get_monotonic_time();
        run_on_cpu(first_cpu, madeira_se_run_on_cpu,
                   RUN_ON_CPU_HOST_PTR(&run));
        ((MadeiraSEQemuInstance *)opaque)->stats_dispatch_us +=
            (uint64_t)(g_get_monotonic_time() - started);
    } else {
        run_on_cpu(first_cpu, madeira_se_run_on_cpu,
                   RUN_ON_CPU_HOST_PTR(&run));
    }
    bql_unlock();
    return run.status;
}

static int madeira_se_backend_interrupt(void *userdata, void *opaque)
{
    MadeiraSEQemuInstance *instance = opaque;

    (void)userdata;
    if (instance == NULL) {
        return -1;
    }
    qatomic_set(&instance->interrupted, true);
    if (qatomic_read(&madeira_se_active_instance) == instance) {
        cpu_exit(first_cpu);
    }
    return 0;
}

static int madeira_se_backend_memory_event(void *userdata, void *opaque,
                                           madeira_se_cpu_memory_event_t event,
                                           uint64_t guest_address,
                                           uint64_t size,
                                           uint32_t protection)
{
    MadeiraSEQemuInstance *instance = opaque;
    int status = 0;
    bool mappings_changed = false;

    (void)userdata;
    if (instance == NULL) {
        return -1;
    }
    bql_lock();
    switch (event) {
    case MADEIRA_SE_CPU_MEMORY_MAP:
        status = madeira_se_map(instance, guest_address, size, protection,
                                &mappings_changed);
        break;
    case MADEIRA_SE_CPU_MEMORY_UNMAP:
        mappings_changed = madeira_se_unmap(guest_address, size);
        break;
    case MADEIRA_SE_CPU_MEMORY_PROTECT:
        mappings_changed = madeira_se_protect(guest_address, size, protection);
        break;
    case MADEIRA_SE_CPU_MEMORY_DIRTY:
        madeira_se_invalidate_translations(guest_address, size);
        break;
    default:
        status = -1;
        break;
    }
    if (status == 0 && mappings_changed) {
        madeira_se_flush_translations();
    }
    bql_unlock();
    return status;
}

static int madeira_se_backend_invalidate(void *userdata, void *opaque,
                                         uint64_t guest_address, uint64_t size)
{
    (void)userdata;
    if (opaque == NULL || size == 0 || guest_address + size < guest_address) {
        return -1;
    }
    bql_lock();
    madeira_se_invalidate_translations(guest_address, size);
    bql_unlock();
    return 0;
}

static void madeira_se_backend_perf_counters(
    void *userdata, void *opaque, madeira_se_cpu_perf_counters_t *out_counters)
{
    (void)userdata;
    (void)opaque;
    if (out_counters == NULL) {
        return;
    }
    memset(out_counters, 0, sizeof(*out_counters));
    out_counters->version = MADEIRA_SE_CPU_ABI_VERSION;
    madeira_se_tcti_perf_read(&out_counters->guest_instructions,
                              &out_counters->tb_entries,
                              &out_counters->tb_translations,
                              &out_counters->translated_instructions);
}

static void madeira_se_backend_destroy(void *userdata, void *opaque)
{
    MadeiraSEQemuInstance *instance = opaque;

    (void)userdata;
    if (instance == NULL) {
        return;
    }
    bql_lock();
    if (madeira_se_instance_count > 0) {
        madeira_se_instance_count--;
    }
    if (madeira_se_instance_count == 0) {
        madeira_se_unmap_all();
        madeira_se_flush_translations();
    }
    if (madeira_se_context_instance == instance) {
        madeira_se_context_instance = NULL;
    }
    bql_unlock();
    if (instance->stats_enabled) {
        fprintf(stderr,
                "MADEIRA_SE_CPU_STATS backend=%s runs=%" PRIu64
                " instructions=%" PRIu64 " dispatch_us=%" PRIu64
                " budget=%" PRIu64 " syscall=%" PRIu64
                " unix=%" PRIu64 " exception=%" PRIu64
                " halt=%" PRIu64 " interrupted=%" PRIu64 "\n",
                madeira_se_qemu_tcti_backend()->name, instance->stats_runs,
                instance->stats_instructions, instance->stats_dispatch_us,
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_BUDGET],
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_SYSCALL],
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_UNIX_CALL],
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_EXCEPTION],
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_HALT],
                instance->stats_reasons[MADEIRA_SE_CPU_EXIT_INTERRUPTED]);
    }
    g_free(instance->xsave_buffer);
    g_free(instance);
}

const madeira_se_cpu_backend_t *madeira_se_qemu_tcti_backend(void)
{
    static const madeira_se_cpu_backend_t backend = {
        .version = MADEIRA_SE_CPU_ABI_VERSION,
#ifdef TARGET_X86_64
        .name = "qemu-x86_64-tcti",
        .capabilities = MADEIRA_SE_CPU_CAP_NO_RUNTIME_CODEGEN |
                        MADEIRA_SE_CPU_CAP_X86_64,
#else
        .name = "qemu-i386-tcti",
        .capabilities = MADEIRA_SE_CPU_CAP_NO_RUNTIME_CODEGEN |
                        MADEIRA_SE_CPU_CAP_X86_32,
#endif
        .create = madeira_se_backend_create,
        .run = madeira_se_backend_run,
        .interrupt = madeira_se_backend_interrupt,
        .memory_event = madeira_se_backend_memory_event,
        .invalidate = madeira_se_backend_invalidate,
        .destroy = madeira_se_backend_destroy,
        .perf_counters = madeira_se_backend_perf_counters,
    };

    return &backend;
}

static void madeira_se_smoke_run_on_cpu(CPUState *cs, run_on_cpu_data data)
{
    MadeiraSESmokeRun *run = data.host_ptr;
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    const unsigned int code_flags = DESC_P_MASK | DESC_S_MASK |
        DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK | DESC_B_MASK;
    const unsigned int data_flags = DESC_P_MASK | DESC_S_MASK |
        DESC_W_MASK | DESC_A_MASK | DESC_B_MASK;

    cpu_x86_update_cr0(env, (env->cr[0] | CR0_PE_MASK) & ~CR0_PG_MASK);
    cpu_x86_load_seg_cache(env, R_CS, 0x08, 0, UINT32_MAX, code_flags);
    cpu_x86_load_seg_cache(env, R_SS, 0x10, 0, UINT32_MAX, data_flags);
    cpu_x86_load_seg_cache(env, R_DS, 0x10, 0, UINT32_MAX, data_flags);
    cpu_x86_load_seg_cache(env, R_ES, 0x10, 0, UINT32_MAX, data_flags);
    cpu_x86_load_seg_cache(env, R_FS, 0x10, 0, UINT32_MAX, data_flags);
    cpu_x86_load_seg_cache(env, R_GS, 0x10, 0, UINT32_MAX, data_flags);
    cpu_load_eflags(env, 0x2, UINT32_MAX);
    memset(env->regs, 0, sizeof(env->regs));
    env->eip = run->guest_address;
    env->cr[2] = 0;
    env->error_code = 0;
    cs->halted = false;
    cs->exception_index = -1;
    cs->madeira_se_user_mode = true;
    qatomic_set(&cs->exit_request, 0);
    qatomic_set(&cs->interrupt_request, 0);
    qatomic_set(&cs->neg.icount_decr.u16.high, 0);

    bql_unlock();
    icount_prepare_for_run(cs, 16);
    run->cpu_result = cpu_exec(cs);
    icount_process_data(cs);
    bql_lock();
    run->eax = env->regs[R_EAX];
    run->fault_address = env->cr[2];
    run->error_code = env->error_code;
}

int madeira_se_qemu_tcti_smoke(void)
{
    static const uint8_t guest_code[] = {
        0xb8, 0x12, 0x34, 0x56, 0x78,
        0xf4,
    };
    const uint64_t guest_address = 0x100000;
    MadeiraSESmokeRun run = {
        .guest_address = guest_address,
        .cpu_result = -1,
    };
    MemoryRegion region;
    uint8_t page[4096] = { 0 };

    if (first_cpu == NULL) {
        return -1;
    }
    memcpy(page, guest_code, sizeof(guest_code));

    bql_lock();
    memory_region_init_ram_ptr(&region, NULL, "madeira-se-smoke",
                               sizeof(page), page);
    memory_region_add_subregion(get_system_memory(), guest_address, &region);
    run_on_cpu(first_cpu, madeira_se_smoke_run_on_cpu,
               RUN_ON_CPU_HOST_PTR(&run));
    memory_region_del_subregion(get_system_memory(), &region);
    tb_flush(first_cpu);
    bql_unlock();

    if (run.cpu_result != EXCP_HLT || run.eax != 0x78563412) {
        fprintf(stderr, "Madeira-SE TCTI smoke mismatch: result=%#x eax=%#" PRIx64 "\n",
                run.cpu_result, run.eax);
        return -1;
    }

    run.guest_address = guest_address + sizeof(page);
    run.cpu_result = -1;
    run.fault_address = 0;
    run.error_code = 0;
    bql_lock();
    run_on_cpu(first_cpu, madeira_se_smoke_run_on_cpu,
               RUN_ON_CPU_HOST_PTR(&run));
    bql_unlock();
    if (run.cpu_result != EXCP0E_PAGE ||
        run.fault_address != run.guest_address ||
        run.error_code != (PG_ERROR_U_MASK | PG_ERROR_I_D_MASK)) {
        fprintf(stderr, "Madeira-SE unmapped fetch mismatch: result=%#x "
                "address=%#" PRIx64 " error=%#x\n", run.cpu_result,
                run.fault_address, run.error_code);
        return -1;
    }
    return 0;
}
