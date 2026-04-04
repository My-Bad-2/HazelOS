#include <stdatomic.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/lapic.h"
#include "cpu/smp.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"

struct tlb_shootdown_data {
    arch_pagemap_t* map;
    uintptr_t vaddr;
    size_t pages;
    atomic_size_t ack_count;
};

static struct tlb_shootdown_data current_shootdown;
static qspinlock_t tlb_lock;

void smp_tlb_shootdown(arch_pagemap_t* map, uintptr_t vaddr, size_t pages) {
    if (unlikely(!smp_is_initialized())) return;
    acquire_qspinlock(&tlb_lock);

    current_shootdown.map   = map;
    current_shootdown.vaddr = vaddr;
    current_shootdown.pages = pages;

    atomic_store(&current_shootdown.ack_count, 0);

    lapic_send_broadcast_ipi(INTERRUPT_IPI_TLB, DELIVERY_MODE_FIXED);

    size_t expected_acks = mp_request.response->cpu_count - 1;
    while (atomic_load(&current_shootdown.ack_count) < expected_acks) arch_pause();

    release_qspinlock(&tlb_lock);
}

irq_return_t ipi_tlb_shootdown_handler(interrupt_trapframe_t*, void*) {
    arch_mmu_flush_local(
        current_shootdown.map,
        current_shootdown.vaddr,
        current_shootdown.pages,
        smp_current_core_idx()
    );

    atomic_fetch_add(&current_shootdown.ack_count, 1);
    return IRQ_HANDLED;
}