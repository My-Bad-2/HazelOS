#include <uacpi/kernel_api.h>
#include <uacpi/status.h>

#include "boot/boot.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"
#include "memory/vmm.h"

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr* out_rsdp_address) {
    if (!rsdp_request.response) {
        PANIC("UACPI: RSDP not found!");
        return UACPI_STATUS_NOT_FOUND;
    }

    pagemap_t* kernel_pagemap = vmm_get_kernel_pagemap();

    uintptr_t rsdp_virt = (uintptr_t)rsdp_request.response->address;
    uintptr_t rsdp_phys = pagemap_translate(kernel_pagemap, rsdp_virt);

    if (!rsdp_phys) {
        PANIC("UACPI: RSDP not mapped!");
        return UACPI_STATUS_NOT_FOUND;
    }

    *out_rsdp_address = rsdp_phys;
    return UACPI_STATUS_OK;
}

void* uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    if (len == 0) {
        return nullptr;
    }

    uacpi_size offset = addr & (PAGE_SIZE_SMALL - 1);
    addr              = align_down(addr, PAGE_SIZE_SMALL);

    uacpi_size total_size = len + offset;
    total_size            = align_up(total_size, PAGE_SIZE_SMALL);

    void* virt = vmalloc(
        kernel_space,
        0,
        total_size,
        VMM_FLAG_MMIO | VMM_FLAG_DEMAND,
        CACHE_MMIO,
        PAGE_SIZE_SMALL
    );

    if (!virt) {
        return nullptr;
    }

    cache_type_t cache        = CACHE_WRITE_BACK;
    uint32_t flags            = VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL;
    pagemap_t* kernel_pagemap = vmm_get_kernel_pagemap();

    pagemap_map_args_t args = {
        .virt_addr = virt,
        .phys_addr = (void*)addr,
        .length    = total_size,
        .flags     = flags,
        .cache     = cache,
        .page_size = PAGE_SIZE_SMALL,
    };

    if (!pagemap_map(kernel_pagemap, &args)) {
        PANIC("UACPI: Failed to map UACPI address 0x%016lx -> %p\n", addr, virt);
    }

    return (void*)((uintptr_t)virt + offset);
}

void uacpi_kernel_unmap(void* addr, uacpi_size len) {
    if (len == 0 || addr == nullptr) {
        return;
    }

    uintptr_t virt_addr       = (uintptr_t)addr;
    uacpi_size offset         = virt_addr & (PAGE_SIZE_SMALL - 1);
    pagemap_t* kernel_pagemap = vmm_get_kernel_pagemap();

    virt_addr = align_down(virt_addr, PAGE_SIZE_SMALL);
    len       = align_up(len, PAGE_SIZE_SMALL);

    pagemap_unmap_args_t args = {
        .virt_addr = (void*)virt_addr,
        .length    = len,
        .free_phys = false,
    };

    pagemap_unmap(kernel_pagemap, &args);
}

void uacpi_kernel_log(uacpi_log_level lvl, const uacpi_char* fmt) {
    switch (lvl) {
        case UACPI_LOG_ERROR:
            KLOG_ERROR(fmt);
            break;
        case UACPI_LOG_WARN:
            KLOG_WARN(fmt);
            break;
        case UACPI_LOG_INFO:
            KLOG_INFO(fmt);
            break;
        case UACPI_LOG_TRACE:
            KLOG_TRACE(fmt);
            break;
        case UACPI_LOG_DEBUG:
            KLOG_DEBUG(fmt);
            break;
    }
}

void* uacpi_kernel_alloc(uacpi_size size) {
    return kmalloc(size);
}

void uacpi_kernel_free(void* mem, uacpi_size len) {
    kfree(mem);
}

uacpi_handle uacpi_kernel_create_mutex() {
    interrupt_lock_t* lock = kmalloc(sizeof(interrupt_lock_t));
    create_interrupt_lock(lock);
    return lock;
}

void uacpi_kernel_free_mutex(uacpi_handle lock) {
    kfree(lock);
}

uacpi_handle uacpi_kernel_create_spinlock() {
    spinlock_t* lock = kmalloc(sizeof(spinlock_t));
    create_spinlock(lock);
    return lock;
}

void uacpi_kernel_free_spinlock(uacpi_handle lock) {
    kfree(lock);
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle lock, uacpi_u16) {
    acquire_interrupt_lock((interrupt_lock_t*)lock);
    return UACPI_STATUS_OK;
}

void uacpi_kernel_release_mutex(uacpi_handle lock) {
    release_interrupt_lock((interrupt_lock_t*)lock);
}
