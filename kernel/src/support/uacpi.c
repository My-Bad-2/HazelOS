#include <uacpi/kernel_api.h>
#include <uacpi/status.h>

#include "boot/boot.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"
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

    vm_object_t* vmo = vm_object_create(VM_OBJ_ANONYMOUS, total_size);

    void* virt = vmalloc(
        kernel_space,
        0,
        total_size,
        VMM_FLAG_MMIO | VMM_FLAG_DEMAND,
        CACHE_MMIO,
        PAGE_SIZE_SMALL,
        vmo,
        0
    );

    vm_object_deref(vmo);

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