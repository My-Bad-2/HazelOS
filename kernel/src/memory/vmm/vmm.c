#include "memory/vmm.h"

#include "boot/boot.h"
#include "boot/limine.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/arch_mmu.h"
#include "memory/memory.h"
#include "memory/pagemap.h"

extern void vmm_map_kernel(pagemap_t* map, uintptr_t kernel_base, uintptr_t phys_base_delta);

static pagemap_t* kernel_pagemap = nullptr;
static uintptr_t highest_address = 0;

pagemap_t* vmm_get_kernel_pagemap() {
    return kernel_pagemap;
}

static void vmm_map_memory(pagemap_t* map) {
    if (!memmap_request.response || !memmap_request.response->entries) {
        KLOG_INIT_FAIL();
        PANIC("VMM: Limine memory map is missing\n");
    }

    size_t memmap_count                  = memmap_request.response->entry_count;
    struct limine_memmap_entry** memmaps = memmap_request.response->entries;

    for (size_t i = 0; i < memmap_count; ++i) {
        struct limine_memmap_entry* entry = memmaps[i];

        bool should_map    = false;
        cache_type_t cache = CACHE_WRITE_BACK;

        switch (entry->type) {
            case LIMINE_MEMMAP_USABLE:
            case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
            case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES:
                should_map = true;
                cache      = CACHE_WRITE_BACK;
                break;
            case LIMINE_MEMMAP_ACPI_RECLAIMABLE:
            case LIMINE_MEMMAP_ACPI_NVS:
            case LIMINE_MEMMAP_ACPI_TABLES:
                should_map = true;
                cache      = CACHE_ROM;
                break;
            case LIMINE_MEMMAP_FRAMEBUFFER:
                should_map = true;
                cache      = CACHE_FRAMEBUFFER;
                break;
            default:
                should_map = false;
                break;
        }

        if (!should_map) {
            continue;
        }

        uintptr_t phys_start = entry->base;
        uintptr_t phys_end   = entry->base + entry->length;

        phys_start = align_down(phys_start, PAGE_SIZE_SMALL);
        phys_end   = align_up(phys_end, PAGE_SIZE_SMALL);

        if (highest_address < phys_end) {
            highest_address = phys_end;
        }

        uintptr_t curr = phys_start;

        while (curr < phys_end) {
            uintptr_t remaining = phys_end - curr;

            pagemap_map_args_t args = {
                .flags      = VMM_FLAG_READ | VMM_FLAG_WRITE,
                .cache      = cache,
                .pkey       = 0,
                .skip_flush = true
            };

            if (is_aligned(curr, PAGE_SIZE_LARGE) && (remaining >= PAGE_SIZE_LARGE)) {
                args.page_size = PAGE_SIZE_LARGE;
                args.length    = PAGE_SIZE_LARGE;
            } else if (is_aligned(curr, PAGE_SIZE_MEDIUM) && (remaining >= PAGE_SIZE_MEDIUM)) {
                args.page_size = PAGE_SIZE_MEDIUM;
                args.length    = PAGE_SIZE_MEDIUM;
            } else {
                args.page_size = PAGE_SIZE_SMALL;
                args.length    = PAGE_SIZE_SMALL;
            }

            curr           = align_down(curr, args.page_size);
            uintptr_t virt = to_higher_half(curr);

            args.phys_addr = (void*)curr;
            args.virt_addr = (void*)virt;

            if (!pagemap_map(map, &args)) {
                KLOG_INIT_FAIL();
                PANIC(
                    "VMM: mapping failed virt=0x%lx phys=0x%lx size=0x%zx\n",
                    virt,
                    curr,
                    args.length
                );
            }

            curr += args.length;
        }
    }
}

void vmm_init(void) {
    KLOG_INIT_START("Virtual Memory Manager");
    kernel_pagemap = pagemap_create();

    uintptr_t kernel_base = (uintptr_t)kernel_file_request.response->executable_file->address;

    uintptr_t phys_base  = kernel_address_request.response->physical_base;
    uintptr_t virt_base  = kernel_address_request.response->virtual_base;
    uintptr_t phys_delta = phys_base - virt_base;

    arch_mmu_init();
    vmm_map_memory(kernel_pagemap);
    vmm_map_kernel(kernel_pagemap, kernel_base, phys_delta);
    pagemap_load(kernel_pagemap);
    KLOG_INIT_OK();
}

const uintptr_t get_kernel_space_start_limit(void) {
    return align_up(to_higher_half(highest_address), PAGE_SIZE_LARGE);
}