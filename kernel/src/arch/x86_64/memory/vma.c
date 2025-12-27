#include "memory/vma.h"

#include <string.h>

#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/pmm.h"

extern uintptr_t shared_zero_page;

bool vmm_handle_fault(vm_space_t* space, uintptr_t addr, uint32_t error_code) {
    acquire_interrupt_lock(&space->lock);

    bool is_present = error_code & X86_PAGE_FAULT_PRESENT;
    bool is_write   = error_code & X86_PAGE_FAULT_WRITE;
    bool is_user    = error_code & X86_PAGE_FAULT_USER;

    vm_area_t* vma = vmm_find_vma(space, addr);

    if (!vma) {
        release_interrupt_lock(&space->lock);
        return false;
    }

    if (is_write && !(vma->flags & VMM_FLAG_WRITE)) {
        release_interrupt_lock(&space->lock);
        return false;
    }

    if (is_user && !(vma->flags & VMM_FLAG_USER)) {
        release_interrupt_lock(&space->lock);
        return false;
    }

    uintptr_t page_base  = align_down(addr, vma->page_size);
    size_t frames_needed = vma->page_size / PAGE_SIZE_SMALL;

    if (!is_present) {
        void* phys = pmm_alloc_aligned(vma->page_size, frames_needed);

        if (!phys) {
            release_interrupt_lock(&space->lock);
            return false;
        }

        pagemap_map_args_t margs = {
            .virt_addr  = (void*)page_base,
            .phys_addr  = (void*)phys,
            .page_size  = (uint32_t)vma->page_size,
            .length     = vma->page_size,
            .flags      = vma->flags,
            .pkey       = 0,
            .skip_flush = false,
        };

        if (!pagemap_map(space->map, margs)) {
            pmm_free(phys, frames_needed);
            release_interrupt_lock(&space->lock);
            return false;
        }

        memset((void*)to_higher_half((uintptr_t)phys), 0, vma->page_size);

        release_interrupt_lock(&space->lock);
        return true;
    }

    // Handle Copy-on-Write
    if (is_present && is_write) {
        size_t flags = pagemap_get_flags(space->map, page_base);

        if ((vma->flags & VMM_FLAG_WRITE) && !(flags & X86_PAGE_FLAG_WRITE)) {
            if (vma->flags & VMM_FLAG_SHARED) {
                release_interrupt_lock(&space->lock);
                return false;
            }

            uintptr_t old_phys = pagemap_translate(space->map, page_base);
            uint32_t ref_count = pmm_get_ref((void*)old_phys);

            if (ref_count == 1 && old_phys != shared_zero_page) {
                pagemap_protect_args_t pargs = {
                    .virt_addr = (void*)page_base,
                    .flags     = vma->flags | VMM_FLAG_WRITE,
                    .cache     = vma->cache,
                };

                pagemap_protect(space->map, pargs);

                release_interrupt_lock(&space->lock);
                return true;
            }

            void* new_phys = pmm_alloc_aligned(vma->page_size, frames_needed);
            if (!new_phys) {
                release_interrupt_lock(&space->lock);
                return false;  // OOM
            }

            if (old_phys == shared_zero_page) {
                memset((void*)to_higher_half((uintptr_t)new_phys), 0, vma->page_size);
            } else {
                memcpy(
                    (void*)to_higher_half((uintptr_t)new_phys),
                    (void*)to_higher_half((uintptr_t)old_phys),
                    vma->page_size
                );
            }

            pmm_dec_ref((void*)old_phys);

            pagemap_map_args_t margs = {
                .virt_addr  = (void*)page_base,
                .phys_addr  = new_phys,
                .page_size  = (uint32_t)vma->page_size,
                .length     = vma->page_size,
                .flags      = vma->flags | VMM_FLAG_WRITE,
                .skip_flush = false,
            };

            pagemap_map(space->map, margs);
            release_interrupt_lock(&space->lock);
            return true;
        }
    }

    release_interrupt_lock(&space->lock);
    return false;
}