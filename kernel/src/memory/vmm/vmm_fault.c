#include <stdint.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pmm.h"
#include "memory/vma.h"

#include "../internal/vma_tree.h"

bool vmm_handle_fault(vm_space_t* space, uintptr_t fault_addr, uint32_t error_code) {
    struct vmm_fault_info info = arch_decode_fault_error(error_code);

    acquire_read(&space->lock);

    vm_area_t* vma = atomic_load_explicit(&space->cached_vma, memory_order_acquire);
    if (!vma || fault_addr < vma->start || fault_addr >= vma->end) {
        vma = vmm_find_vma_unsafe(space, fault_addr);
        if (vma) {
            atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
        }
    }

    if (!vma) {
        release_read(&space->lock);
        return false;
    }

    if (vma->flags & VMM_FLAG_GUARD) {
        KLOG_WARN("VMM: Stack overflow detected at %p", (void*)fault_addr);
        release_read(&space->lock);
        return false;
    }

    if (info.is_user && !(vma->flags & VMM_FLAG_USER)) {
        goto segfault;
    }
    if (info.is_exec && !(vma->flags & VMM_FLAG_EXECUTE)) {
        goto segfault;
    }
    if (info.is_write && !(vma->flags & VMM_FLAG_WRITE)) {
        goto segfault;
    }

    uintptr_t aligned_addr = align_down(fault_addr, vma->page_size);
    size_t frames_needed   = vma->page_size / PAGE_SIZE_SMALL;

    // Case A: Demand paging
    if (!info.is_present) {
        void* phys = pmm_alloc(frames_needed);
        if (!phys) {
            KLOG_ERROR("VMM: OOM during demand paging at %p", (void*)fault_addr);
            release_read(&space->lock);
            return false;
        }

        pmm_inc_ref(phys);

        uint32_t pte_flags = vma->flags;
        if (vma->flags & VMM_FLAG_COW) {
            pte_flags &= ~VMM_FLAG_WRITE;
        }

        pagemap_map_args_t args = {
            .virt_addr = (void*)aligned_addr,
            .phys_addr = phys,
            .length    = vma->page_size,
            .flags     = pte_flags,
            .cache     = vma->cache,
            .page_size = vma->page_size,
        };

        if (!pagemap_map(space->map, &args)) {
            pmm_dec_ref(phys);
            pmm_free(phys);
            release_read(&space->lock);
            return false;
        }

        memset((void*)aligned_addr, 0, vma->page_size);
        release_read(&space->lock);
        return true;
    }

    // Case B: Copy-On-Write
    if (info.is_present && info.is_write && (vma->flags & VMM_FLAG_COW)) {
        uintptr_t old_phys = pagemap_translate(space->map, aligned_addr);
        if (!old_phys) {
            KLOG_ERROR("VMM: COW state corrupted at %p", (void*)fault_addr);
            release_read(&space->lock);
            return false;
        }

        // Exclusive Owner Reuse
        if (pmm_get_ref((void*)old_phys) == 1) {
            vma->flags &= ~VMM_FLAG_COW;

            pagemap_protect_args_t prot_args = {
                .virt_addr = (void*)aligned_addr,
                .flags     = vma->flags,
            };
            pagemap_protect(space->map, &prot_args);

            release_read(&space->lock);
            return true;
        }

        // Duplicate for shared owners
        void* new_phys = pmm_alloc(frames_needed);
        if (!new_phys) {
            release_read(&space->lock);
            return false;
        }

        pmm_inc_ref(new_phys);

        void* src_ptr = (void*)to_higher_half((uintptr_t)old_phys);
        void* dst_ptr = (void*)to_higher_half((uintptr_t)new_phys);
        memcpy(dst_ptr, src_ptr, vma->page_size);

        vma->flags &= ~VMM_FLAG_COW;

        pagemap_map_args_t map_args = {
            .virt_addr = (void*)aligned_addr,
            .phys_addr = new_phys,
            .length    = vma->page_size,
            .flags     = vma->flags,
            .cache     = vma->cache,
            .page_size = vma->page_size,
        };

        pagemap_map(space->map, &map_args);
        pmm_dec_ref((void*)old_phys);

        release_read(&space->lock);
        return true;
    }

segfault:
    release_read(&space->lock);
    return false;
}