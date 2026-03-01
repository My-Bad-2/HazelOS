#include <stdint.h>
#include <string.h>

#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/vm_object.h"
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
    size_t object_offset   = vma->object_offset + (aligned_addr - vma->start);

    uintptr_t phys       = vm_object_get_page(vma->object, object_offset, true, info.is_write);
    size_t map_page_size = vma->page_size;

    // Transparent Huge page promotion attempt
    // Essentially, merge 512 4KB entries into a single 2MB entry
    uintptr_t huge_vaddr = align_down(fault_addr, PAGE_SIZE_MEDIUM);
    size_t huge_offset   = vma->object_offset + (huge_vaddr - vma->start);

    if (vma->page_size == PAGE_SIZE_SMALL && vma->object && vma->object->type == VM_OBJ_ANONYMOUS &&
        huge_vaddr >= vma->start && (huge_vaddr + PAGE_SIZE_MEDIUM) <= vma->end) {
        phys = vm_object_get_huge_page(vma->object, huge_offset, info.is_write);

        if (phys) {
            aligned_addr  = huge_vaddr;
            map_page_size = PAGE_SIZE_MEDIUM;
        }
    }

    if (!phys) {
        KLOG_ERROR("VMM: Failed to resolve page fault at %p (OOM or VFS Error)", (void*)fault_addr);
        release_read(&space->lock);
        return false;
    }

    uint32_t pte_flags = vma->flags;

    if ((vma->flags & VMM_FLAG_COW) && !info.is_write) {
        pte_flags &= ~VMM_FLAG_WRITE;
    }

    pagemap_map_args_t args = {
        .virt_addr = (void*)aligned_addr,
        .phys_addr = (void*)phys,
        .length    = vma->page_size,
        .flags     = pte_flags,
        .cache     = vma->cache,
        .page_size = vma->page_size,
    };

    if (!pagemap_map(space->map, &args)) {
        KLOG_ERROR("VMM: Hardware MMU mapping failed at %p", (void*)aligned_addr);
        release_read(&space->lock);
        return false;
    }

    if (vma->object && vma->object->type == VM_OBJ_SHADOW) {
        vm_object_collapse(vma->object);
    }

    release_read(&space->lock);
    return true;

segfault:
    release_read(&space->lock);
    return false;
}