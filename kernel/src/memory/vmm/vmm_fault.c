#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "libs/log.h"
#include "libs/math.h"
#include "memory/memory.h"
#include "memory/vm_object.h"
#include "memory/vma.h"

#include "../internal/vma_tree.h"

bool vmm_handle_fault(struct vm_space* space, uintptr_t fault_addr, uint32_t error_code) {
    struct vmm_fault_info info = arch_decode_fault_error(error_code);

    acquire_read(&space->lock);

    struct vm_area* vma = atomic_load_explicit(&space->cached_vma, memory_order_acquire);
    if (unlikely(!vma || fault_addr < vma->start || fault_addr >= vma->end)) {
        vma = vmm_find_vma_unsafe(space, fault_addr);
        if (likely(vma)) atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
    }

    if (unlikely(!vma)) goto unhandled_fault;
    if (unlikely(vma->flags & VMM_FLAG_GUARD)) goto unhandled_fault;
    if (unlikely(info.is_user && !(vma->flags & VMM_FLAG_USER))) goto segfault;
    if (unlikely(info.is_exec && !(vma->flags & VMM_FLAG_EXECUTE))) goto segfault;
    if (unlikely(info.is_write && !(vma->flags & VMM_FLAG_WRITE))) goto segfault;
    if (unlikely(!space->map)) goto unhandled_fault;

    uintptr_t map_page_size = vma_page_size(vma);
    uintptr_t aligned_addr  = align_down(fault_addr, map_page_size);
    size_t object_offset    = vma->object_offset + (aligned_addr - vma->start);
    uintptr_t phys          = 0;

    // 1. Transparent Huge Page (THP) Promotion Attempt First!
    uintptr_t huge_vaddr = align_down(fault_addr, PAGE_SIZE_MEDIUM);
    size_t huge_offset   = vma->object_offset + (huge_vaddr - vma->start);

    // Only attempt THP if the base VMA uses 4K pages and fits a 2MB block
    if (vma->page_shift == PAGE_SHIFT_SMALL && vma->object &&
        vma->object->type == VM_OBJ_ANONYMOUS && huge_vaddr >= vma->start &&
        (huge_vaddr + PAGE_SIZE_MEDIUM) <= vma->end) {
        uintptr_t huge_phys = vm_object_get_huge_page(vma->object, huge_offset, info.is_write);

        if (huge_phys) {
            phys          = huge_phys;
            aligned_addr  = huge_vaddr;
            map_page_size = PAGE_SIZE_MEDIUM;
        }
    }

    if (likely(!phys)) {
        phys = vm_object_get_page(vma->object, object_offset, true, info.is_write);

        if (unlikely(!phys)) {
            KLOG_ERROR("VMM: Failed to resolve page fault at %p (OOM or VFS Error)", fault_addr);
            goto unhandled_fault;
        }
    }

    uint32_t pte_flags = vma->flags;
    // Enforce Read-Only faults on COW pages until they are duplicated by the object
    if (unlikely((vma->flags & VMM_FLAG_COW) && !info.is_write)) pte_flags &= ~VMM_FLAG_WRITE;

    pagemap_unmap_args_t unmap_args = {
        .virt_addr = (void*)aligned_addr,
        .length    = map_page_size,
        .free_phys = false,
    };

    pagemap_unmap(space->map, &unmap_args);

    pagemap_map_args_t args = {
        .virt_addr = (void*)aligned_addr,
        .phys_addr = (void*)phys,
        .length    = map_page_size,
        .flags     = pte_flags | VMM_FLAG_FIXED,
        .cache     = vma->cache,
        .page_size = map_page_size,
    };

    if (unlikely(!pagemap_map(space->map, &args))) goto unhandled_fault;
    if (unlikely(vma->object && vma->object->type == VM_OBJ_SHADOW))
        vm_object_collapse(vma->object);

    release_read(&space->lock);
    return true;

segfault:
unhandled_fault:
    release_read(&space->lock);
    return false;
}