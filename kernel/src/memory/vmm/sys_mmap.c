#include <errno.h>

#include "libs/math.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

#include "../internal/vma_tree.h"

static uint32_t sys_prot_to_vmm(int prot) {
    uint32_t ret = VMM_FLAG_USER;

    if (prot == PROT_NONE) {
        return ret;
    }

    if (prot & PROT_READ) {
        ret |= VMM_FLAG_READ;
    }

    if (prot & PROT_WRITE) {
        ret |= VMM_FLAG_WRITE;
    }

    if (prot & PROT_EXEC) {
        ret |= VMM_FLAG_EXECUTE;
    }

    return ret;
}

static uint32_t sys_flags_to_vmm(int prot, int flags) {
    uint32_t ret = sys_prot_to_vmm(prot);

    if (flags & MAP_SHARED) {
        ret |= VMM_FLAG_SHARED;
    }

    if (flags & MAP_PRIVATE) {
        ret |= VMM_FLAG_PRIVATE;
    }

    if (flags & MAP_FIXED) {
        ret |= VMM_FLAG_FIXED;
    }

    if (flags & MAP_FIXED_NOREPLACE) {
        ret |= (VMM_FLAG_FIXED | VMM_FLAG_FIXED_NOREPLACE);
    }

    if (flags & MAP_LOCKED) {
        ret |= VMM_FLAG_LOCKED;
    }

    if ((flags & MAP_GROWSDOWN) || (flags & MAP_STACK)) {
        ret |= VMM_FLAG_STACK;
    }

    if (flags & MAP_POPULATE) {
        ret |= VMM_FLAG_POPULATE;
    } else if (flags & MAP_ANONYMOUS) {
        ret |= VMM_FLAG_DEMAND;
    }

    return ret;
}

static size_t get_page_size_from_flags(int flags) {
    if (!(flags & MAP_HUGETLB)) {
        return PAGE_SIZE_SMALL;
    }

    uint32_t huge_page_code = (flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK;
    return (huge_page_code == 0) ? PAGE_SIZE_MEDIUM : (1ul << huge_page_code);
}

void* sys_mmap(vm_space_t* space, void* addr, size_t length, int prot, int flags, int fd, long) {
    if (!length || !space) {
        return (void*)-EINVAL;
    }

    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE)) {
        return (void*)-EINVAL;
    }

    if (!(flags & MAP_SHARED) && !(flags & MAP_PRIVATE)) {
        return (void*)-EINVAL;
    }

    size_t page_size = get_page_size_from_flags(flags);

    if (page_size != PAGE_SIZE_SMALL && page_size != PAGE_SIZE_MEDIUM &&
        page_size != PAGE_SIZE_LARGE) {
        return (void*)-EINVAL;
    }

    size_t aligned_length = align_up(length, page_size);

    if (aligned_length < length) {
        return (void*)-ENOMEM;
    }

    if ((flags & MAP_FIXED) || (flags & MAP_FIXED_NOREPLACE)) {
        if (!addr || !is_aligned((uintptr_t)addr, page_size)) {
            return (void*)-EINVAL;
        }
    } else if (addr && !is_aligned((uintptr_t)addr, page_size)) {
        addr = nullptr;
    }

    if ((flags & MAP_FIXED) && !(flags & MAP_FIXED_NOREPLACE)) {
        sys_munmap(space, addr, aligned_length);
    }

    uint32_t vma_flags = sys_flags_to_vmm(prot, flags);
    cache_type_t cache = CACHE_WRITE_BACK;

    if (!(flags & MAP_ANONYMOUS)) {
        if (fd < 0) {
            return (void*)-EBADF;
        }

        vma_flags &= ~VMM_FLAG_DEMAND;
    }

    void* mapped_addr = vmalloc(space, addr, aligned_length, vma_flags, cache, page_size);

    if (!mapped_addr) {
        if (flags & MAP_FIXED_NOREPLACE) {
            return (void*)-EEXIST;
        }

        return (void*)-ENOMEM;
    }

    return mapped_addr;
}

int sys_munmap(vm_space_t* space, void* addr, size_t length) {
    if (!space || !addr || length == 0) {
        return -EINVAL;
    }

    uintptr_t start = (uintptr_t)addr;
    if (!is_aligned(start, PAGE_SIZE_SMALL)) {
        return -EINVAL;
    }

    size_t aligned_length = align_up(length, PAGE_SIZE_SMALL);

    vmfree(space, (void*)start, aligned_length);
    return 0;
}

int sys_mprotect(vm_space_t* space, void* addr, size_t length, int prot) {
    if (!space || !addr || length == 0) {
        return -EINVAL;
    }

    uintptr_t start = (uintptr_t)addr;
    if (!is_aligned(start, PAGE_SIZE_SMALL)) {
        return -EINVAL;
    }

    uintptr_t end           = start + align_up(length, PAGE_SIZE_SMALL);
    uint32_t new_prot_flags = sys_prot_to_vmm(prot);

    uint32_t perm_mask = ~(VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_EXECUTE);

    acquire_write(&space->lock);

    uintptr_t current = start;
    while (current < end) {
        vm_area_t* vma = vmm_find_vma_unsafe(space, current);

        if (!vma) {
            release_write(&space->lock);
            return -ENOMEM;
        }

        if (current > vma->start) {
            vma = vmm_split_vma(space, vma, current);
            if (!vma) {
                release_write(&space->lock);
                return -ENOMEM;
            }
        }

        if (end < vma->end) {
            vm_area_t* right_half = vmm_split_vma(space, vma, end);
            if (!right_half) {
                release_write(&space->lock);
                return -ENOMEM;
            }
        }

        vma->flags = (vma->flags & perm_mask) | (new_prot_flags & ~perm_mask);

        if (!(vma->flags & VMM_FLAG_DEMAND)) {
            uint32_t pte_flags = vma->flags;

            if (vma->flags & VMM_FLAG_COW) {
                pte_flags &= ~VMM_FLAG_WRITE;
            }

            pagemap_protect_args_t prot_args = {
                .virt_addr = (void*)vma->start,
                .flags     = pte_flags,
                .cache     = vma->cache,
            };

            for (uintptr_t p = vma->start; p < vma->end; p += vma->page_size) {
                prot_args.virt_addr = (void*)p;
                pagemap_protect(space->map, &prot_args);
            }
        }

        uintptr_t next_addr = vma->end;

        rb_erase_augmented(&vma->rb_node, &space->rb_root, vma_compute_subtree_gap);

        if (vmm_try_merge(space, vma->start, vma->size, vma->flags, vma->cache, vma->page_size)) {
            kmem_cache_free(vma_cache, vma);
        } else {
            vmm_insert_vma(space, vma);
        }

        current = next_addr;
    }

    atomic_store_explicit(&space->cached_vma, nullptr, memory_order_relaxed);

    release_write(&space->lock);
    return 0;
}

void* sys_mremap(
    vm_space_t* space,
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address
) {
    if (!space || !old_address || old_size == 0 || new_size == 0) {
        return (void*)-EINVAL;
    }

    if ((flags & MREMAP_DONTUNMAP) && !(flags & MREMAP_MAYMOVE)) {
        return (void*)-EINVAL;
    }

    if (flags & MREMAP_FIXED) {
        if (!(flags & MREMAP_MAYMOVE)) {
            return (void*)-EINVAL;
        }

        if (!new_address || !is_aligned((uintptr_t)new_address, PAGE_SIZE_SMALL)) {
            return (void*)-EINVAL;
        }
    }

    uintptr_t old_addr = (uintptr_t)old_address;
    if (!is_aligned(old_addr, PAGE_SIZE_SMALL)) {
        return (void*)-EINVAL;
    }

    old_size = align_up(old_size, PAGE_SIZE_SMALL);
    new_size = align_up(new_size, PAGE_SIZE_SMALL);

    if (old_size == new_size && !(flags & MREMAP_DONTUNMAP)) {
        return old_address;
    }

    if (new_size < old_size && !(flags & MREMAP_DONTUNMAP)) {
        size_t shrink_diff = old_size - new_size;
        sys_munmap(space, (void*)(old_addr + new_size), shrink_diff);
        return old_address;
    }

    acquire_write(&space->lock);

    vm_area_t* vma = vmm_find_vma_unsafe(space, old_addr);

    if (!vma || vma->start != old_addr || vma->size != old_size) {
        release_write(&space->lock);
        return (void*)-EFAULT;
    }

    if (!(flags & MREMAP_DONTUNMAP)) {
        size_t extra_size         = new_size - old_size;
        struct rb_node* next_node = rb_next(&vma->rb_node);
        uintptr_t next_start =
            next_node ? rb_entry(next_node, vm_area_t, rb_node)->start : space->end_limit;

        if (vma->end + extra_size <= next_start) {
            if (vmm_map_range(
                    space,
                    vma->end,
                    extra_size,
                    vma->page_size,
                    vma->flags,
                    vma->cache
                )) {
                vma->end += extra_size;
                vma->size = new_size;

                if (next_node) {
                    vm_area_t* next_vma = rb_entry(next_node, vm_area_t, rb_node);
                    next_vma->own_gap   = next_vma->start - vma->end;
                    vma_propagate_gap_up(&next_vma->rb_node);
                }

                vma_propagate_gap_up(&vma->rb_node);

                atomic_store_explicit(&space->cached_vma, vma, memory_order_relaxed);
                release_write(&space->lock);
                return old_address;
            }
        }
    }

    if (!(flags & MREMAP_MAYMOVE)) {
        release_write(&space->lock);
        return (void*)-ENOMEM;
    }

    uint32_t vma_flags       = vma->flags;
    cache_type_t vma_caching = vma->cache;
    size_t vma_page_size     = vma->page_size;

    release_write(&space->lock);

    uint32_t alloc_flags = vma_flags | ((flags & MREMAP_FIXED) ? VMM_FLAG_FIXED : 0);

    void* new_addr_ptr = vmalloc(
        space,
        new_address,
        new_size,
        alloc_flags | VMM_FLAG_DEMAND,
        vma_caching,
        vma_page_size
    );

    if (!new_addr_ptr) {
        return (void*)-ENOMEM;
    }

    uintptr_t new_start = (uintptr_t)new_addr_ptr;

    acquire_write(&space->lock);

    vma = vmm_find_vma_unsafe(space, old_addr);

    if (!vma || vma->start != old_addr || vma->size != old_size) {
        release_write(&space->lock);
        vmfree(space, new_addr_ptr, new_size);
        return (void*)-EAGAIN;
    }

    uintptr_t current_old = old_addr;
    uintptr_t current_new = new_start;

    while (current_old < old_addr + old_size) {
        uintptr_t phys = pagemap_translate(space->map, current_old);

        if (phys) {
            pagemap_unmap_args_t unmap_args = {
                .virt_addr = (void*)current_old,
                .length    = vma_page_size,
                .free_phys = false,
            };

            pagemap_unmap(space->map, &unmap_args);

            uint32_t pte_flags = vma_flags;
            if (vma_flags & VMM_FLAG_COW) {
                pte_flags &= ~VMM_FLAG_WRITE;
            }

            pagemap_map_args_t map_args = {
                .virt_addr = (void*)current_new,
                .phys_addr = (void*)phys,
                .length    = vma_page_size,
                .flags     = pte_flags,
                .cache     = vma_caching,
                .page_size = vma_page_size,
            };

            pagemap_map(space->map, &map_args);
        }

        current_old += vma_page_size;
        current_new += vma_page_size;
    }

    if (new_size > old_size) {
        size_t extra_size = new_size - old_size;

        if (!vmm_map_range(
                space,
                new_start + old_size,
                extra_size,
                vma_page_size,
                vma_flags,
                vma_caching
            )) {
            release_write(&space->lock);
            vmfree(space, new_addr_ptr, new_size);
            return (void*)-ENOMEM;
        }
    }

    if (flags & MREMAP_DONTUNMAP) {
        vm_area_t* old_vma = vmm_find_vma_unsafe(space, old_addr);

        if (old_vma && old_vma->start == old_addr && old_vma->size == old_size) {
            old_vma->flags |= VMM_FLAG_DEMAND;
            old_vma->flags &= ~(VMM_FLAG_SHARED | VMM_FLAG_POPULATE);
        }

        release_write(&space->lock);
    } else {
        release_write(&space->lock);
        sys_munmap(space, old_address, old_size);
    }

    return new_addr_ptr;
}