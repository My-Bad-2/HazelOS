#include "memory/paging.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cpu/cpu.h"
#include "cpu/registers.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"
#include "memory/vmm.h"

#define MAX_PAGE_TABLE_ENTRIES 512

static int paging_max_levels = 4;
static bool nx_supported     = false;
static bool pml3_translation = false;

typedef struct {
    uint64_t entries[MAX_PAGE_TABLE_ENTRIES];
} pagetable_t;

static inline int virt_addr_to_idx(uintptr_t virt_addr, int level) {
    int shift = 12 + (level - 1) * 9;
    return (int)((virt_addr >> shift) & (MAX_PAGE_TABLE_ENTRIES - 1));
}

static inline int get_target_level(size_t page_size) {
    if (page_size == PAGE_SIZE_LARGE) {
        return 3;
    }

    if (page_size == PAGE_SIZE_MEDIUM) {
        return 2;
    }

    return 1;
}

static inline size_t get_level_size(int level) {
    int shift = 12 + (level - 1) * 9;
    return 1ul << shift;
}

static inline bool is_table_empty(pagetable_t* table) {
    for (int i = 0; i < MAX_PAGE_TABLE_ENTRIES; ++i) {
        if (table->entries[i] != 0) {
            return false;
        }
    }

    return true;
}

static inline bool pagemap_is_active(pagemap_t* map) {
    uint64_t cr3 = read_cr3();

    return (cr3 & X86_PAGE_ADDRESS_MASK) == (map->phys_root & X86_PAGE_ADDRESS_MASK);
}

static inline void reload_mapping(pagemap_t* map) {
    // Check if the modified map is the one currently loaded
    if (pagemap_is_active(map)) {
        write_cr3(map->phys_root);
    }
}

size_t convert_generic_flags(uint32_t flags, cache_type_t cache, size_t page_size) {
    size_t ret       = 0;
    const size_t pat = (page_size == PAGE_SIZE_SMALL) ? X86_PAGE_FLAG_PAT : X86_PAGE_FLAG_LARGE_PAT;

    if (flags & VMM_FLAG_READ) {
        ret |= X86_PAGE_FLAG_PRESENT;
    }

    if (flags & VMM_FLAG_WRITE) {
        ret |= X86_PAGE_FLAG_WRITE;
    }

    if (flags & VMM_FLAG_USER) {
        ret |= X86_PAGE_FLAG_USER;
    }

    if (flags & VMM_FLAG_GLOBAL) {
        ret |= X86_PAGE_FLAG_GLOBAL;
    }

    if (!(flags & VMM_FLAG_EXECUTE) && nx_supported) {
        ret |= X86_PAGE_FLAG_NX;
    }

    if (flags & VMM_FLAG_SHARED) {
        ret |= X86_PAGE_FLAG_SHARED;
    }

    if (flags & VMM_FLAG_DEMAND) {
        ret |= X86_PAGE_FLAG_DEMAND;
    }

    if (flags & VMM_FLAG_PRIVATE) {
        ret |= X86_PAGE_FLAG_PRIVATE;
    }

    if (page_size != PAGE_SIZE_SMALL) {
        ret |= X86_PAGE_FLAG_HUGE;
    }

    switch (cache) {
        case CACHE_UNCACHEABLE:
            ret |= X86_PAGE_FLAG_CACHE_DISABLE;
            break;
        case CACHE_MMIO:
        case CACHE_DEVICE:
            ret |= X86_PAGE_FLAG_CACHE_DISABLE | X86_PAGE_FLAG_WRITE_THROUGH;
            break;
        case CACHE_WRITE_THROUGH:
            ret |= X86_PAGE_FLAG_WRITE_THROUGH;
            break;
        case CACHE_WRITE_PROTECTED:
            ret |= pat;
            break;
        case CACHE_WRITE_COMBINING:
            ret |= pat | X86_PAGE_FLAG_WRITE_THROUGH;
            break;
        case CACHE_WRITE_BACK:
        default:
            break;
    }

    return ret;
}

static uint64_t*
get_page_table_entry(pagemap_t* map, uintptr_t virt_addr, int target_lvl, bool allocate) {
    ASSERT(map && virt_addr);
    uintptr_t curr_table_phys = map->phys_root;
    pagetable_t* table        = (pagetable_t*)to_higher_half(curr_table_phys);
    int idx                   = 0;

    for (int l = paging_max_levels; l > target_lvl; --l) {
        idx = virt_addr_to_idx(virt_addr, l);

        uintptr_t entry = table->entries[idx];

        if (entry & X86_PAGE_FLAG_HUGE) {
            // Refuse to split an existing huge-page mapping implicitly;
            // callers must explicitly tear it down if they want finer granularity.
            errno = EBUSY;
            KLOG_WARN("Paging: refusing to split huge mapping virt=0x%lx level=%d\n", virt_addr, l);
            return nullptr;
        }

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            if (!allocate) {
                return nullptr;
            }

            void* table_phys = pmm_alloc(1);

            if (!table_phys) {
                errno = ENOMEM;
                KLOG_ERROR("Paging: failed to allocate page table at level=%d\n", l);
                return nullptr;
            }

            pagetable_t* new_table = (pagetable_t*)to_higher_half((uintptr_t)table_phys);
            memset(new_table, 0, sizeof(pagetable_t));

            uint64_t new_entry  = (uintptr_t)table_phys | X86_NEW_PAGE_TABLE_FLAGS;
            table->entries[idx] = new_entry;
            entry               = new_entry;
        }

        curr_table_phys = entry & X86_PAGE_ADDRESS_MASK;
        table           = (pagetable_t*)to_higher_half(curr_table_phys);
    }

    idx = virt_addr_to_idx(virt_addr, target_lvl);
    return &table->entries[idx];
}

bool pagemap_map(pagemap_t* map, pagemap_map_args_t args) {
    if (args.page_size == PAGE_SIZE_LARGE && !pml3_translation) {
        args.page_size = PAGE_SIZE_MEDIUM;
    }

    uintptr_t virt_start = (uintptr_t)args.virt_addr;
    uintptr_t phys_addr  = (uintptr_t)args.phys_addr;

    size_t length = args.length;
    size_t flags  = convert_generic_flags(args.flags, args.cache, args.page_size);

    if (length == 0) {
        errno = EINVAL;
        KLOG_WARN("Paging: map zero length requested virt=0x%lx\n", virt_start);
        return false;
    }

    size_t page_size = args.page_size;
    int target_level = get_target_level(args.page_size);

    // Track if we allocated memory locally so we can free it if mappings fails
    bool allocated_locally = false;

    if (!is_aligned(virt_start, page_size)) {
        errno = EINVAL;
        KLOG_WARN(
            "Paging: map virt addr not aligned virt=0x%lx page_size=0x%zx\n",
            virt_start,
            page_size
        );
        return false;
    }

    // If mapping specific phys memory, it must be aligned too.
    if (!is_aligned(phys_addr, page_size) && phys_addr) {
        errno = EINVAL;
        KLOG_WARN(
            "Paging: map phys addr not aligned phys=0x%lx page_size=0x%zx\n",
            phys_addr,
            page_size
        );
        return false;
    }

    // Calculate number of pages needed
    size_t aligned_length = align_up(length, page_size);
    size_t num_pages      = aligned_length / page_size;

    uintptr_t curr_virt = virt_start;

    // We track how many pages we successfully setup for rollback purposes
    size_t pages_mapped = 0;
    bool success        = true;

    acquire_interrupt_lock(&map->lock);
    for (size_t i = 0; i < num_pages; ++i) {
        uintptr_t curr_phys = 0;

        if (phys_addr != 0) {
            // Fixed Mapping (Contiguous)
            curr_phys = phys_addr + (i * page_size);
        } else {
            void* p = pmm_alloc_aligned(page_size, page_size / PAGE_SIZE_SMALL);

            if (!p) {
                errno = ENOMEM;
                KLOG_ERROR(
                    "Paging: map failed to allocate phys page virt=0x%lx size=0x%zx\n",
                    curr_virt,
                    page_size
                );
                success = false;
                // Go to Rollback
                break;
            }

            curr_phys = (uintptr_t)p;
        }

        uint64_t* pte = get_page_table_entry(map, curr_virt, target_level, true);

        if (!pte) {
            // If we just allocated this page, we must free it immediately
            if (phys_addr == 0) {
                pmm_free((void*)curr_phys, page_size / PAGE_SIZE_SMALL);
            }

            if (errno == 0) {
                errno = EFAULT;
            }

            KLOG_WARN(
                "Paging: map failed to get PTE virt=0x%lx level=%d errno=%d\n",
                curr_virt,
                target_level,
                errno
            );
            success = false;
            // Go to Rollback
            break;
        }

        // Write entry
        // If there was an old mapping here, too bad we're overwriting it.
        uint64_t entry = curr_phys & ~0xffful;
        entry |= flags;

        if (args.pkey > 0) {
            entry |= ((uint64_t)(args.pkey & 0xf) << 59);
        }

        *pte = entry;

        curr_virt += page_size;
        pages_mapped++;
    }

    if (!success) {
        // We failed in the middle. We must undo exactly what we did.
        // If we were allocating memory (phys_base == 0), we must free it.
        // If we were just mapping (phys_base != 0), we just unmap.
        uintptr_t cleanup_virt = virt_start;

        for (size_t i = 0; i < pages_mapped; ++i) {
            uint64_t* pte = get_page_table_entry(map, cleanup_virt, target_level, false);

            if (pte && (*pte & X86_PAGE_FLAG_PRESENT)) {
                uint64_t phys_to_free = *pte & ~0xffful;
                *pte                  = 0;

                if (phys_addr == 0) {
                    pmm_free((void*)phys_to_free, page_size);
                }
            }

            cleanup_virt += page_size;

            // Flush TLB for the range we just messed up (and cleaned up) to ensure no stale entries
            // remain from the partial attempt.
            reload_mapping(map);
            release_interrupt_lock(&map->lock);

            if (errno == 0) {
                errno = EFAULT;
            }

            KLOG_WARN(
                "Paging: map rollback after %zu pages mapped virt_start=0x%lx errno=%d\n",
                pages_mapped,
                virt_start,
                errno
            );

            return false;
        }
    }

    if (!args.skip_flush) {
        if (aligned_length > (PAGE_SIZE_MEDIUM * 16)) {
            reload_mapping(map);
        } else {
            for (size_t i = 0; i < num_pages; ++i) {
                invlpg((const void*)(virt_start + (i * page_size)));
            }
        }
    }

    release_interrupt_lock(&map->lock);
    return true;
}

static bool unmap_worker(
    pagetable_t* table,
    int level,
    uintptr_t virt_start,
    uintptr_t virt_end,
    bool free_phys
) {
    uint64_t level_size = get_level_size(level);

    int start_idx = virt_addr_to_idx(virt_start, level);
    int end_idx   = virt_addr_to_idx(virt_end, level);

    // If the range covers "indices before 0" or "indices after 511" relative to the full virtual
    // space, `virt_addr_to_idx()` naturally wraps or clamps becuase we are passing the speicifc
    // virt_start/virt_end down. However, if we are recursing, the parent guarantees we only look at
    // indices to this specific table path.
    bool table_modified = false;

    for (int i = start_idx; i <= end_idx; ++i) {
        uint64_t entry = table->entries[i];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            continue;
        }

        uintptr_t entry_phys = entry & X86_PAGE_ADDRESS_MASK;
        bool is_huge         = (entry & X86_PAGE_FLAG_HUGE);

        // Leaf Case: Level 1 (PT) or Huge Page
        if (level == 1 || is_huge) {
            table->entries[i] = 0;
            table_modified    = true;

            if (free_phys) {
                size_t size_to_free = (level == 1) ? PAGE_SIZE_SMALL : level_size;

                pmm_free((void*)entry_phys, size_to_free / PAGE_SIZE_SMALL);
            }
        } else {
            // Internal nodes: Recurse deeper
            bool child_became_empty = unmap_worker(
                (pagetable_t*)to_higher_half(entry_phys),
                level - 1,
                virt_start,
                virt_end,
                free_phys
            );

            if (child_became_empty) {
                table->entries[i] = 0;
                table_modified    = true;

                pmm_free((void*)entry_phys, 1);
            }
        }
    }

    // If we didn't touch anything, don't scan for emptiness
    if (!table_modified) {
        return false;
    }

    return is_table_empty(table);
}

void pagemap_unmap(pagemap_t* map, pagemap_unmap_args_t args) {
    if (args.length == 0) {
        errno = EINVAL;
        KLOG_WARN("Paging: unmap zero length request\n");
        return;
    }

    // Align to page boundaries
    uintptr_t virt_start = align_down((uintptr_t)args.virt_addr, PAGE_SIZE_SMALL);
    uintptr_t virt_end   = align_up(virt_start + args.length, PAGE_SIZE_SMALL);

    if (virt_end < virt_start) {
        virt_end = UINTPTR_MAX;
    }

    // Decrement end by 1 to make the range inclusive for index calculations.
    // For example: if range is 0x1000 to 0x2000 (1 page), start = 0x1000, end = 0x1fff.
    virt_end--;

    // Perform the recursive walk
    // We ignore the return value; we never free the root itself here.
    acquire_interrupt_lock(&map->lock);
    unmap_worker(
        (pagetable_t*)to_higher_half(map->phys_root),
        paging_max_levels,
        virt_start,
        virt_end,
        args.free_phys
    );

    // A single 2MB huge paeg contains 512 4KB pages. Executing 512 invlpg instructions is
    // expensive. A full CR3 write is often cheaper.
    if (args.length > PAGE_SIZE_MEDIUM * 16) {
        reload_mapping(map);
    } else {
        // For small ranges (e.g. 4KB to 1.9MB), individual invalidation is better to preserve the
        // TLB entries of the rest of the kernel.
        for (uintptr_t i = virt_start; i <= virt_end; i += PAGE_SIZE_SMALL) {
            invlpg((const void*)(i));
        }
    }

    release_interrupt_lock(&map->lock);
}

uintptr_t pagemap_translate(pagemap_t* map, uintptr_t virt_addr) {
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    size_t page_size    = PAGE_SIZE_SMALL;
    uint64_t entry      = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);

    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            goto not_found;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        page_size = PAGE_SIZE_LARGE;
        goto found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        page_size = PAGE_SIZE_MEDIUM;
        goto found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 1 (PT)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

found:
    release_interrupt_lock(&map->lock);
    return (entry & X86_PAGE_ADDRESS_MASK) + (virt_addr & (page_size - 1));
not_found:
    release_interrupt_lock(&map->lock);
    return 0;
}

void pagemap_protect(pagemap_t* map, pagemap_protect_args_t args) {
    uintptr_t virt_addr = (uintptr_t)args.virt_addr;
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    size_t flags        = convert_generic_flags(args.flags, args.cache, PAGE_SIZE_LARGE);

    size_t preserved_bits = 0;
    uint64_t entry        = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);

    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            goto cleanup;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        preserved_bits     = entry & X86_PAGE_PRESERVED_BITS;
        table->entries[i3] = preserved_bits | flags;
        goto flush_tlb;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        preserved_bits     = entry & X86_PAGE_PRESERVED_BITS;
        table->entries[i2] = preserved_bits | flags;
        goto flush_tlb;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 1 (PT)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    flags              = convert_generic_flags(args.flags, args.cache, PAGE_SIZE_SMALL);
    preserved_bits     = entry & X86_PAGE_PRESERVED_BITS & ~X86_PAGE_FLAG_HUGE;
    table->entries[i1] = preserved_bits | flags;

flush_tlb:
    reload_mapping(map);
cleanup:
    release_interrupt_lock(&map->lock);
}

bool pagemap_shatter(pagemap_t* map, uintptr_t virt_addr) {
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    uint64_t entry      = 0;

    int err = 0;

    // We need to track where we are to update the entry later.
    uint64_t* entry_ptr = 0;
    int level           = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);
    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            err = ENOENT;
            goto cleanup;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i3];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        err = ENOENT;
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        // Found 1GB page
        level = 3;
        goto do_shatter;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i2];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        err = ENOENT;
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        // Found 2MB page
        level = 2;
        goto do_shatter;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // If we are here, it's already a 4K page (Level 1), so nothing to shatter.
cleanup:
    release_interrupt_lock(&map->lock);
    if (err != 0) {
        errno = err;
        KLOG_WARN("Paging: shatter failed virt=0x%lx errno=%d\n", virt_addr, err);
    }
    return false;
do_shatter:
    // Allocate a new Page Table frame.
    // We need a zeroes 4K page for the new table.
    void* new_table_ptr = pmm_alloc_aligned(PAGE_SIZE_SMALL, 1);

    if (!new_table_ptr) {
        err = ENOMEM;
        release_interrupt_lock(&map->lock);
        errno = err;
        KLOG_ERROR(
            "Paging: shatter failed to allocate table virt=0x%lx errno=%d\n",
            virt_addr,
            err
        );
        return false;
    }

    uintptr_t new_table_phys = (uintptr_t)new_table_ptr;
    pagetable_t* new_table   = (pagetable_t*)to_higher_half(new_table_phys);

    uintptr_t huge_phys_base = entry & X86_PAGE_ADDRESS_MASK;

    // Size of the new smaller pages.
    size_t step_size = 0;

    // Inherit flags (R/W, User, NX, etc.)
    size_t flags = entry;

    if (level == 3) {
        // Splitting 1 GB -> 512 * 2MB
        step_size = PAGE_SIZE_MEDIUM;

        // The children are still huge (2MB), just smaller huge.
        flags |= X86_PAGE_FLAG_HUGE;
    } else {
        // Splitting 2MB -> 512 * 4KB
        step_size = PAGE_SIZE_SMALL;

        // The children are standard 4K pages.
        flags &= ~X86_PAGE_FLAG_HUGE;
    }

    // Mask out the physical address from flags, keep permissions
    flags &= ~X86_PAGE_ADDRESS_MASK;

    // Mask out Accessed/Dirty from parent, we let the CPU set them on the specific small pages
    // later
    flags &= ~(X86_PAGE_FLAG_ACCESSED | X86_PAGE_FLAG_DIRTY);

    // We create 512 entries, each pointing to a chunk of the original huge page.
    for (size_t i = 0; i < 512; ++i) {
        new_table->entries[i] = (huge_phys_base + (i * step_size)) | flags;
    }

    // Update the Parent Entry.
    // Instead of forcing permissive flags (RW | User), we inherit the access control bits from the
    // original huge page.
    const size_t access_mask = X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_WRITE | X86_PAGE_FLAG_USER |
                               X86_PAGE_FLAG_WRITE_THROUGH | X86_PAGE_FLAG_CACHE_DISABLE |
                               X86_PAGE_FLAG_LARGE_PAT | X86_PAGE_FLAG_NX;
    size_t inherited_flags   = entry & access_mask;

    // The new parent points to the new table, is Present, and inherits restrictions.
    uint64_t new_parent_entry = new_table_phys | X86_PAGE_FLAG_PRESENT | inherited_flags;

    // Write the entry atomically
    *entry_ptr = new_parent_entry;

    reload_mapping(map);
    release_interrupt_lock(&map->lock);
    return true;
}

void pagemap_load(pagemap_t* map) {
    if (!pagemap_is_active(map)) {
        write_cr3(map->phys_root);
    }
}

size_t pagemap_get_flags(pagemap_t* map, uintptr_t virt_addr) {
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    uint64_t entry      = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);

    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            goto not_found;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto found;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 1 (PT)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i3];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto not_found;
    }

found:
    release_interrupt_lock(&map->lock);
    return entry & ~X86_PAGE_ADDRESS_MASK;
not_found:
    release_interrupt_lock(&map->lock);
    return 0;
}

static void pagemap_release_worker(uintptr_t table_phys, int level, int target_level) {
    pagetable_t* table = (pagetable_t*)to_higher_half(table_phys);

    // If we are at the top PML, only iterate the lower half (User Space) entries (0 to 255) to
    // avoid nuking kernel tables.
    int max_idx = MAX_PAGE_TABLE_ENTRIES;

    if (level == paging_max_levels) {
        max_idx = MAX_PAGE_TABLE_ENTRIES / 2;
    }

    for (int i = 0; i < max_idx; ++i) {
        uint64_t entry = table->entries[i];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            continue;
        }

        uintptr_t child_phys = entry & X86_PAGE_ADDRESS_MASK;

        // If not at the leaf, recurse first
        if (level > target_level && !(entry & X86_PAGE_FLAG_HUGE)) {
            pagemap_release_worker(child_phys, level - 1, target_level);
        }

        if (level > 1 && !(entry & X86_PAGE_FLAG_HUGE)) {
            pmm_free((void*)child_phys, 1);
        }
    }
}

void pagemap_release(pagemap_t* map) {
    // Switch to a safe pagemap if we are currently running on the map we are about t destroy.
    if (pagemap_is_active(map)) {
        pagemap_load(vmm_get_kernel_pagemap());
    }

    pagemap_release_worker(map->phys_root, paging_max_levels, 1);

    pmm_free((void*)map->phys_root, 1);
    map->phys_root = 0;
}

void pagemap_sync_kernel(pagemap_t* target_map) {
    pagemap_t* kernel_map = vmm_get_kernel_pagemap();

    pagetable_t* target_pml = (pagetable_t*)to_higher_half(target_map->phys_root);
    pagetable_t* kernel_pml = (pagetable_t*)to_higher_half(kernel_map->phys_root);

    // Copy the top half (Entries 256 to 511)
    // This copies the pointers to the kernel PDPs.
    // Since kernel PDPs are shared, any update inside them is visible globally.
    memcpy(&target_pml->entries[256], &kernel_pml->entries[256], 256 * sizeof(uint64_t));
}

bool pagemap_test_and_clear_dirty(pagemap_t* map, uintptr_t virt_addr) {
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    uint64_t entry      = 0;
    bool is_dirty       = false;

    // We need to track where we are to update the entry later.
    uint64_t* entry_ptr = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);

    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            goto cleanup;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i3];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto check_dirty;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i2];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto check_dirty;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i1];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

check_dirty:
    is_dirty = (entry & X86_PAGE_FLAG_DIRTY);

    if (is_dirty) {
        entry &= ~X86_PAGE_FLAG_DIRTY;
        *entry_ptr = entry;

        invlpg((void*)virt_addr);
    }

cleanup:
    release_interrupt_lock(&map->lock);
    return is_dirty;
}

bool pagemap_test_and_clear_accessed(pagemap_t* map, uintptr_t virt_addr) {
    uintptr_t phys_curr = map->phys_root;
    pagetable_t* table  = (pagetable_t*)to_higher_half(phys_curr);
    uint64_t entry      = 0;
    bool is_dirty       = false;

    // We need to track where we are to update the entry later.
    uint64_t* entry_ptr = 0;

    int i5 = virt_addr_to_idx(virt_addr, 5);
    int i4 = virt_addr_to_idx(virt_addr, 4);
    int i3 = virt_addr_to_idx(virt_addr, 3);
    int i2 = virt_addr_to_idx(virt_addr, 2);
    int i1 = virt_addr_to_idx(virt_addr, 1);

    acquire_interrupt_lock(&map->lock);

    // If we are in 5-level mode, the root is PML5. We must resolve it
    // to get the physical address of the PML4 table.
    if (paging_max_levels == 5) {
        entry = table->entries[i5];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            goto cleanup;
        }

        // Extract the physical address of the next level (PML4)
        phys_curr = entry & X86_PAGE_ADDRESS_MASK;
    }

    // Level 4 (PML4)
    table = (pagetable_t*)to_higher_half(phys_curr);
    entry = table->entries[i4];

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 3 (PDP)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i3];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto check_accessed;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i2];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

    if (entry & X86_PAGE_FLAG_HUGE) {
        goto check_accessed;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i1];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
        goto cleanup;
    }

check_accessed:
    is_dirty = (entry & X86_PAGE_FLAG_ACCESSED);

    if (is_dirty) {
        entry &= ~X86_PAGE_FLAG_ACCESSED;
        *entry_ptr = entry;

        invlpg((void*)virt_addr);
    }

cleanup:
    release_interrupt_lock(&map->lock);
    return is_dirty;
}

bool pagemap_collapse(pagemap_t* map, uintptr_t virt_addr) {
    // Virt_addr must be 2MB aligned
    if (!is_aligned(virt_addr, PAGE_SIZE_MEDIUM)) {
        errno = EINVAL;
        KLOG_WARN("Paging: collapse virt=0x%lx is not 2MB aligned\n", virt_addr);
        return false;
    }

    int err = 0;
    acquire_interrupt_lock(&map->lock);

    // Walk to the Page directory (Level 2)
    uint64_t* pde = get_page_table_entry(map, virt_addr, 2, false);
    bool success  = false;

    if (!pde || !(*pde & X86_PAGE_FLAG_PRESENT)) {
        err = ENOENT;
        goto cleanup;
    }

    // If already huge, nothing to do
    if (*pde & X86_PAGE_FLAG_HUGE) {
        success = true;
        goto cleanup;
    }

    uintptr_t pt_phys = *pde & X86_PAGE_ADDRESS_MASK;
    pagetable_t* pt   = (pagetable_t*)to_higher_half(pt_phys);

    if (!(pt->entries[0] & X86_PAGE_FLAG_PRESENT)) {
        err = ENOENT;
        goto cleanup;
    }

    uintptr_t base_phys   = pt->entries[0] & X86_PAGE_ADDRESS_MASK;
    size_t expected_flags = pt->entries[0] & ~X86_PAGE_ADDRESS_MASK;

    if (!is_aligned(base_phys, PAGE_SIZE_MEDIUM)) {
        err = EINVAL;
        goto cleanup;
    }

    for (size_t i = 1; i < MAX_PAGE_TABLE_ENTRIES; ++i) {
        uint64_t entry = pt->entries[i];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            err = ENOENT;
            goto cleanup;
        }

        if ((entry & ~X86_PAGE_ADDRESS_MASK) != expected_flags) {
            err = EINVAL;
            goto cleanup;
        }

        if ((entry & X86_PAGE_ADDRESS_MASK) != (base_phys + (i * PAGE_SIZE_SMALL))) {
            err = EINVAL;
            goto cleanup;
        }
    }

    uint64_t new_pde = base_phys | expected_flags | X86_PAGE_FLAG_HUGE;

    *pde = new_pde;
    pmm_free((void*)pt_phys, 1);
    invlpg((const void*)virt_addr);
    success = true;
cleanup:
    release_interrupt_lock(&map->lock);
    if (!success && err != 0) {
        errno = err;
        KLOG_WARN("Paging: collapse failed virt=0x%lx errno=%d\n", virt_addr, err);
    }
    return success;
}

void pagemap_create(pagemap_t* map) {
    void* root_frame = pmm_alloc(1);

    if (!root_frame) {
        PANIC("Out of Memory\n");
        map->phys_root = 0;
        return;
    }

    map->phys_root = (uintptr_t)root_frame;

    pagetable_t* table = (pagetable_t*)to_higher_half(map->phys_root);

    memset(table, 0, 256 * sizeof(uint64_t));
    pagemap_t* kernel_map = vmm_get_kernel_pagemap();

    if (kernel_map && kernel_map != map) {
        pagemap_sync_kernel(map);
    } else {
        memset(&table->entries[256], 0, 256 * sizeof(uint64_t));
    }

    create_interrupt_lock(&map->lock);
}

void pagemap_global_init() {
    bool has_pge  = cpu_has_feature(FEATURE_PGE);
    bool has_la57 = cpu_has_feature(FEATURE_LA57);

    bool has_smep = cpu_has_feature(FEATURE_SMEP);
    bool has_smap = cpu_has_feature(FEATURE_SMAP);
    bool has_pku  = cpu_has_feature(FEATURE_PKU);

    nx_supported     = cpu_has_feature(FEATURE_XD);
    pml3_translation = cpu_has_feature(FEATURE_PDPE1GB);

    KLOG_INFO(
        "Paging: features PGE=%d LA57=%d SMEP=%d SMAP=%d PKU=%d NX=%d 1G=%d\n",
        has_pge,
        has_la57,
        has_smep,
        has_smap,
        has_pku,
        nx_supported,
        pml3_translation
    );

    if (nx_supported) {
        uint64_t efer = read_msr(X86_MSR_IA32_EFER);
        efer |= X86_EFER_NXE;
        write_msr(X86_MSR_IA32_EFER, efer);
        KLOG_INFO("Paging: NXE enabled in EFER\n");
    }

    uint64_t cr4 = read_cr4();
    if (has_pge) {
        cr4 |= X86_CR4_PGE;
    }

    if (has_smep) {
        cr4 |= X86_CR4_SMEP;
    }

    if (has_pku) {
        cr4 |= X86_CR4_PKE;
    }

    if (has_la57) {
        if (cr4 & X86_CR4_LA57) {
            paging_max_levels = 5;
        } else {
            paging_max_levels = 4;
        }
    }

    KLOG_INFO(
        "Paging: CR4 set PGE=%d SMEP=%d PKE=%d LA57=%d (levels=%d)\n",
        !!(cr4 & X86_CR4_PGE),
        !!(cr4 & X86_CR4_SMEP),
        !!(cr4 & X86_CR4_PKE),
        !!(cr4 & X86_CR4_LA57),
        paging_max_levels
    );

    write_cr4(cr4);

    uint64_t cr0 = read_cr0();
    cr0 |= X86_CR0_WP;
    cr0 |= X86_CR0_PG;
    write_cr0(cr0);

    KLOG_INFO("Paging: CR0 paging+WP enabled (cr0=0x%lx)\n", cr0);
}

typedef struct {
    char* buffer;
    size_t size;
    size_t offset;
    bool full;
} walk_ctx_t;

static void walk_printf(walk_ctx_t* ctx, const char* fmt, ...) {
    if (ctx->full) {
        return;
    }

    if (ctx->offset >= ctx->size - 1) {
        ctx->full = true;
        return;
    }

    size_t remaining = ctx->size - ctx->offset;

    va_list args;
    va_start(args, fmt);

    int written = vsnprintf(ctx->buffer + ctx->offset, remaining, fmt, args);

    va_end(args);

    if (written < 0) {
        ctx->full = true;
    } else if ((size_t)written >= remaining) {
        ctx->offset += remaining - 1;
        ctx->full = true;
    } else {
        ctx->offset += (size_t)written;
    }
}

static void walk_print_flags(walk_ctx_t* ctx, size_t entry) {
    walk_printf(
        ctx,
        "[%c%c%c%c%c%c%c%c]",
        (entry & X86_PAGE_FLAG_PRESENT) ? 'P' : '-',
        (entry & X86_PAGE_FLAG_WRITE) ? 'W' : 'R',
        (entry & X86_PAGE_FLAG_USER) ? 'U' : 'S',
        (entry & X86_PAGE_FLAG_NX) ? 'X' : '-',
        (entry & X86_PAGE_FLAG_ACCESSED) ? 'A' : '-',
        (entry & X86_PAGE_FLAG_DIRTY) ? 'D' : '-',
        (entry & X86_PAGE_FLAG_WRITE_THROUGH) ? 'T' : '-',
        (entry & X86_PAGE_FLAG_CACHE_DISABLE) ? 'C' : '-'
    );
}

static void
walk_worker(pagemap_t* map, walk_ctx_t* ctx, uintptr_t table_phys, int level, uintptr_t virt_base) {
    if (ctx->full) {
        return;
    }

    pagetable_t* table = (pagetable_t*)to_higher_half(table_phys);
    size_t level_size  = get_level_size(level);

    for (size_t i = 0; i < MAX_PAGE_TABLE_ENTRIES; ++i) {
        uint64_t entry = table->entries[i];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            continue;
        }

        uintptr_t curr_virt  = virt_base + (i * level_size);
        uintptr_t child_phys = entry & X86_PAGE_ADDRESS_MASK;
        bool is_huge         = (entry & X86_PAGE_FLAG_HUGE);

        if (level == 1 || is_huge) {
            for (int j = 0; j < (paging_max_levels - level); j++) {
                walk_printf(ctx, "  ");
            }

            const char* size_str = (level == 1) ? "4KB" : (level == 2 ? "2MB" : "1GB");

            walk_printf(ctx, "V:%016lx -> P:%016lx | %s | ", curr_virt, child_phys, size_str);

            walk_print_flags(ctx, entry);
            walk_printf(ctx, "\n");
        } else {
            walk_worker(map, ctx, child_phys, level - 1, curr_virt);
        }

        if (ctx->full) {
            return;
        }
    }
}

size_t pagemap_walk(pagemap_t* map, char* buffer, size_t size) {
    if (!map || !buffer || size == 0) {
        return 0;
    }

    walk_ctx_t ctx = {
        .buffer = buffer,
        .size   = size,
        .offset = 0,
        .full   = false,
    };

    walk_printf(&ctx, "Pagemap Root: %016lx (Level %d)\n", map->phys_root, paging_max_levels);

    walk_worker(map, &ctx, map->phys_root, paging_max_levels, 0);

    if (ctx.full) {
        ctx.offset -= 4;
        walk_printf(&ctx, "...\n");
    }

    return ctx.offset;
}

static bool
clone_worker(pagemap_t* map, uintptr_t src_table_phys, uintptr_t dest_table_phys, int level) {
    pagetable_t* src_table  = (pagetable_t*)to_higher_half(src_table_phys);
    pagetable_t* dest_table = (pagetable_t*)to_higher_half(dest_table_phys);

    // Limit iteration to user space only.
    int max_idx =
        (level == paging_max_levels) ? MAX_PAGE_TABLE_ENTRIES / 2 : MAX_PAGE_TABLE_ENTRIES;

    for (size_t i = 0; i < max_idx; ++i) {
        uint64_t entry = src_table->entries[i];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            continue;
        }

        uintptr_t phys_addr = entry & X86_PAGE_ADDRESS_MASK;
        size_t flags        = entry & ~X86_PAGE_ADDRESS_MASK;
        bool is_huge        = (entry & X86_PAGE_FLAG_HUGE);

        if (level == 1 || is_huge) {
            if (flags & X86_PAGE_FLAG_WRITE) {
                uint64_t new_flags    = (flags & ~X86_PAGE_FLAG_WRITE) | X86_PAGE_FLAG_PRIVATE;
                src_table->entries[i] = phys_addr | new_flags;

                // Child gets exact same flags (RO + Shared) and same phys address
                dest_table->entries[i] = phys_addr | new_flags;
            } else {
                // Already Read-Onyl. Just link it.
                dest_table->entries[i] = entry;
            }

            pmm_inc_ref((void*)phys_addr);
        } else {
            void* new_table_ptr = pmm_alloc(1);

            if (!new_table_ptr) {
                return false;
            }

            uintptr_t new_table_phys = (uintptr_t)new_table_ptr;

            dest_table->entries[i] = new_table_phys | X86_NEW_PAGE_TABLE_FLAGS;

            if (!clone_worker(map, phys_addr, new_table_phys, level - 1)) {
                return false;
            }
        }
    }

    return true;
}

// TODO: Implement PF handler
bool pagemap_clone(pagemap_t* dest, pagemap_t* src) {
    acquire_interrupt_lock(&src->lock);
    acquire_interrupt_lock(&dest->lock);

    pagemap_create(dest);

    if (dest->phys_root == 0) {
        release_interrupt_lock(&dest->lock);
        release_interrupt_lock(&src->lock);

        return false;
    }

    bool success = clone_worker(src, src->phys_root, dest->phys_root, paging_max_levels);

    if (pagemap_is_active(src)) {
        reload_mapping(src);
    }

    release_interrupt_lock(&dest->lock);
    release_interrupt_lock(&src->lock);

    return success;
}