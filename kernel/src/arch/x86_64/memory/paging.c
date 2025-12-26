#include "memory/paging.h"

#include <stdint.h>
#include <string.h>

#include "cpu/registers.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/pmm.h"

#define MAX_PAGE_TABLE_ENTRIES 512

static int paging_max_levels     = 0;
static bool nx_supported         = false;
static bool huge_pages_supported = false;

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

static inline void reload_mapping(pagemap_t* map) {
    uint64_t cr3 = read_cr3();

    // Check if the modified map is the one currently loaded
    if ((cr3 & X86_PAGE_ADDRESS_MASK) == (map->phys_root & X86_PAGE_ADDRESS_MASK)) {
        write_cr3(cr3);
    }
}

static inline size_t convert_generic_flags(uint32_t flags, cache_type_t cache, size_t page_size) {
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

    if (page_size != PAGE_SIZE_SMALL) {
        ret |= X86_PAGE_FLAG_HUGE;
    }

    switch (cache) {
        case CACHE_UNCACHEABLE:
            ret |= x86_PAGE_FLAG_CACHE_DISABLE;
            break;
        case CACHE_MMIO:
        case CACHE_DEVICE:
            ret |= x86_PAGE_FLAG_CACHE_DISABLE | X86_PAGE_FLAG_WRITE_THROUGH;
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
        idx             = virt_addr_to_idx(virt_addr, l);
        uintptr_t entry = table->entries[idx];

        if (entry & X86_PAGE_FLAG_HUGE) {
            // Refuse to split an existing huge-page mapping implicitly;
            // callers must explicitly tear it down if they want finer granularity.
            return nullptr;
        }

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            if (!allocate) {
                return nullptr;
            }

            void* table_phys = pmm_alloc(1);

            if (!table_phys) {
                KLOG_ERROR("Failed to allocate page table at level=%d", l);
                return nullptr;
            }

            pagetable_t* new_table = (pagetable_t*)to_higher_half((uintptr_t)virt_addr);
            memset(new_table, 0, sizeof(pagetable_t));

            uint64_t new_entry      = (uintptr_t)table_phys | X86_NEW_PAGE_TABLE_FLAGS;
            new_table->entries[idx] = new_entry;
            entry                   = new_entry;
        }

        curr_table_phys = entry & X86_PAGE_ADDRESS_MASK;
        table           = (pagetable_t*)to_higher_half(curr_table_phys);
    }

    idx = virt_addr_to_idx(virt_addr, target_lvl);
    return &table->entries[idx];
}

bool pagemap_map(pagemap_t* map, pagemap_map_args_t args) {
    if (args.page_size == PAGE_SIZE_LARGE && !huge_pages_supported) {
        args.page_size = PAGE_SIZE_MEDIUM;
    }

    uintptr_t virt_start = (uintptr_t)args.virt_addr;
    uintptr_t phys_addr  = (uintptr_t)args.phys_addr;

    size_t length = args.length;
    size_t flags  = convert_generic_flags(args.flags, args.cache, args.page_size);

    if (length == 0) {
        return false;
    }

    size_t page_size = args.page_size;
    int target_level = get_target_level(args.page_size);

    // Track if we allocated memory locally so we can free it if mappings fails
    bool allocated_locally = false;

    if (!is_aligned(virt_start, page_size)) {
        return false;
    }

    // If mapping specific phys memory, it must be aligned too.
    if (!is_aligned(phys_addr, page_size) && phys_addr) {
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
        return;
    }

    // Align to page boundaries
    uintptr_t virt_start = align_down(virt_start, PAGE_SIZE_SMALL);
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
        // Found 1GB page
        level = 3;
        goto do_shatter;
    }

    phys_curr = entry & X86_PAGE_ADDRESS_MASK;

    // Level 2 (PD)
    // Level 3 (PDP)
    table     = (pagetable_t*)to_higher_half(phys_curr);
    entry_ptr = &table->entries[i2];
    entry     = *entry_ptr;

    if (!(entry & X86_PAGE_FLAG_PRESENT)) {
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
    return false;
do_shatter:
    // Allocate a new Page Table frame.
    // We need a zeroes 4K page for the new table.
    void* new_table_ptr = pmm_alloc_aligned(PAGE_SIZE_SMALL, 1);

    if (!new_table_ptr) {
        release_interrupt_lock(&map->lock);
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
                               X86_PAGE_FLAG_WRITE_THROUGH | x86_PAGE_FLAG_CACHE_DISABLE |
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