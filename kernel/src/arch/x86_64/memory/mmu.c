#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "cpu/cpu.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/arch_mmu.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/paging.h"
#include "memory/pmm.h"
#include "memory/vma.h"
#include "memory/vmm.h"

static int paging_max_levels  = 4;
static bool nx_supported      = false;
static bool pml3_translation  = false;
static bool pku_supported     = false;
static bool pcid_supported    = false;
static bool invpcid_supported = false;

static kmem_cache_t* pcid_cache = nullptr;

static cpu_local_mmu_t* cpu_mmu_states = nullptr;
static uint32_t total_cpu              = 0;

static cpu_local_mmu_t* get_cpu_local_mmu_by_id(uint32_t cpu_id) {
    if (!cpu_mmu_states || cpu_id >= mp_request.response->cpu_count) return nullptr;

    return &cpu_mmu_states[cpu_id];
}

static size_t get_pat_flags(cache_type_t cache, bool is_huge) {
    size_t pat_bit = is_huge ? X86_PAGE_FLAG_LARGE_PAT : X86_PAGE_FLAG_PAT;

    switch (cache) {
        case CACHE_UNCACHEABLE:
            return X86_PAGE_FLAG_CACHE_DISABLE;
        case CACHE_MMIO:
        case CACHE_DEVICE:
            return X86_PAGE_FLAG_CACHE_DISABLE | X86_PAGE_FLAG_WRITE_THROUGH;
        case CACHE_WRITE_THROUGH:
            return X86_PAGE_FLAG_WRITE_THROUGH;
        case CACHE_WRITE_PROTECTED:
            return pat_bit;
        case CACHE_WRITE_COMBINING:
            return pat_bit | X86_PAGE_FLAG_WRITE_THROUGH;
        case CACHE_FRAMEBUFFER:
            return pat_bit | X86_PAGE_FLAG_CACHE_DISABLE;
        case CACHE_ROM:
            return pat_bit | X86_PAGE_FLAG_CACHE_DISABLE | X86_PAGE_FLAG_WRITE_THROUGH;
        case CACHE_WRITE_BACK:
        default:
            return 0;
    }
}

static inline size_t flags_to_arch(uint32_t flags, cache_type_t cache, bool is_huge, uint8_t pkey) {
    size_t arch_flags = 0;

    if (flags & VMM_FLAG_DEMAND)
        arch_flags |= X86_PAGE_FLAG_DEMAND;
    else
        arch_flags |= X86_PAGE_FLAG_PRESENT;

    if (flags & VMM_FLAG_WRITE) arch_flags |= X86_PAGE_FLAG_WRITE;
    if (flags & VMM_FLAG_USER) arch_flags |= X86_PAGE_FLAG_USER;
    if (!(flags & VMM_FLAG_EXECUTE) && nx_supported) arch_flags |= X86_PAGE_FLAG_NX;
    if (flags & VMM_FLAG_GLOBAL) arch_flags |= X86_PAGE_FLAG_GLOBAL;
    if (is_huge) arch_flags |= X86_PAGE_FLAG_HUGE;
    if (pkey > 0 && pku_supported) arch_flags |= ((uint64_t)(pkey & 0xF) << 59);

    return arch_flags | get_pat_flags(cache, is_huge);
}

static inline uint32_t flags_to_generic(size_t arch_flags) {
    uint32_t flags = 0;

    if (arch_flags & X86_PAGE_FLAG_PRESENT) flags |= VMM_FLAG_READ;
    if (arch_flags & X86_PAGE_FLAG_WRITE) flags |= VMM_FLAG_WRITE;
    if (arch_flags & X86_PAGE_FLAG_USER) flags |= VMM_FLAG_USER;
    if (arch_flags & X86_PAGE_FLAG_GLOBAL) flags |= VMM_FLAG_GLOBAL;
    if (!(arch_flags & X86_PAGE_FLAG_NX)) flags |= VMM_FLAG_EXECUTE;

    return flags;
}

static inline size_t resolve_page_size(size_t req_size, uintptr_t virt, uintptr_t phys) {
    // Downgrade 1GB to 2MB if unsupported or unaligned
    if (req_size == PAGE_SIZE_LARGE) {
        if (!pml3_translation || !is_aligned(virt, PAGE_SIZE_LARGE) ||
            (phys && !is_aligned(phys, PAGE_SIZE_LARGE))) {
            req_size = PAGE_SIZE_MEDIUM;
        }
    }

    // Downgrade 2MB to 4KB if unaligned
    if (req_size == PAGE_SIZE_MEDIUM) {
        if (!is_aligned(virt, PAGE_SIZE_MEDIUM) || (phys && !is_aligned(phys, PAGE_SIZE_MEDIUM))) {
            req_size = PAGE_SIZE_SMALL;
        }
    }

    return req_size;
}

static uint64_t* get_pte_cursor(
    uintptr_t root_phys,
    uintptr_t virt_addr,
    int target_level,
    bool allocate,
    uint64_t** cached_table,
    uintptr_t* cached_base
) {
    if (*cached_table != nullptr) {
        int shift            = 12 + (target_level - 1) * 9;
        uintptr_t table_mask = ~((1ul << (shift + 9)) - 1);

        if ((virt_addr & table_mask) == (*cached_base & table_mask)) {
            return &(*cached_table)[(virt_addr >> shift) & 0x1ff];
        }
    }

    uintptr_t curr_phys = root_phys;
    for (int level = paging_max_levels; level > target_level; level--) {
        uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
        int idx         = (int)((virt_addr >> (12 + (level - 1) * 9)) & 0x1ff);
        uint64_t entry  = table[idx];

        if (!(entry & X86_PAGE_FLAG_PRESENT)) {
            if (!allocate) {
                return nullptr;
            }

            void* new_pt = pmm_alloc(1);

            if (!new_pt) {
                return nullptr;
            }

            memset((void*)to_higher_half((uintptr_t)new_pt), 0, PAGE_SIZE_SMALL);

            table[idx] = (uintptr_t)new_pt | X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_WRITE |
                         X86_PAGE_FLAG_USER;
            entry      = table[idx];
        } else if (entry & X86_PAGE_FLAG_HUGE) {
            // You can't have a PML3 translation when the caller
            return nullptr;
        }

        curr_phys = entry & X86_PAGE_ADDRESS_MASK;
    }

    uint64_t* target_table = (uint64_t*)to_higher_half(curr_phys);
    *cached_table          = target_table;
    *cached_base           = virt_addr;

    return &target_table[(virt_addr >> (12 + (target_level - 1) * 9)) & 0x1ff];
}

static uint64_t*
get_existing_pte(uintptr_t root_phys, uintptr_t virt, size_t* out_step_size, int* out_level) {
    uintptr_t curr_phys = root_phys;
    for (int level = paging_max_levels; level >= 1; --level) {
        uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
        int idx         = (int)((virt >> (12 + (level - 1) * 9)) & 0x1ff);
        uint64_t entry  = table[idx];

        if (!(entry & X86_PAGE_FLAG_PRESENT) && !(entry & X86_PAGE_FLAG_DEMAND)) {
            return nullptr;
        }

        if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) {
            if (out_step_size) {
                *out_step_size = (level == 3) ? PAGE_SIZE_LARGE : PAGE_SIZE_MEDIUM;
            }

            if (out_level) {
                *out_level = level;
            }

            return &table[idx];
        } else if (level == 1) {
            if (out_step_size) {
                *out_step_size = PAGE_SIZE_SMALL;
            }

            if (out_level) {
                *out_level = 1;
            }

            return &table[idx];
        }

        curr_phys = entry & X86_PAGE_ADDRESS_MASK;
    }

    return nullptr;
}

int arch_mmu_map(
    arch_pagemap_t* map,
    uintptr_t virt,
    uintptr_t phys,
    size_t length,
    uint32_t flags,
    uint32_t cache,
    uint8_t pkey,
    size_t req_page_size
) {
    if (!map || length == 0 || !arch_is_canonical(virt, paging_max_levels)) {
        return -EINVAL;
    }

    size_t actual_page_size = resolve_page_size(req_page_size, virt, phys);
    size_t arch_flags       = flags_to_arch(flags, cache, actual_page_size > PAGE_SIZE_SMALL, pkey);
    int target_level        = (actual_page_size == PAGE_SIZE_LARGE)
                                  ? 3
                                  : ((actual_page_size == PAGE_SIZE_MEDIUM) ? 2 : 1);

    size_t num_pages = div_roundup(length, actual_page_size);
    bool is_demand   = (flags & VMM_FLAG_DEMAND);

    uint64_t* cached_table = nullptr;
    uintptr_t cached_base  = 0;
    int status             = 0;
    size_t pages_mapped    = 0;
    uintptr_t curr_virt    = virt;

    acquire_spinlock(&map->lock);

    for (size_t i = 0; i < num_pages; ++i) {
        uintptr_t curr_phys = 0;

        if (!is_demand) {
            curr_phys =
                phys ? (phys + (i * actual_page_size))
                     : (
                           uintptr_t
                       )pmm_alloc_aligned(actual_page_size, actual_page_size / PAGE_SIZE_SMALL);

            if (!curr_phys) {
                status = -ENOMEM;
                break;
            }
        }

        uint64_t* pte = get_pte_cursor(
            map->phys_root,
            curr_virt,
            target_level,
            true,
            &cached_table,
            &cached_base
        );

        if (!pte || (*pte & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND))) {
            if (!phys && !is_demand) {
                pmm_free((void*)curr_phys);
            }

            status = pte ? -EEXIST : -EFAULT;
            break;
        }

        *pte = (curr_phys & X86_PAGE_ADDRESS_MASK) | arch_flags;
        curr_virt += actual_page_size;
        pages_mapped++;
    }

    if (status != 0 && pages_mapped > 0) {
        curr_virt    = virt;
        cached_table = nullptr;

        for (size_t i = 0; i < pages_mapped; ++i) {
            uint64_t* pte = get_pte_cursor(
                map->phys_root,
                curr_virt,
                target_level,
                false,
                &cached_table,
                &cached_base
            );

            if (pte && (*pte != 0)) {
                if (!phys && !is_demand && (*pte & X86_PAGE_FLAG_PRESENT)) {
                    uintptr_t phys_addr = *pte & X86_PAGE_ADDRESS_MASK;
                    if ((*pte & X86_PAGE_FLAG_HUGE)) {
                        phys_addr &= ~X86_PAGE_FLAG_LARGE_PAT;
                    }

                    pmm_free((void*)phys_addr);
                }

                *pte = 0;
            }

            curr_virt += actual_page_size;
        }
    }

    release_spinlock(&map->lock);

    if (status == 0) arch_mmu_flush_tlb(map, virt, length);
    return status;
}

static bool unmap_level(
    uintptr_t table_phys,
    int level,
    uintptr_t virt_start,
    uintptr_t virt_end,
    bool free_phys
) {
    uint64_t* table  = (uint64_t*)to_higher_half(table_phys);
    int shift        = 12 + (level - 1) * 9;
    size_t step_size = 1ul << shift;

    uintptr_t curr = virt_start;
    while (curr < virt_end) {
        int idx        = (int)((curr >> shift) & 0x1ff);
        uint64_t entry = table[idx];
        uintptr_t next = align_down(curr, step_size) + step_size;
        if (next == 0 || next > virt_end) next = virt_end;

        if (entry & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND)) {
            if (level == 1 || (entry & X86_PAGE_FLAG_HUGE)) {
                if (free_phys && (entry & X86_PAGE_FLAG_PRESENT)) {
                    uintptr_t phys = entry & X86_PAGE_ADDRESS_MASK;
                    if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) phys &= ~X86_PAGE_FLAG_LARGE_PAT;

                    pmm_dec_ref((void*)phys);
                }

                table[idx] = 0;
            } else {
                bool child_empty =
                    unmap_level(entry & X86_PAGE_ADDRESS_MASK, level - 1, curr, next, free_phys);

                if (child_empty) {
                    pmm_free((void*)(entry & X86_PAGE_ADDRESS_MASK));
                    table[idx] = 0;
                }
            }
        }

        curr = next;
    }

    for (int i = 0; i < 512; i++)
        if (table[i] != 0) return false;
    return true;
}

int arch_mmu_unmap(arch_pagemap_t* map, uintptr_t virt, size_t length, bool free_phys) {
    if (!map || length == 0) return -EINVAL;

    uintptr_t end_virt = virt + length;
    if (end_virt < virt) return -EINVAL;

    acquire_spinlock(&map->lock);
    unmap_level(map->phys_root, paging_max_levels, virt, end_virt, free_phys);
    release_spinlock(&map->lock);

    arch_mmu_flush_tlb(map, virt, length);
    return 0;
}

uintptr_t
arch_mmu_translate(arch_pagemap_t* map, uintptr_t virt, uint32_t* out_flags, size_t* page_size) {
    if (!map || !arch_is_canonical(virt, paging_max_levels)) {
        return 0;
    }

    acquire_spinlock(&map->lock);
    uintptr_t curr_phys   = map->phys_root;
    uintptr_t result_phys = 0;

    for (int level = paging_max_levels; level >= 1; level--) {
        uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
        int idx         = (int)((virt >> (12 + (level - 1) * 9)) & 0x1ff);
        uint64_t entry  = table[idx];

        if (!(entry & X86_PAGE_FLAG_PRESENT) && !(entry & X86_PAGE_FLAG_DEMAND)) {
            break;
        }

        if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) {
            size_t page_mask    = (level == 3) ? (PAGE_SIZE_LARGE - 1) : (PAGE_SIZE_MEDIUM - 1);
            uintptr_t base_phys = entry & X86_PAGE_ADDRESS_MASK;
            base_phys &= ~X86_PAGE_FLAG_LARGE_PAT;
            result_phys = base_phys + (virt & page_mask);

            if (out_flags) {
                *out_flags = flags_to_generic(entry);
            }

            if (page_size) {
                *page_size = (level == 3) ? PAGE_SIZE_LARGE : PAGE_SIZE_MEDIUM;
            }

            break;
        } else if (level == 1) {
            result_phys = (entry & X86_PAGE_ADDRESS_MASK) + (virt & (PAGE_SIZE_SMALL - 1));

            if (out_flags) {
                *out_flags = flags_to_generic(entry);
            }

            if (page_size) {
                *page_size = PAGE_SIZE_SMALL;
            }

            break;
        }

        curr_phys = entry & X86_PAGE_ADDRESS_MASK;
    }

    release_spinlock(&map->lock);
    return result_phys;
}

void arch_mmu_load(arch_pagemap_t* map) {
    uint64_t val = map->phys_root & X86_PAGE_ADDRESS_MASK;

    if (pcid_supported) {
        uint32_t cpu_id = arch_get_core_idx();
        val |= (map->pcids[cpu_id] & 0xfff) | (1ULL << 63);
    }

    write_cr3(val);
}

#define TLB_FLUSH_THRESHOLD 64
void arch_mmu_flush_local(arch_pagemap_t* map, uintptr_t virt, size_t length, uint32_t cpu_id) {
    uint64_t cr3 = read_cr3();
    size_t pages = div_roundup(length, PAGE_SIZE_SMALL);

    if ((cr3 & X86_PAGE_ADDRESS_MASK) != (map->phys_root & X86_PAGE_ADDRESS_MASK)) return;

    bool has_pcid = (pcid_supported && invpcid_supported && map->pcids && map->pcids[cpu_id] != 0);
    if (pages > TLB_FLUSH_THRESHOLD) {
        if (has_pcid)
            invpcid(INVPCID_SINGLE_CONTEXT, map->pcids[cpu_id], 0);
        else
            arch_mmu_load(map);
    } else {
        uintptr_t end = virt + length;

        if (has_pcid) {
            uint64_t pcid = map->pcids[cpu_id];
            for (uintptr_t addr = virt; addr < end; addr += PAGE_SIZE_SMALL)
                invpcid(INVPCID_INDIVIDUAL_ADDR, pcid, addr);
        } else {
            for (uintptr_t addr = virt; addr < end; addr += PAGE_SIZE_SMALL) invlpg((void*)addr);
        }
    }
}

void arch_mmu_flush_tlb(arch_pagemap_t* map, uintptr_t virt, size_t length) {
    if (!map || length == 0) return;

    size_t flags = arch_save_flags();
    arch_disable_interrupts();

    uint64_t cr3    = read_cr3();
    uint32_t cpu_id = arch_get_core_idx();
    size_t pages    = div_roundup(length, PAGE_SIZE_SMALL);

    smp_tlb_shootdown(map, virt, pages);
    arch_mmu_flush_local(map, virt, length, cpu_id);

    arch_restore_flags(flags);
}

int arch_mmu_remap(arch_pagemap_t* map, uintptr_t old_virt, uintptr_t new_virt, size_t length) {
    if (!map || length == 0) return -EINVAL;

    if (!arch_is_canonical(old_virt, paging_max_levels) ||
        !arch_is_canonical(new_virt, paging_max_levels))
        return -EINVAL;

    if (old_virt == new_virt) return 0;

    acquire_spinlock(&map->lock);

    bool backwards = (new_virt > old_virt) && (new_virt < old_virt + length);

    uintptr_t curr_old = backwards ? (old_virt + length) : old_virt;
    uintptr_t curr_new = backwards ? (new_virt + length) : new_virt;
    size_t remaining   = length;

    uint64_t* new_cached_table = nullptr;
    uintptr_t new_cached_base  = 0;

    int status = 0;

    while (remaining > 0) {
        uintptr_t probe_old;
        if (backwards)
            probe_old = curr_old - PAGE_SIZE_SMALL;
        else
            probe_old = curr_old;

        size_t step_size  = PAGE_SIZE_SMALL;
        int level         = 1;
        uint64_t* old_pte = get_existing_pte(map->phys_root, probe_old, &step_size, &level);

        if (backwards && old_pte && level > 1) {
            uintptr_t huge_base = probe_old & ~(step_size - 1);
            if (huge_base < old_virt) {
                arch_mmu_shatter(map, probe_old);
                continue;
            }

            probe_old = huge_base;
        }

        if (!old_pte || *old_pte == 0) {
            step_size = PAGE_SIZE_SMALL;
        } else {
            uintptr_t target_new = backwards ? (curr_new - step_size) : curr_new;

            if (level > 1) {
                if (remaining < step_size || !is_aligned(target_new, step_size)) {
                    arch_mmu_shatter(map, probe_old);
                    continue;
                }
            }

            uint64_t* new_pte = get_pte_cursor(
                map->phys_root,
                target_new,
                level,
                true,
                &new_cached_table,
                &new_cached_base
            );

            if (!new_pte) {
                status = -ENOMEM;
                break;
            }

            if (*new_pte & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND)) {
                status = -EEXIST;
                break;
            }

            *new_pte = *old_pte;
            *old_pte = 0;
        }

        if (backwards) {
            curr_old -= step_size;
            curr_new -= step_size;
        } else {
            curr_old += step_size;
            curr_new += step_size;
        }

        remaining -= step_size;
    }

    release_spinlock(&map->lock);

    arch_mmu_flush_tlb(map, old_virt, length);
    arch_mmu_flush_tlb(map, new_virt, length);

    return status;
}

int arch_mmu_allocate_pcid(arch_pagemap_t* map) {
    if (!pcid_supported) {
        return 0;
    }

    uint32_t cpu_id = arch_get_core_idx();

    if (cpu_id >= map->pcids_capacity) {
        return -ERANGE;
    }

    acquire_spinlock(&map->lock);

    if (map->pcids[cpu_id] != 0) {
        release_spinlock(&map->lock);
        return 0;
    }

    release_spinlock(&map->lock);

    cpu_local_mmu_t* cpu_mmu = get_cpu_local_mmu_by_id(cpu_id);
    int allocated_pcid       = -1;

    acquire_spinlock(&cpu_mmu->pcid_lock);

    for (int i = 0; i < 64; ++i) {
        if (cpu_mmu->pcid_bitmap[i] == UINT64_MAX) {
            continue;
        }

        for (int bit = 0; bit < 64; ++bit) {
            int pcid = (i * 64) + bit;

            if (pcid == 0) {
                // Reserved for kernel/idle
                continue;
            }

            if (!(cpu_mmu->pcid_bitmap[i] & (1ul << bit))) {
                cpu_mmu->pcid_bitmap[i] |= (1ul << bit);
                allocated_pcid = pcid;
                break;
            }
        }

        if (allocated_pcid != -1) {
            break;
        }
    }

    release_spinlock(&cpu_mmu->pcid_lock);

    if (allocated_pcid == -1) {
        return -EBUSY;
    }

    acquire_spinlock(&map->lock);
    map->pcids[cpu_id] = allocated_pcid;
    release_spinlock(&map->lock);

    return 0;
}

void arch_mmu_free_pcid(arch_pagemap_t* map) {
    if (!pcid_supported || !map->pcids) {
        return;
    }

    acquire_spinlock(&map->lock);

    for (uint32_t cpu = 0; cpu < map->pcids_capacity; ++cpu) {
        uint16_t pcid = map->pcids[cpu];

        if (pcid != 0) {
            cpu_local_mmu_t* cpu_mmu = get_cpu_local_mmu_by_id(cpu);

            if (cpu_mmu) {
                acquire_spinlock(&cpu_mmu->pcid_lock);
                int idx = pcid / 64;
                int bit = pcid % 64;
                cpu_mmu->pcid_bitmap[idx] &= ~(1ul << bit);
                release_spinlock(&cpu_mmu->pcid_lock);
            }

            map->pcids[cpu] = 0;
        }
    }

    kmem_cache_free(pcid_cache, map->pcids);
    map->pcids          = nullptr;
    map->pcids_capacity = 0;

    release_spinlock(&map->lock);
}

int arch_mmu_allocate_pkey(arch_pagemap_t* map) {
    if (!pku_supported) {
        return -EBADF;
    }

    acquire_spinlock(&map->lock);

    for (int i = 0; i < X86_MAX_PKEYS; ++i) {
        if (!(map->active_pkeys & (1 << i))) {
            map->active_pkeys |= (1 << i);
            release_spinlock(&map->lock);
            return i;
        }
    }

    release_spinlock(&map->lock);

    return -EBUSY;
}

// TODO: Expose it as a syscall
void arch_mmu_write_pkru(arch_pagemap_t* map) {
    if (!pku_supported || !map) {
        return;
    }

    // 01 (Access disable) for all keys
    uint32_t pkru_val = 0x55555555;

    // Grant full access to key 0
    pkru_val &= ~(3u);

    for (int i = 0; i < X86_MAX_PKEYS; ++i) {
        if (map->active_pkeys & (1 << i)) {
            pkru_val &= ~(3u << (i * 2));
        }
    }

    asm volatile("wrpkru" ::"a"(pkru_val), "c"(0), "d"(0));
}

int arch_mmu_create(arch_pagemap_t* map) {
    if (!map) {
        return -EINVAL;
    }

    create_spinlock(&map->lock);
    map->active_pkeys = 0;

    void* root_frame = pmm_alloc(1);
    if (!root_frame) {
        return -ENOMEM;
    }

    map->phys_root  = (uintptr_t)root_frame;
    uint64_t* table = (uint64_t*)to_higher_half(map->phys_root);

    memset(table, 0, 256 * sizeof(uint64_t));

    arch_pagemap_t* kernel_map = (arch_pagemap_t*)vmm_get_kernel_pagemap();
    if (kernel_map && kernel_map != map) {
        uint64_t* kernel_table = (uint64_t*)to_higher_half(kernel_map->phys_root);
        memcpy(&table[256], &kernel_table[256], 256 * sizeof(uint64_t));
    } else {
        memset(&table[256], 0, 256 * sizeof(uint64_t));
    }

    if (pcid_supported) {
        uint32_t cpu_count = mp_request.response->cpu_count;
        map->pcids         = (uint16_t*)kmem_cache_alloc(pcid_cache);

        if (!map->pcids) {
            pmm_free(root_frame);
            map->phys_root = 0;
            return -ENOMEM;
        }

        map->pcids_capacity = cpu_count;
    } else {
        map->pcids          = nullptr;
        map->pcids_capacity = 0;
    }

    return 0;
}

void arch_mmu_destroy(arch_pagemap_t* map) {
    if (!map) {
        return;
    }

    arch_mmu_free_pcid(map);

    uint64_t current_cr3 = read_cr3();

    if ((current_cr3 & X86_PAGE_ADDRESS_MASK) == (map->phys_root & X86_PAGE_ADDRESS_MASK)) {
        arch_pagemap_t* kernel_map = (arch_pagemap_t*)vmm_get_kernel_pagemap();

        if (kernel_map) {
            arch_mmu_load(kernel_map);
        }
    }

    if (map->phys_root) {
        pmm_free((void*)map->phys_root);
        map->phys_root = 0;
    }
}

void arch_mmu_init(void) {
    bool has_pge  = cpu_has_feature(FEATURE_PGE);
    bool has_la57 = cpu_has_feature(FEATURE_LA57);

    pcid_supported    = cpu_has_feature(FEATURE_PCID);
    invpcid_supported = cpu_has_feature(FEATURE_INVPCID);
    pku_supported     = cpu_has_feature(FEATURE_PKU);

    bool has_smep = cpu_has_feature(FEATURE_SMEP);
    bool has_smap = cpu_has_feature(FEATURE_SMAP);

    nx_supported     = cpu_has_feature(FEATURE_XD);
    pml3_translation = cpu_has_feature(FEATURE_PDPE1GB);

    if (nx_supported) {
        write_msr(X86_MSR_IA32_EFER, read_msr(X86_MSR_IA32_EFER) | X86_EFER_NXE);
    }

    uint64_t cr4 = read_cr4();

    if (has_pge) {
        cr4 |= X86_CR4_PGE;
    }

    if (has_smep) {
        cr4 |= X86_CR4_SMEP;
    }

    if (pku_supported) {
        cr4 |= X86_CR4_PKE;
    }

    if (pcid_supported) {
        cr4 |= X86_CR4_PCIDE;
    }

    if (has_la57 && (cr4 & X86_CR4_LA57)) {
        paging_max_levels = 5;
    } else {
        paging_max_levels = 4;
    }

    write_cr4(cr4);

    uint64_t cr0 = read_cr0();
    cr0 |= X86_CR0_WP;
    cr0 |= X86_CR0_PG;
    write_cr0(cr0);

    uint64_t pat = 0;

    // Index 0: PWT=0, PCD=0 -> WB (Write Back) - Default
    pat |= X86_PAT_TYPE_WRITE_BACK << 0;

    // Index 1: PWT=1, PCD=0 -> WT (Write Through)
    pat |= X86_PAT_TYPE_WRITE_THROUGH << 8;

    // Index 2: PWT=0, PCD=1 -> UC- (Uncacheable Minus)
    // We use UC- (0x07) here so MTRRs can override it if necessary.
    pat |= X86_PAT_TYPE_UNCACHEABLE_MINUS << 16;

    // Index 3: PWT=1, PCD=1 -> UC (String Uncacheable) - MMIO/Device
    pat |= X86_PAT_TYPE_UNCACHEABLE << 24;

    // Index 4: PAT=1, PWT=0, PCD=0 -> WP (Write Proctected)
    pat |= X86_PAT_TYPE_WRITE_PROTECT << 32;

    // Index 5: PAT=1, PWT=1, PCD=0 -> WC (Write Combining)
    pat |= X86_PAT_TYPE_WRITE_COMBINING << 40;

    // Index 6: PAT=1, PWT=0, PCD=1 -> WC - Framebuffer (useful for debugging)
    // Turn this to X86_PAT_TYPE_UNCACHEABLE for debugging visual artifacts
    pat |= X86_PAT_TYPE_WRITE_COMBINING << 48;

    // Index 7: PAT=1, PWT=1, PCD=1 -> WP - ACPI Tables
    pat |= X86_PAT_TYPE_WRITE_PROTECT << 56;

    write_msr(X86_MSR_IA32_PAT, pat);

    uint32_t cpu_count = mp_request.response->cpu_count;

    cpu_mmu_states = kmalloc(cpu_count * sizeof(cpu_local_mmu_t));

    for (uint32_t i = 0; i < cpu_count; ++i) {
        create_spinlock(&cpu_mmu_states[i].pcid_lock);
    }

    pcid_cache = kmem_cache_create(
        "pcid_cache",
        cpu_count * sizeof(uint16_t),
        _Alignof(uint16_t),
        0,
        nullptr
    );
}

const uintptr_t get_user_space_end_limit(void) {
    return (paging_max_levels == 5) ? USER_SPACE_END_5L : USER_SPACE_END_4L;
}

void arch_mmu_free_pkey(arch_pagemap_t* map, uint8_t pkey) {
    if (!pku_supported || !map || pkey == 0 || pkey >= X86_MAX_PKEYS) {
        return;
    }

    acquire_spinlock(&map->lock);

    map->active_pkeys &= ~(1 << pkey);

    release_spinlock(&map->lock);
}

int arch_mmu_protect(
    arch_pagemap_t* map,
    uintptr_t virt,
    size_t length,
    uint32_t flags,
    cache_type_t cache,
    uint8_t pkey
) {
    if (!map || length == 0 || !arch_is_canonical(virt, paging_max_levels)) {
        return -EINVAL;
    }

    uintptr_t curr_virt = virt;
    uintptr_t end_virt  = virt + length;
    int status          = 0;

    acquire_spinlock(&map->lock);

    while (curr_virt < end_virt) {
        uintptr_t curr_phys = map->phys_root;
        uint64_t* pte       = nullptr;
        size_t step_size    = PAGE_SIZE_SMALL;
        bool is_huge        = false;

        for (int level = paging_max_levels; level >= 1; level--) {
            uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
            int idx         = (int)((curr_virt >> (12 + (level - 1) * 9)) & 0x1ff);
            uint64_t entry  = table[idx];

            if (!(entry & X86_PAGE_FLAG_PRESENT) && !(entry & X86_PAGE_FLAG_DEMAND)) {
                break;
            }

            if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) {
                pte       = &table[idx];
                step_size = (level == 3) ? PAGE_SIZE_LARGE : PAGE_SIZE_MEDIUM;
                is_huge   = true;
                break;
            } else if (level == 1) {
                pte       = &table[idx];
                step_size = PAGE_SIZE_SMALL;
                is_huge   = false;
                break;
            }

            curr_phys = entry & X86_PAGE_ADDRESS_MASK;
        }

        if (pte) {
            uint64_t preserved_bits =
                *pte & (X86_PAGE_ADDRESS_MASK | X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND |
                        X86_PAGE_FLAG_HUGE | X86_PAGE_FLAG_ACCESSED | X86_PAGE_FLAG_DIRTY);

            if (is_huge) {
                preserved_bits &=
                    ~(X86_PAGE_FLAG_LARGE_PAT | X86_PAGE_FLAG_CACHE_DISABLE |
                      X86_PAGE_FLAG_WRITE_THROUGH);
            } else {
                preserved_bits &=
                    ~(X86_PAGE_FLAG_PAT | X86_PAGE_FLAG_CACHE_DISABLE |
                      X86_PAGE_FLAG_WRITE_THROUGH);
            }

            size_t arch_flags = flags_to_arch(flags, cache, is_huge, pkey);

            arch_flags &= ~(X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND | X86_PAGE_FLAG_HUGE);

            *pte = preserved_bits | arch_flags;
        } else {
            status = -ENOENT;
            break;
        }

        curr_virt += step_size;
    }

    release_spinlock(&map->lock);

    arch_mmu_flush_tlb(map, virt, length);

    return status;
}

#define PTE_PRESERVED_FLAGS                                                                      \
    (X86_PAGE_ADDRESS_MASK | X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND | X86_PAGE_FLAG_HUGE | \
     X86_PAGE_FLAG_DIRTY | X86_PAGE_FLAG_ACCESSED | X86_PAGE_FLAG_LARGE_PAT | X86_PAGE_FLAG_PAT)

int arch_mmu_shatter(arch_pagemap_t* map, uintptr_t virt) {
    if (!map || !arch_is_canonical(virt, paging_max_levels)) {
        return -EINVAL;
    }

    void* new_pt = pmm_alloc(1);
    if (!new_pt) {
        return -ENOMEM;
    }

    uint64_t* new_table = (uint64_t*)to_higher_half((uintptr_t)new_pt);

    acquire_spinlock(&map->lock);

    uintptr_t curr_phys = map->phys_root;
    uint64_t* pte       = nullptr;
    int hit_level       = 0;

    for (int level = paging_max_levels; level >= 1; level--) {
        uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
        int idx         = (int)((virt >> (12 + (level - 1) * 9)) & 0x1ff);
        uint64_t entry  = table[idx];

        if (!(entry & X86_PAGE_FLAG_PRESENT) && !(entry & X86_PAGE_FLAG_DEMAND)) {
            release_spinlock(&map->lock);
            pmm_free(new_pt);
            return -ENOENT;
        }

        if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) {
            pte       = &table[idx];
            hit_level = level;
            break;
        } else if (level == 1) {
            release_spinlock(&map->lock);
            pmm_free(new_pt);
            return 0;
        }

        curr_phys = entry & X86_PAGE_ADDRESS_MASK;
    }

    if (!pte) {
        release_spinlock(&map->lock);
        pmm_free(new_pt);
        return -ENOENT;
    }

    uint64_t entry      = *pte;
    uintptr_t base_phys = entry & X86_PAGE_ADDRESS_MASK;

    if (hit_level > 1) {
        base_phys &= ~X86_PAGE_FLAG_LARGE_PAT;
    }

    size_t flags = entry & ~(X86_PAGE_ADDRESS_MASK | X86_PAGE_FLAG_HUGE | X86_PAGE_FLAG_LARGE_PAT);
    if (entry & X86_PAGE_FLAG_LARGE_PAT) {
        flags |= X86_PAGE_FLAG_PAT;
    }

    size_t step_size   = (hit_level == 3) ? PAGE_SIZE_MEDIUM : PAGE_SIZE_SMALL;
    size_t child_flags = flags | ((hit_level == 3) ? X86_PAGE_FLAG_HUGE : 0);

    for (int i = 0; i < 512; i++) {
        new_table[i] = base_phys | child_flags;
        base_phys += step_size;
    }

    size_t dir_flags = X86_PAGE_FLAG_PRESENT;
    if (entry & X86_PAGE_FLAG_USER) dir_flags |= X86_PAGE_FLAG_USER;
    if (entry & X86_PAGE_FLAG_WRITE) dir_flags |= X86_PAGE_FLAG_WRITE;
    *pte = (uintptr_t)new_pt | dir_flags;

    release_spinlock(&map->lock);

    arch_mmu_flush_tlb(
        map,
        virt & ~((hit_level == 3 ? PAGE_SIZE_LARGE : PAGE_SIZE_MEDIUM) - 1),
        hit_level == 3 ? PAGE_SIZE_LARGE : PAGE_SIZE_MEDIUM
    );

    return 0;
}

int arch_mmu_collapse(arch_pagemap_t* map, uintptr_t virt) {
    if (!map || !is_aligned(virt, PAGE_SIZE_MEDIUM)) {
        return -EINVAL;
    }

    acquire_spinlock(&map->lock);

    uintptr_t curr_phys = map->phys_root;
    for (int level = paging_max_levels; level > 2; level--) {
        uint64_t* table = (uint64_t*)to_higher_half(curr_phys);
        uint64_t entry  = table[(virt >> (12 + (level - 1) * 9)) & 0x1ff];

        if (!(entry & X86_PAGE_FLAG_PRESENT) || (entry & X86_PAGE_FLAG_HUGE)) {
            release_spinlock(&map->lock);
            return -ENOENT;
        }

        curr_phys = entry & X86_PAGE_ADDRESS_MASK;
    }

    uint64_t* pde = &((uint64_t*)to_higher_half(curr_phys))[(virt >> 21) & 0x1ff];

    if (!(*pde & X86_PAGE_FLAG_PRESENT)) {
        release_spinlock(&map->lock);
        return -ENOENT;
    }
    if (*pde & X86_PAGE_FLAG_HUGE) {
        release_spinlock(&map->lock);
        return 0;
    }

    uintptr_t pt_phys = *pde & X86_PAGE_ADDRESS_MASK;
    uint64_t* pt      = (uint64_t*)to_higher_half(pt_phys);

    if (!(pt[0] & X86_PAGE_FLAG_PRESENT)) {
        release_spinlock(&map->lock);
        return -ENOENT;
    }

    uintptr_t base_phys = pt[0] & X86_PAGE_ADDRESS_MASK;
    if (!is_aligned(base_phys, PAGE_SIZE_MEDIUM)) {
        release_spinlock(&map->lock);
        return -EINVAL;
    }

    uint64_t expected_entry = pt[0];

    for (int i = 1; i < 512; i++) {
        expected_entry += PAGE_SIZE_SMALL;

        if (pt[i] != expected_entry) {
            release_spinlock(&map->lock);
            return -EINVAL;
        }
    }

    size_t new_flags = (pt[0] & ~X86_PAGE_ADDRESS_MASK) | X86_PAGE_FLAG_HUGE;
    if (new_flags & X86_PAGE_FLAG_PAT) {
        new_flags = (new_flags & ~X86_PAGE_FLAG_PAT) | X86_PAGE_FLAG_LARGE_PAT;
    }

    *pde = base_phys | new_flags;

    release_spinlock(&map->lock);

    pmm_free((void*)pt_phys);
    arch_mmu_flush_tlb(map, virt, PAGE_SIZE_MEDIUM);
    return 0;
}

bool arch_mmu_test_and_clear_dirty(arch_pagemap_t* map, uintptr_t virt) {
    if (!map) {
        return false;
    }

    acquire_spinlock(&map->lock);
    uintptr_t curr_phys = map->phys_root;
    bool dirty          = false;
    size_t flush_size   = PAGE_SIZE_SMALL;

    for (int level = paging_max_levels; level >= 1; level--) {
        uint64_t* pte =
            &((uint64_t*)to_higher_half(curr_phys))[(virt >> (12 + (level - 1) * 9)) & 0x1ff];

        if (!(*pte & X86_PAGE_FLAG_PRESENT)) {
            break;
        }

        if (level == 1 || (*pte & X86_PAGE_FLAG_HUGE)) {
            if (*pte & X86_PAGE_FLAG_DIRTY) {
                dirty = true;
                *pte &= ~X86_PAGE_FLAG_DIRTY;
                flush_size = (level == 1) ? PAGE_SIZE_SMALL
                                          : ((level == 2) ? PAGE_SIZE_MEDIUM : PAGE_SIZE_LARGE);
            }

            break;
        }

        curr_phys = *pte & X86_PAGE_ADDRESS_MASK;
    }

    release_spinlock(&map->lock);

    if (dirty) {
        arch_mmu_flush_tlb(map, virt, flush_size);
    }

    return dirty;
}

bool arch_mmu_test_and_clear_accessed(arch_pagemap_t* map, uintptr_t virt) {
    if (!map) {
        return false;
    }

    acquire_spinlock(&map->lock);
    uintptr_t curr_phys = map->phys_root;
    bool accessed       = false;
    size_t flush_size   = PAGE_SIZE_SMALL;

    for (int level = paging_max_levels; level >= 1; level--) {
        uint64_t* pte =
            &((uint64_t*)to_higher_half(curr_phys))[(virt >> (12 + (level - 1) * 9)) & 0x1ff];

        if (!(*pte & X86_PAGE_FLAG_PRESENT)) {
            break;
        }

        if (level == 1 || (*pte & X86_PAGE_FLAG_HUGE)) {
            if (*pte & X86_PAGE_FLAG_ACCESSED) {
                accessed = true;
                *pte &= ~X86_PAGE_FLAG_ACCESSED;
                flush_size = (level == 1) ? PAGE_SIZE_SMALL
                                          : ((level == 2) ? PAGE_SIZE_MEDIUM : PAGE_SIZE_LARGE);
            }

            break;
        }

        curr_phys = *pte & X86_PAGE_ADDRESS_MASK;
    }

    release_spinlock(&map->lock);

    if (accessed) {
        arch_mmu_flush_tlb(map, virt, flush_size);
    }

    return accessed;
}

static void free_table_recursive(uintptr_t phys_addr, int level) {
    uint64_t* table = (uint64_t*)to_higher_half(phys_addr);
    int max_idx     = (level == paging_max_levels) ? 256 : 512;

    for (int i = 0; i < max_idx; i++) {
        uint64_t entry = table[i];
        if (!(entry & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND))) continue;

        if (level == 1 || (entry & X86_PAGE_FLAG_HUGE)) {
            if (entry & X86_PAGE_FLAG_PRESENT) {
                uintptr_t phys = entry & X86_PAGE_ADDRESS_MASK;
                if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) phys &= ~X86_PAGE_FLAG_LARGE_PAT;

                pmm_dec_ref((void*)phys);
            }
        } else {
            free_table_recursive(entry & X86_PAGE_ADDRESS_MASK, level - 1);
        }
    }

    pmm_free((void*)phys_addr);
}

static int clone_table(uintptr_t dest_phys, uintptr_t src_phys, int level) {
    uint64_t* dest = (uint64_t*)to_higher_half(dest_phys);
    uint64_t* src  = (uint64_t*)to_higher_half(src_phys);

    int max_idx = (level == paging_max_levels) ? 256 : 512;
    int status  = 0;

    for (int i = 0; i < max_idx; i++) {
        uint64_t entry = src[i];

        if (!(entry & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND))) continue;

        if (level == 1 || (entry & X86_PAGE_FLAG_HUGE)) {
            if (entry & X86_PAGE_FLAG_WRITE) {
                entry  = (entry & ~X86_PAGE_FLAG_WRITE) | X86_PAGE_FLAG_DEMAND;
                src[i] = entry;
            }

            if (entry & X86_PAGE_FLAG_PRESENT) {
                uintptr_t phys_addr = entry & X86_PAGE_ADDRESS_MASK;
                if (level > 1 && (entry & X86_PAGE_FLAG_HUGE)) {
                    phys_addr &= ~X86_PAGE_FLAG_LARGE_PAT;
                }

                pmm_inc_ref((void*)phys_addr);
            }

            dest[i] = entry;
        } else {
            void* new_pt = pmm_alloc(1);
            if (!new_pt) {
                status = -ENOMEM;
                goto cleanup_on_error;
            }

            memset((void*)to_higher_half((uintptr_t)new_pt), 0, PAGE_SIZE_SMALL);

            // Inherit the USER flag from the parent directory
            size_t dir_flags = X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_WRITE;
            if (entry & X86_PAGE_FLAG_USER) dir_flags |= X86_PAGE_FLAG_USER;

            dest[i] = (uintptr_t)new_pt | dir_flags;

            status = clone_table((uintptr_t)new_pt, entry & X86_PAGE_ADDRESS_MASK, level - 1);
            if (status != 0) {
                pmm_free(new_pt);
                dest[i] = 0;
                goto cleanup_on_error;
            }
        }

        continue;

    cleanup_on_error:
        for (int j = 0; j < i; j++) {
            uint64_t clean_entry = dest[j];
            if (!(clean_entry & (X86_PAGE_FLAG_PRESENT | X86_PAGE_FLAG_DEMAND))) continue;

            if (level == 1 || (clean_entry & X86_PAGE_FLAG_HUGE)) {
                if (clean_entry & X86_PAGE_FLAG_PRESENT) {
                    uintptr_t phys_addr = clean_entry & X86_PAGE_ADDRESS_MASK;
                    if (level > 1 && (clean_entry & X86_PAGE_FLAG_HUGE))
                        phys_addr &= ~X86_PAGE_FLAG_LARGE_PAT;

                    pmm_dec_ref((void*)phys_addr);
                }
            } else {
                free_table_recursive(clean_entry & X86_PAGE_ADDRESS_MASK, level - 1);
            }

            dest[j] = 0;
        }

        return status;
    }

    return 0;
}

int arch_mmu_clone(arch_pagemap_t* dest, arch_pagemap_t* src) {
    if (!dest || !src || dest == src) return -EINVAL;

    if ((uintptr_t)dest < (uintptr_t)src) {
        acquire_spinlock(&dest->lock);
        acquire_spinlock(&src->lock);
    } else {
        acquire_spinlock(&src->lock);
        acquire_spinlock(&dest->lock);
    }

    int status = clone_table(dest->phys_root, src->phys_root, paging_max_levels);

    uint64_t cr3 = read_cr3();
    if ((cr3 & X86_PAGE_ADDRESS_MASK) == (src->phys_root & X86_PAGE_ADDRESS_MASK)) {
        if (pcid_supported && invpcid_supported) {
            uint32_t cpu_id = arch_get_core_idx();
            invpcid(INVPCID_SINGLE_CONTEXT, src->pcids[cpu_id], 0);
        } else {
            write_cr3(cr3);
        }
    }

    if ((uintptr_t)dest < (uintptr_t)src) {
        release_spinlock(&src->lock);
        release_spinlock(&dest->lock);
    } else {
        release_spinlock(&dest->lock);
        release_spinlock(&src->lock);
    }

    return status;
}

void arch_mmu_sync_kernel(arch_pagemap_t* target_map) {
    arch_pagemap_t* kernel_map = (arch_pagemap_t*)vmm_get_kernel_pagemap();

    if (!target_map || !kernel_map || kernel_map == target_map) {
        return;
    }

    acquire_spinlock(&target_map->lock);

    memcpy(
        &((uint64_t*)to_higher_half(target_map->phys_root))[256],
        &((uint64_t*)to_higher_half(kernel_map->phys_root))[256],
        256 * sizeof(uint64_t)
    );

    release_spinlock(&target_map->lock);
}

bool vmm_is_user_region(uintptr_t addr, size_t size) {
    return (addr >= USER_SPACE_START) && ((addr + size) <= get_user_space_end_limit());
}