#include "memory/pmm.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "boot/boot.h"
#include "boot/limine.h"
#include "compiler.h"
#include "libs/dlist.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"

#define PAGE_SIZE     PAGE_SIZE_SMALL
#define PMM_MAX_ORDER 11  // 2^11 pages = 8MB max contiguous block
#define PAGE_SHIFT    PAGE_SHIFT_SMALL

#define MAX_ZONES 3

#define ZONE_ID_DMA    0  // < 16 MB
#define ZONE_ID_DMA32  1  // < 4 GB
#define ZONE_ID_NORMAL 2  // > 4 GB

#define SECTION_SHIFT     27  // 2^27 = 128MB Sections
#define SECTION_SIZE      (1ul << SECTION_SHIFT)
#define SECTION_MASK      (SECTION_SIZE - 1)
#define PAGES_PER_SECTION (SECTION_SIZE / PAGE_SIZE)

#define MAX_PHYSMEM_BITS 48  // 48-bit physical address space
#define MAX_SECTIONS     (1ul << (MAX_PHYSMEM_BITS - SECTION_SHIFT))

#define ZONE_DMA_LIMIT    (PAGE_SIZE_MEDIUM * 16)  // 16MB
#define ZONE_DMA32_LIMIT  (PAGE_SIZE_LARGE * 4)    // 4GB
#define ZONE_NORMAL_LIMIT ((uintptr_t)-1)          // 4GB - MAX

#define PAGE_ZONE_MASK 0x0f
#define PAGE_FLAG_USED (1 << 7)

#define REF_SATURATION UINT16_MAX
#define PCP_BATCH_SIZE 16

struct free_area {
    struct dlist_head list;
};

struct mem_section {
    struct page* map;  // Array of pages, allocated only if section exists
};

struct zone {
    struct dlist_head free_areas[PMM_MAX_ORDER + 1];
    uint16_t free_mask;
    spinlock_t lock;
    uintptr_t limit;
    atomic_size_t free_count[PMM_MAX_ORDER + 1];
};

static struct mem_section* mem_sections = nullptr;
static struct zone zones[MAX_ZONES]     = {0};
static int active_zone_count            = 0;

static struct {
    uintptr_t limit;
} zone_config[MAX_ZONES] = {
    {ZONE_DMA_LIMIT},
    {ZONE_DMA32_LIMIT},
    {ZONE_NORMAL_LIMIT},
};

static size_t section_count           = 0;
static atomic_size_t stat_used_bytes  = 0;
static atomic_size_t stat_total_bytes = 0;

static int get_zone_id_from_phys(uintptr_t phys) {
    for (int i = 0; i < active_zone_count; ++i) {
        if (phys < zones[i].limit) {
            return i;
        }
    }

    // Fall back to last zone
    return active_zone_count - 1;
}

static inline void set_page_zone(struct page* page, int zone_id) {
    page->flags &= ~PAGE_ZONE_MASK;
    page->flags |= (zone_id & PAGE_ZONE_MASK);
}

static inline int get_page_zone_id(struct page* page) {
    return page->flags & PAGE_ZONE_MASK;
}

static inline int get_order(size_t count) {
    if (unlikely(count == 0)) {
        return 0;
    }

    int order = 64 - clz(count - 1);
    return order;
}

static inline void mask_set(struct zone* zone, int order) {
    zone->free_mask |= (1 << order);
}

static inline void mask_clear_if_empty(struct zone* zone, int order) {
    if (dlist_empty(&zone->free_areas[order])) {
        zone->free_mask &= ~(1 << order);
    }
}

struct page* phys_to_page(uintptr_t phys) {
    size_t sec_idx = phys >> SECTION_SHIFT;

    if (unlikely(sec_idx >= section_count || !mem_sections[sec_idx].map)) {
        return nullptr;
    }

    return &mem_sections[sec_idx].map[(phys & SECTION_MASK) >> PAGE_SHIFT];
}

static int zone_to_id(struct zone* zone) {
    return (int)(zone - zones);
}

static inline uintptr_t page_to_phys(struct page* page) {
    uint32_t sec_idx      = page->buddy.section_idx;
    struct page* map_base = mem_sections[sec_idx].map;

    size_t page_idx = (size_t)(page - map_base);
    return ((uintptr_t)sec_idx << SECTION_SHIFT) + (page_idx << PAGE_SHIFT);
}

static inline struct dlist_head* page_to_list_node(struct page* page) {
    uintptr_t phys = page_to_phys(page);
    return &((struct free_area*)to_higher_half(phys))->list;
}

static inline struct page* list_node_to_page(struct dlist_head* node) {
    uintptr_t phys = from_higher_half((uintptr_t)node);
    return phys_to_page(phys);
}

static void buddy_insert(struct zone* zone, struct page* page, int order) {
    int z_id = zone_to_id(zone);

    uint8_t flags = page->flags & ~(PAGE_FLAG_USED | PAGE_ZONE_MASK);
    page->flags   = flags | (z_id & PAGE_ZONE_MASK);
    page->order   = order;

    struct dlist_head* node = page_to_list_node(page);
    dlist_add(node, &zone->free_areas[order]);

    atomic_fetch_add_explicit(&zone->free_count[order], 1, memory_order_relaxed);
    mask_set(zone, order);
}

static void buddy_remove(struct zone* zone, struct page* page, int order) {
    struct dlist_head* node = page_to_list_node(page);
    dlist_del(node);

    page->flags |= PAGE_FLAG_USED;

    atomic_fetch_sub_explicit(&zone->free_count[order], 1, memory_order_relaxed);
    mask_clear_if_empty(zone, order);
}

static struct page* buddy_alloc_locked(struct zone* zone, int order) {
    uint16_t search_mask = zone->free_mask & ~((1 << order) - 1);

    if (unlikely(search_mask == 0)) {
        return nullptr;
    }

    int curr_order = ctz(search_mask);

    if (curr_order > PMM_MAX_ORDER) {
        return nullptr;
    }

    struct dlist_head* node = zone->free_areas[curr_order].next;
    struct page* page       = list_node_to_page(node);

    buddy_remove(zone, page, curr_order);
    uintptr_t page_phys = page_to_phys(page);

    // Split down
    while (curr_order > order) {
        curr_order--;
        uintptr_t buddy_phys = page_phys + (1ul << (curr_order + PAGE_SHIFT));
        struct page* buddy   = phys_to_page(buddy_phys);

        prefetch(buddy);
        buddy_insert(zone, buddy, curr_order);
    }

    page->order = order;
    atomic_fetch_add_explicit(&stat_used_bytes, (1ul << order) * PAGE_SIZE, memory_order_relaxed);

    return page;
}

static struct page* buddy_alloc_zone(struct zone* zone, int order) {
    acquire_spinlock(&zone->lock);
    struct page* page = buddy_alloc_locked(zone, order);
    release_spinlock(&zone->lock);
    return page;
}

static void buddy_free_zone(struct zone* zone, struct page* page, int order) {
    acquire_spinlock(&zone->lock);

    atomic_fetch_sub_explicit(&stat_used_bytes, (1ul << order) * PAGE_SIZE, memory_order_relaxed);

    int z_idx           = get_page_zone_id(page);
    uintptr_t page_phys = page_to_phys(page);

    // Coalesce
    while (order < PMM_MAX_ORDER) {
        uintptr_t buddy_phys = page_phys ^ (1ul << (order + PAGE_SHIFT));
        struct page* buddy   = phys_to_page(buddy_phys);

        if (!buddy || (buddy->flags & PAGE_FLAG_USED) || (buddy->order != order) ||
            (get_page_zone_id(buddy) != z_idx)) {
            break;
        }

        buddy_remove(zone, buddy, order);

        if (buddy_phys < page_phys) {
            page      = buddy;
            page_phys = buddy_phys;
        }

        order++;
    }

    buddy_insert(zone, page, order);
    release_spinlock(&zone->lock);
}

void* pmm_alloc(size_t count) {
    if (unlikely(count == 0)) {
        return nullptr;
    }

    int order = get_order(count);

    for (int i = active_zone_count - 1; i >= 0; i--) {
        struct zone* zone = &zones[i];

        if ((zone->free_mask >> order) == 0) {
            continue;
        }

        struct page* page = buddy_alloc_zone(zone, order);

        if (likely(page)) {
            uintptr_t page_phys = page_to_phys(page);
            atomic_store_explicit(&page->buddy.ref_count, 1, memory_order_release);
            return (void*)page_phys;
        }
    }

    PANIC("Failed to allocate page of count %lu order=%d\n", count, order);
    return nullptr;
}

void* pmm_alloc_aligned(size_t alignment, size_t count) {
    if (unlikely(count == 0)) {
        return nullptr;
    }

    int size_order  = get_order(count);
    int align_order = 0;

    if (alignment > PAGE_SIZE) {
        size_t align_pages = div_roundup(alignment, PAGE_SIZE);
        align_order        = get_order(align_pages);
    }

    int order = (align_order > size_order) ? align_order : size_order;

    for (int i = active_zone_count - 1; i >= 0; i--) {
        struct zone* zone = &zones[i];

        if ((zone->free_mask & (0xffff << order)) == 0) {
            continue;
        }

        acquire_spinlock(&zone->lock);
        struct page* page = buddy_alloc_locked(zone, order);
        release_spinlock(&zone->lock);

        if (likely(page)) {
            uintptr_t page_phys = page_to_phys(page);
            atomic_store_explicit(&page->buddy.ref_count, 1, memory_order_release);
            return (void*)page_phys;
        }
    }

    return nullptr;
}

size_t pmm_alloc_bulk(size_t count, int order, void** pages) {
    if (unlikely(count == 0)) {
        return 0;
    }

    size_t allocated = 0;

    for (int i = active_zone_count - 1; i >= 0; i--) {
        if (allocated >= count) {
            break;
        }

        struct zone* zone = &zones[i];

        if ((zone->free_mask & (0xffff << order)) == 0) {
            continue;
        }

        acquire_spinlock(&zone->lock);

        while (allocated < count) {
            struct page* page = buddy_alloc_locked(zone, order);

            if (!page) {
                break;
            }

            uintptr_t page_phys = page_to_phys(page);
            atomic_store_explicit(&page->buddy.ref_count, 1, memory_order_release);
            pages[allocated++] = (void*)page_phys;
        }

        release_spinlock(&zone->lock);
    }

    return allocated;
}

void pmm_free(void* ptr) {
    if (!ptr) {
        return;
    }

    pmm_dec_ref(ptr);
}

void pmm_inc_ref(void* ptr) {
    if (unlikely(!ptr)) {
        return;
    }

    struct page* page = phys_to_page((uintptr_t)ptr);

    uint16_t old     = atomic_load_explicit(&page->buddy.ref_count, memory_order_relaxed);
    uint16_t new_val = 0;

    do {
        if (unlikely(old == REF_SATURATION)) {
            KLOG_WARN("PMM: Ref count saturation on %p\n", ptr);
            return;
        }

        new_val = old + 1;
    } while (!atomic_compare_exchange_strong_explicit(
        &page->buddy.ref_count,
        &old,
        new_val,
        memory_order_relaxed,
        memory_order_relaxed
    ));
}

void pmm_dec_ref(void* ptr) {
    if (unlikely(!ptr)) {
        return;
    }

    struct page* page = phys_to_page((uintptr_t)ptr);

    uint16_t old     = atomic_load_explicit(&page->buddy.ref_count, memory_order_acquire);
    uint16_t new_val = 0;

    do {
        if (unlikely(old == REF_SATURATION)) {
            return;
        }

        if (unlikely(old == 0)) {
            KLOG_WARN("PMM: Double free detected on %p\n", ptr);
            return;
        }

        new_val = old - 1;
    } while (!atomic_compare_exchange_strong_explicit(
        &page->buddy.ref_count,
        &old,
        new_val,
        memory_order_acq_rel,
        memory_order_acquire
    ));

    if (new_val == 0) {
        int order = page->order;
        int z_idx = get_page_zone_id(page);

        buddy_free_zone(&zones[z_idx], page, order);
    }
}

uint16_t pmm_get_ref(void* ptr) {
    if (unlikely(!ptr)) {
        return 0;
    }

    struct page* page = phys_to_page((uintptr_t)ptr);
    return atomic_load_explicit(&page->buddy.ref_count, memory_order_relaxed);
}

void pmm_init(void) {
    KLOG_INIT_START("Physical Memory Manager");

    if (!memmap_request.response) {
        PANIC("No Memory Map detected!");
    }

    size_t count                         = memmap_request.response->entry_count;
    struct limine_memmap_entry** entries = memmap_request.response->entries;

    uintptr_t highest_usable_addr              = 0;
    struct limine_memmap_entry* largest_region = nullptr;
    size_t total_ram_accum                     = 0;

    for (size_t i = 0; i < count; ++i) {
        struct limine_memmap_entry* entry = entries[i];

        bool is_candidate = entry->type == LIMINE_MEMMAP_USABLE ||
                            entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
                            entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES ||
                            entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE;
        bool is_usable    = entry->type == LIMINE_MEMMAP_USABLE;

        if (is_candidate) {
            uintptr_t top = entry->base + entry->length;

            if (top > highest_usable_addr) {
                highest_usable_addr = top;
            }

            total_ram_accum += entry->length;

            if (is_usable && (!largest_region || entry->length > largest_region->length)) {
                largest_region = entry;
            }
        }
    }

    if (!largest_region) {
        PANIC("Out of Memory!");
    }

    size_t used_bytes = total_ram_accum;
    section_count     = (highest_usable_addr + SECTION_SIZE - 1) >> SECTION_SHIFT;
    active_zone_count = sizeof(zone_config) / sizeof(zone_config[0]);

    if (active_zone_count > MAX_ZONES) {
        active_zone_count = MAX_ZONES;
    }

    size_t table_size = section_count * sizeof(struct mem_section);

    if (table_size > largest_region->length) {
        KLOG_INIT_FAIL();
        PANIC("Not enough metadata memory!\n");
    }

    uintptr_t boot_ptr = largest_region->base;
    mem_sections       = (void*)to_higher_half(boot_ptr);
    memset(mem_sections, 0, table_size);

    boot_ptr += table_size;
    boot_ptr = align_up(boot_ptr, PAGE_SIZE);

    for (size_t i = 0; i < count; ++i) {
        struct limine_memmap_entry* entry = entries[i];

        bool is_candidate = entry->type == LIMINE_MEMMAP_USABLE ||
                            entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
                            entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES ||
                            entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE;

        if (!is_candidate) {
            continue;
        }

        uintptr_t start = align_down(entry->base, SECTION_SIZE);
        uintptr_t end   = align_up(entry->base + entry->length, SECTION_SIZE);

        for (uintptr_t addr = start; addr < end; addr += SECTION_SIZE) {
            size_t idx = addr >> SECTION_SHIFT;

            if ((idx >= section_count) || mem_sections[idx].map) {
                continue;
            }

            size_t map_size = PAGES_PER_SECTION * sizeof(struct page);

            if (boot_ptr + map_size > largest_region->base + largest_region->length) {
                KLOG_INIT_FAIL();
                PANIC("PMM: Not enough memory in boot region for metadata!");
            }

            mem_sections[idx].map = (void*)to_higher_half(boot_ptr);
            boot_ptr += map_size;

            struct page init_page;
            memset(&init_page, 0, sizeof(init_page));
            init_page.flags             = PAGE_FLAG_USED;
            init_page.buddy.section_idx = (uint32_t)idx;

            uint128_t page_template;
            memcpy(&page_template, &init_page, sizeof(page_template));

            uint128_t* map_page = (uint128_t*)mem_sections[idx].map;
            for (size_t p = 0; p < PAGES_PER_SECTION; ++p) {
                map_page[p] = page_template;
            }
        }
    }

    boot_ptr = align_up(boot_ptr, PAGE_SIZE);

    for (int i = 0; i < active_zone_count; ++i) {
        struct zone* zone = &zones[i];
        zone->limit       = zone_config[i].limit;
        zone->free_mask   = 0;

        create_spinlock(&zone->lock);

        for (int order = 0; order <= PMM_MAX_ORDER; ++order) {
            dlist_init(&zone->free_areas[order]);
            atomic_init(&zone->free_count[order], 0);
        }
    }

    for (size_t i = 0; i < count; ++i) {
        struct limine_memmap_entry* entry = entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        uintptr_t base_start = (entry == largest_region) ? boot_ptr : entry->base;
        if (base_start == 0) {
            base_start += PAGE_SIZE;
        }

        uintptr_t base_end = entry->base + entry->length;

        for (int z = 0; z < active_zone_count; ++z) {
            struct zone* zone = &zones[z];

            uintptr_t z_start_limit = (z == 0) ? 0 : zones[z - 1].limit;
            uintptr_t z_end_limit   = zone->limit;

            uintptr_t p   = (base_start > z_start_limit) ? base_start : z_start_limit;
            uintptr_t end = (base_end < z_end_limit) ? base_end : z_end_limit;

            if (p >= end) {
                continue;
            }

            uintptr_t max_block_size = 1ul << (PMM_MAX_ORDER + PAGE_SHIFT);

            // Walk forward until we hit a perfectly aligned max-order boundary
            while (p < end && !is_aligned(p, max_block_size)) {
                size_t pages_left = (end - p) >> PAGE_SHIFT;
                if (pages_left == 0) {
                    break;
                }

                int max_order   = PMM_MAX_ORDER;
                int align_order = ctz(p >> PAGE_SHIFT);
                if (align_order < max_order) {
                    max_order = align_order;
                }

                int size_order = 63 - clz(pages_left);
                if (size_order < max_order) {
                    max_order = size_order;
                }

                struct page* page = phys_to_page(p);
                if (likely(page)) {
                    set_page_zone(page, z);
                    buddy_insert(zone, page, max_order);

                    used_bytes -= 1ul << (max_order + PAGE_SHIFT);
                }

                p += (1ul << (max_order + PAGE_SHIFT));
            }

            // Perfectly aligned, max-size chunks. No need need for bit math
            while (p + max_block_size <= end) {
                struct page* page = phys_to_page(p);

                if (likely(page)) {
                    set_page_zone(page, z);
                    buddy_insert(zone, page, PMM_MAX_ORDER);

                    used_bytes -= max_block_size;
                }

                p += max_block_size;
            }

            // Clean up whatever small pieces are left at the end
            while (p < end) {
                size_t pages_left = (end - p) >> PAGE_SHIFT;
                if (pages_left == 0) {
                    break;
                }

                int max_order   = PMM_MAX_ORDER;
                int align_order = ctz(p >> PAGE_SHIFT);
                if (align_order < max_order) {
                    max_order = align_order;
                }

                int size_order = 63 - clz(pages_left);
                if (size_order < max_order) {
                    max_order = size_order;
                }

                struct page* page = phys_to_page(p);
                if (likely(page)) {
                    set_page_zone(page, z);
                    buddy_insert(zone, page, max_order);

                    used_bytes -= 1ul << (max_order + PAGE_SHIFT);
                }

                p += (1ul << (max_order + PAGE_SHIFT));
            }
        }
    }

    atomic_store_explicit(&stat_total_bytes, total_ram_accum, memory_order_relaxed);
    atomic_store_explicit(&stat_used_bytes, used_bytes, memory_order_relaxed);

    KLOG_INIT_OK();
}

void pmm_get_stats(pmm_stats_t* stats) {
    stats->total_memory = atomic_load_explicit(&stat_total_bytes, memory_order_relaxed);
    stats->used_memory  = atomic_load_explicit(&stat_used_bytes, memory_order_relaxed);
    stats->free_memory  = stats->total_memory - stats->used_memory;
}