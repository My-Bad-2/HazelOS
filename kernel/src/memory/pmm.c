#include "memory/pmm.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
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
#define PAGE_SHIFT    12

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

struct [[gnu::aligned(CACHE_LINE_SIZE)]] pcp_cache {
    void* pages[PCP_BATCH_SIZE];
    int count;
    irq_lock_t lock;
};

static struct mem_section* mem_sections = nullptr;
static struct pcp_cache* pcp_caches     = nullptr;
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

static inline struct page* phys_to_page(uintptr_t phys) {
    size_t sec_idx = phys >> SECTION_SHIFT;

    if (unlikely(sec_idx >= section_count)) {
        return nullptr;
    }

    if (unlikely(!mem_sections[sec_idx].map)) {
        return nullptr;
    }

    return &mem_sections[sec_idx].map[(phys & SECTION_MASK) >> PAGE_SHIFT];
}

static int zone_to_id(struct zone* zone) {
    return (int)(zone - zones);
}

static inline uintptr_t page_to_phys(struct page* page) {
    return page->phys_addr;
}

static inline struct dlist_head* page_to_list_node(struct page* page) {
    uintptr_t virt = to_higher_half(page->phys_addr);
    return &((struct free_area*)virt)->list;
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

    // Split down
    while (curr_order > order) {
        curr_order--;

        uintptr_t buddy_phys = page->phys_addr + (1ul << (curr_order + PAGE_SHIFT));
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

    int z_idx = get_page_zone_id(page);

    // Coalesce
    while (order < PMM_MAX_ORDER) {
        uintptr_t buddy_phys = page->phys_addr ^ (1ul << (order + PAGE_SHIFT));
        struct page* buddy   = phys_to_page(buddy_phys);

        if (!buddy || (buddy->flags & PAGE_FLAG_USED) || (buddy->order != order) ||
            (get_page_zone_id(buddy) != z_idx)) {
            break;
        }

        buddy_remove(zone, buddy, order);

        if (buddy->phys_addr < page->phys_addr) {
            page = buddy;
        }

        order++;
    }

    buddy_insert(zone, page, order);
    release_spinlock(&zone->lock);
}

static void* pmm_alloc_slow(size_t count) {
    if (unlikely(count == 0)) {
        return nullptr;
    }

    int order = get_order(count);

    for (int i = active_zone_count - 1; i >= 0; i--) {
        struct zone* zone = &zones[i];

        if ((zone->free_mask & ~((1 << order) - 1)) == 0) {
            continue;
        }

        struct page* page = buddy_alloc_zone(zone, order);

        if (likely(page)) {
            atomic_store_explicit(&page->ref_count, 1, memory_order_release);
            // KLOG_DEBUG("PMM: Allocated %lu pages (order %d) at %p\n", count, order,
            // (void*)page->phys_addr);
            return (void*)page->phys_addr;
        }
    }

    PANIC("Failed to allocate page of count %lu order=%d\n", count, order);
    return nullptr;
}

static void pcp_refill(struct pcp_cache* cache) {
    void** dest = &cache->pages[cache->count];

    size_t allocated = pmm_alloc_bulk((size_t)(PCP_BATCH_SIZE - cache->count), 0, dest);
    cache->count += (int)allocated;
}

static void pcp_drain(struct pcp_cache* cache) {
    while (cache->count > 0) {
        void* page = cache->pages[--cache->count];
        pmm_free(page);
    }
}

void* pmm_alloc(size_t count) {
    if (count == 1 && pcp_caches) {
        uint32_t cpu            = arch_get_core_idx();
        struct pcp_cache* cache = &pcp_caches[cpu];

        acquire_irq_lock(&cache->lock);

        if (likely(cache->count > 0)) {
            void* ptr = cache->pages[--cache->count];
            release_irq_lock(&cache->lock);
            return ptr;
        }

        pcp_refill(cache);

        if (likely(cache->count > 0)) {
            void* ptr = cache->pages[--cache->count];
            release_irq_lock(&cache->lock);
            return ptr;
        }

        release_irq_lock(&cache->lock);
        return nullptr;
    }

    return pmm_alloc_slow(count);
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
            atomic_store_explicit(&page->ref_count, 1, memory_order_release);
            // KLOG_DEBUG("PMM: Allocated aligned %lu pages (order %d) at %p\n", count, order,
            // (void*)page->phys_addr);
            return (void*)page->phys_addr;
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

            atomic_store_explicit(&page->ref_count, 1, memory_order_release);
            pages[allocated++] = (void*)page->phys_addr;
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

    uint16_t old     = atomic_load_explicit(&page->ref_count, memory_order_relaxed);
    uint16_t new_val = 0;

    do {
        if (unlikely(old == REF_SATURATION)) {
            KLOG_WARN("PMM: Ref count saturation on %p\n", ptr);
            return;
        }

        new_val = old + 1;
    } while (!atomic_compare_exchange_strong_explicit(
        &page->ref_count,
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

    uint16_t old     = atomic_load_explicit(&page->ref_count, memory_order_acquire);
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
        &page->ref_count,
        &old,
        new_val,
        memory_order_acq_rel,
        memory_order_acquire
    ));

    if (new_val == 0) {
        int order = page->order;
        KLOG_TRACE("PMM: Freeing %p (Order %d)", ptr, order);

        if (order == 0 && pcp_caches) {
            uint32_t cpu            = arch_get_core_idx();
            struct pcp_cache* cache = &pcp_caches[cpu];

            acquire_irq_lock(&cache->lock);

            if (likely(cache->count < PCP_BATCH_SIZE)) {
                cache->pages[cache->count++] = ptr;
                release_irq_lock(&cache->lock);
                return;
            }

            pcp_drain(cache);

            cache->pages[cache->count++] = ptr;

            release_irq_lock(&cache->lock);
            return;
        }

        int z_idx         = get_page_zone_id(page);
        struct zone* zone = &zones[z_idx];

        buddy_free_zone(zone, page, order);
    }
}

uint16_t pmm_get_ref(void* ptr) {
    if (unlikely(!ptr)) {
        return 0;
    }

    struct page* page = phys_to_page((uintptr_t)ptr);
    return atomic_load_explicit(&page->ref_count, memory_order_relaxed);
}

void pmm_init(void) {
    KLOG_INFO("PMM: Initializing...\n");

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

    KLOG_INFO("PMM: Total detected memory: %lu KB\n", total_ram_accum / 1024);

    atomic_store_explicit(&stat_total_bytes, total_ram_accum, memory_order_relaxed);
    atomic_store_explicit(&stat_used_bytes, total_ram_accum, memory_order_relaxed);
    section_count = (highest_usable_addr + SECTION_SIZE - 1) >> SECTION_SHIFT;

    KLOG_INFO("PMM: Section count: %lu\n", section_count);

    active_zone_count = sizeof(zone_config) / sizeof(zone_config[0]);

    if (active_zone_count > MAX_ZONES) {
        active_zone_count = MAX_ZONES;
    }

    size_t cpu_count  = mp_request.response->cpu_count;
    size_t table_size = section_count * sizeof(struct mem_section);
    size_t pcp_size   = cpu_count * sizeof(struct pcp_cache);

    if ((table_size + pcp_size) > largest_region->length) {
        PANIC("Not enough metadata memory!\n");
    }

    uintptr_t boot_ptr = largest_region->base;

    mem_sections = (void*)to_higher_half(boot_ptr);
    memset(mem_sections, 0, table_size);
    boot_ptr += table_size;

    pcp_caches = (void*)to_higher_half(boot_ptr);
    memset(pcp_caches, 0, pcp_size);
    boot_ptr += pcp_size;

    KLOG_INFO("PMM: Allocated %lu PCP cache(s) at %p\n", cpu_count, pcp_caches);

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
                PANIC("PMM: Not enough memory in boot region for metadata!");
            }

            mem_sections[idx].map = (void*)to_higher_half(boot_ptr);
            boot_ptr += map_size;

            for (size_t p = 0; p < PAGES_PER_SECTION; ++p) {
                struct page* page = &mem_sections[idx].map[p];

                page->phys_addr = addr + (p * PAGE_SIZE);
                page->flags     = PAGE_FLAG_USED;
                page->order     = 0;
                atomic_init(&page->ref_count, 0);
            }
        }
    }

    boot_ptr = align_up(boot_ptr, PAGE_SIZE);

    for (int i = 0; i < active_zone_count; ++i) {
        struct zone* zone = &zones[i];
        zones->limit      = zone_config[i].limit;
        zones->free_mask  = 0;

        create_spinlock(&zones->lock);

        for (int order = 0; order <= PMM_MAX_ORDER; ++order) {
            dlist_init(&zones->free_areas[order]);
            dlist_init(&zones->free_areas[order]);
        }
    }

    for (size_t i = 0; i < count; ++i) {
        struct limine_memmap_entry* entry = entries[i];

        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        uintptr_t start = entry->base;
        uintptr_t end   = entry->base + entry->length;

        // If this entry if the one we used for bootstrapping, we must skip the memory we used for
        // the metadata.
        if (entry == largest_region) {
            start = boot_ptr;
        }

        if (start == 0) {
            start += PAGE_SIZE;
        }

        if (start >= end) {
            continue;
        }

        for (uintptr_t p = start; p < end; p += PAGE_SIZE) {
            struct page* page = phys_to_page(p);

            if (unlikely(!page)) {
                continue;
            }

            int z_idx         = get_page_zone_id(page);
            struct zone* zone = &zones[z_idx];

            set_page_zone(page, z_idx);
            buddy_free_zone(zone, page, 0);
        }
    }

    pmm_stats_t stats;
    pmm_get_stats(&stats);
    KLOG_INFO("PMM: Initialization complete. Free memory: %lu KB\n", stats.free_memory / 1024);
}

void pmm_get_stats(pmm_stats_t* stats) {
    stats->total_memory = atomic_load_explicit(&stat_total_bytes, memory_order_relaxed);
    stats->used_memory  = atomic_load_explicit(&stat_used_bytes, memory_order_relaxed);
    stats->free_memory  = stats->total_memory - stats->used_memory;
}