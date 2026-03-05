#include "memory/heap.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "libs/dlist.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pmm.h"

#define PAGE_SIZE  PAGE_SIZE_SMALL
#define PAGE_SHIFT PAGE_SHIFT_SMALL

#define SLAB_NAME_MAX  32
#define BATCH_SIZE     32
#define CPU_CACHE_SIZE 128

#define POISON_FREE 0x6b  // 107 - 'k' - Freed Memory
#define POISON_END  0xa5  // Redzone marker

#define KMALLOC_SHIFT_LOW  3
#define KMALLOC_SHIFT_HIGH 12
#define KMALLOC_CACHES_NUM (KMALLOC_SHIFT_HIGH - KMALLOC_SHIFT_LOW + 1)

struct slab {
    struct dlist_head list;
    struct kmem_cache* cache;

    void* base;
    void* freelist;

    _Atomic(uint32_t) in_use;
    uint32_t total;
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] kmem_cache_cpu {
    _Atomic(void*) freelist;
    struct slab* active;
};

struct kmem_cache {
    spinlock_t lock;
    struct dlist_head partial;

    size_t obj_size;  // Logical size
    size_t size;      // Aligned/Padded size
    size_t align;
    size_t flags;

    size_t color_off;
    size_t color_max;
    size_t color_next;

    void (*ctor)(void*);  // Constructor
    char name[SLAB_NAME_MAX];

    struct kmem_cache_cpu* cpu_slab;
};

static kmem_cache_t cache_boot;
static kmem_cache_t cache_metadata;
static kmem_cache_t* kmalloc_caches[KMALLOC_CACHES_NUM];

static inline struct page* virt_to_page(void* addr) {
    uintptr_t phys = from_higher_half((uintptr_t)addr);
    return phys_to_page(phys);
}

static void add_partial_sorted(kmem_cache_t* cache, struct slab* slab) {
    struct dlist_head* curr;

    dlist_for_each(curr, &cache->partial) {
        struct slab* s = dlist_entry(curr, struct slab, list);

        if (atomic_load(&slab->in_use) >= atomic_load(&s->in_use)) {
            break;
        }
    }

    dlist_add_tail(&slab->list, curr);
}

static void check_poison(kmem_cache_t* cache, void* obj) {
    if (!(cache->flags & SLAB_DEBUG_FREE)) {
        return;
    }

    uint8_t* mem = (uint8_t*)obj;
    // Check first few bytes to ensure they haven't been modified since free
    for (size_t i = sizeof(void*); i < cache->obj_size; ++i) {
        if (unlikely(mem[i] != POISON_FREE)) {
            KLOG_ERROR("Slab corruption in cache %s at %p", cache->name, obj);

            if (cache->flags & SLAB_PANIC) {
                PANIC("Slab Memory Corruption!");
            }
        }
    }
}

static void format_slab(
    kmem_cache_t* cache,
    struct slab* slab,
    void* page_base,
    size_t total_objs,
    size_t color_offset
) {
    slab->base  = (char*)page_base + color_offset;
    slab->total = total_objs;
    slab->cache = cache;

    atomic_init(&slab->in_use, 0);
    dlist_init(&slab->list);

    char* base     = (char*)page_base;
    slab->freelist = base;

    for (size_t i = 0; i < total_objs - 1; ++i) {
        *(void**)(base + (i * cache->size)) = base + ((i + 1) * cache->size);

        if (cache->ctor) {
            cache->ctor(base + (i * cache->size));
        }
    }

    *(void**)(base + ((total_objs - 1) * cache->size)) = nullptr;
    if (cache->ctor) {
        cache->ctor(base + ((total_objs - 1) * cache->size));
    }
}

static struct slab* slab_grow(kmem_cache_t* cache) {
    void* phys = pmm_alloc(1);
    if (!phys) {
        if (cache->flags & SLAB_PANIC) {
            PANIC("OOM in slab_grow");
        }

        return nullptr;
    }

    void* page        = (void*)to_higher_half((uintptr_t)phys);
    struct slab* slab = nullptr;
    size_t available  = PAGE_SIZE;

    if (likely(!(cache->flags & SLAB_NO_OFFSLAB))) {
        slab = kmem_cache_alloc(&cache_metadata);

        if (!slab) {
            pmm_free(phys);
            return nullptr;
        }
    } else {
        slab = (struct slab*)((char*)page + PAGE_SIZE - sizeof(struct slab));
        available -= sizeof(struct slab);
    }

    size_t total_objs = available / cache->size;

    size_t leftover     = available - (total_objs * cache->size);
    cache->color_max    = leftover / cache->color_off;
    size_t color_offset = cache->color_next * cache->color_off;

    cache->color_next++;
    if (cache->color_next > cache->color_max) {
        cache->color_next = 0;
    }

    format_slab(cache, slab, page, available / cache->size, color_offset);

    struct page* p_desc = virt_to_page(page);
    p_desc->flags |= PAGE_FLAG_SLAB;
    p_desc->slab.slab_data = slab;

    return slab;
}

// Retires the current active slab back to the global lists
static void deactivate_slab(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    if (!cc->active) {
        return;
    }

    struct slab* slab = cc->active;
    slab->freelist    = atomic_exchange(&cc->freelist, nullptr);

    if (atomic_load(&slab->in_use) == slab->total) {
    } else if (atomic_load(&slab->in_use) == 0 && slab->freelist) {
        struct page* p_desc = virt_to_page((void*)((uintptr_t)slab->base & ~(PAGE_SIZE - 1)));
        p_desc->flags &= ~PAGE_FLAG_SLAB;
        pmm_free((void*)from_higher_half((uintptr_t)p_desc));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) {
            kmem_cache_free(&cache_metadata, slab);
        }
    } else {
        add_partial_sorted(cache, slab);
    }

    cc->active = nullptr;
}

static void* slab_alloc_slow(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    acquire_spinlock(&cache->lock);

    if (cc) {
        deactivate_slab(cache, cc);
    }

    struct slab* new_active = nullptr;

    if (!dlist_empty(&cache->partial)) {
        new_active = dlist_entry(cache->partial.next, struct slab, list);
        dlist_del(&new_active->list);
    } else {
        new_active = slab_grow(cache);

        if (!new_active) {
            release_spinlock(&cache->lock);
            return nullptr;
        }
    }

    if (cc) {
        cc->active = new_active;
        atomic_store(&cc->freelist, new_active->freelist);
        new_active->freelist = nullptr;

        void* obj = atomic_load(&cc->freelist);
        if (obj) {
            atomic_store(&cc->freelist, *(void**)obj);
            atomic_fetch_add(&new_active->in_use, 1);
        }

        release_spinlock(&cache->lock);
        return obj;
    }

    void* obj = new_active->freelist;
    if (obj) {
        new_active->freelist = *(void**)obj;
        atomic_fetch_add(&new_active->in_use, 1);
    }

    if (new_active->freelist) {
        add_partial_sorted(cache, new_active);
    }

    release_spinlock(&cache->lock);
    return obj;
}

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, size_t flags, void (*ctor)(void*)) {
    kmem_cache_t* cache = kmem_cache_alloc(&cache_boot);

    if (!cache) {
        return nullptr;
    }

    strncpy(cache->name, name, SLAB_NAME_MAX);
    cache->obj_size = size;
    cache->align    = (align < 8) ? 8 : align;
    cache->flags    = flags;
    cache->ctor     = ctor;

    // Redzone calculation
    size_t pad  = (flags & SLAB_RED_ZONES) ? sizeof(uint64_t) : 0;
    cache->size = align_up(size + pad, cache->align);
    if (cache->size < sizeof(void*)) {
        cache->size = sizeof(void*);
    }

    cache->color_off  = CACHE_LINE_SIZE;
    cache->color_next = 0;
    cache->color_max  = 0;

    dlist_init(&cache->partial);
    create_spinlock(&cache->lock);

    size_t struct_size = sizeof(struct kmem_cache_cpu) * mp_request.response->cpu_count;
    void* cpu_phys     = pmm_alloc(div_roundup(struct_size, PAGE_SIZE));
    cache->cpu_slab    = (struct kmem_cache_cpu*)to_higher_half((uintptr_t)cpu_phys);

    for (size_t i = 0; i < mp_request.response->cpu_count; ++i) {
        atomic_init(&cache->cpu_slab[i].freelist, nullptr);
        cache->cpu_slab[i].active = nullptr;
    }

    return cache;
}

void kmem_cache_destroy(kmem_cache_t* cache) {
    pmm_free((void*)from_higher_half((uintptr_t)cache->cpu_slab));

    struct slab *pos, *n;
    dlist_for_each_entry_safe(pos, n, &cache->partial, list) {
        dlist_del(&pos->list);

        struct page* p_desc = virt_to_page(pos->base);
        p_desc->flags &= ~PAGE_FLAG_SLAB;

        pmm_free((void*)from_higher_half((uintptr_t)pos->base));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) {
            kmem_cache_free(&cache_metadata, pos);
        }
    }

    kmem_cache_free(&cache_boot, cache);
}

void* kmem_cache_alloc(kmem_cache_t* cache) {
    if (unlikely(!cache->cpu_slab)) {
        return slab_alloc_slow(cache, nullptr);
    }

    uint32_t flags = arch_save_flags();

    struct kmem_cache_cpu* cc = &cache->cpu_slab[arch_get_core_idx()];
    void* obj                 = nullptr;
    void* next                = nullptr;

    do {
        obj = atomic_load_explicit(&cc->freelist, memory_order_acquire);
        if (unlikely(!obj)) {
            arch_restore_flags(flags);
            return slab_alloc_slow(cache, cc);
        }

        next = *(void**)obj;
    } while (!atomic_compare_exchange_weak_explicit(
        &cc->freelist,
        &obj,
        next,
        memory_order_release,
        memory_order_relaxed
    ));

    atomic_fetch_add(&cc->active->in_use, 1);

    if (obj) {
        *(void**)obj = nullptr;
        check_poison(cache, obj);
    }

    arch_restore_flags(flags);
    return obj;
}

void kmem_cache_free(kmem_cache_t* cache, void* obj) {
    if (unlikely(!obj)) {
        return;
    }

    if (cache->flags & SLAB_DEBUG_FREE) {
        memset((uint8_t*)obj + sizeof(void*), POISON_FREE, cache->obj_size - sizeof(void*));
    }

    struct kmem_cache_cpu* cc = &cache->cpu_slab[arch_get_core_idx()];
    struct slab* slab         = virt_to_page(obj)->slab.slab_data;

    if (likely(slab == cc->active)) {
        void* curr_head = nullptr;

        do {
            curr_head    = atomic_load_explicit(&cc->freelist, memory_order_acquire);
            *(void**)obj = curr_head;
        } while (!atomic_compare_exchange_weak_explicit(
            &cc->freelist,
            &curr_head,
            obj,
            memory_order_release,
            memory_order_relaxed
        ));

        atomic_fetch_sub(&slab->in_use, 1);
        return;
    }

    acquire_spinlock(&cache->lock);

    *(void**)obj          = slab->freelist;
    slab->freelist        = obj;
    uint32_t prior_in_use = atomic_fetch_sub(&slab->in_use, 1);

    if (prior_in_use == slab->total) {
        if (slab->total == 1) {
            struct page* p_desc = virt_to_page((void*)((uintptr_t)slab->base & ~(PAGE_SIZE - 1)));
            p_desc->flags &= ~PAGE_FLAG_SLAB;

            pmm_free((void*)from_higher_half((uintptr_t)p_desc));

            if (!(cache->flags & SLAB_NO_OFFSLAB)) {
                kmem_cache_free(&cache_metadata, slab);
            }
        } else {
            add_partial_sorted(cache, slab);
        }
    } else if (prior_in_use == 1) {
        dlist_del(&slab->list);

        struct page* p_desc = virt_to_page((void*)((uintptr_t)slab->base & ~(PAGE_SIZE - 1)));
        p_desc->flags &= ~PAGE_FLAG_SLAB;
        pmm_free((void*)from_higher_half((uintptr_t)p_desc));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) {
            kmem_cache_free(&cache_metadata, slab);
        }
    }

    release_spinlock(&cache->lock);
}

static void init_internal_cache(kmem_cache_t* cache, const char* name, size_t size) {
    strncpy(cache->name, name, SLAB_NAME_MAX);
    cache->obj_size = size;
    cache->size     = align_up(size, 8);
    cache->align    = 8;
    cache->flags    = SLAB_NO_OFFSLAB;
    cache->cpu_slab = nullptr;
    cache->ctor     = nullptr;

    cache->color_off  = CACHE_LINE_SIZE;
    cache->color_next = 0;
    cache->color_max  = 0;

    dlist_init(&cache->partial);
    create_spinlock(&cache->lock);
}

void kheap_init(void) {
    init_internal_cache(&cache_boot, "kmem_cache", sizeof(kmem_cache_t));
    init_internal_cache(&cache_metadata, "slab_metadata", sizeof(struct slab));

    char name[SLAB_NAME_MAX];
    for (int i = 0; i < KMALLOC_CACHES_NUM; ++i) {
        size_t size = 1 << (i + KMALLOC_SHIFT_LOW);
        snprintf(name, sizeof(name), "km-%lu", size);
        kmalloc_caches[i] = kmem_cache_create(name, size, size, 0, nullptr);
    }
}

void* kmalloc(size_t size) {
    if (size == 0) {
        return nullptr;
    }

    if (size > PAGE_SIZE) {
        void* phys = pmm_alloc(div_roundup(size, PAGE_SIZE));

        if (!phys) {
            KLOG_WARN("kmalloc: pmm_alloc failed for size %lu", size);
            errno = ENOMEM;
            return nullptr;
        }

        return (void*)to_higher_half((uintptr_t)phys);
    }

    size_t idx = 0;
    if (size > 8) {
        size_t blk = 64 - (size_t)clz(size - 1);
        idx        = blk - KMALLOC_SHIFT_LOW;
    }

    if (unlikely(idx >= KMALLOC_CACHES_NUM)) {
        KLOG_ERROR("kmalloc: Invalid size %lu, idx %lu", size, idx);
        errno = EINVAL;
        return nullptr;
    }

    return kmem_cache_alloc(kmalloc_caches[idx]);
}

void kfree(void* ptr) {
    if (!ptr) {
        return;
    }

    struct page* p_desc = virt_to_page(ptr);

    if (!(p_desc->flags & PAGE_FLAG_SLAB)) {
        pmm_free((void*)from_higher_half((uintptr_t)ptr));
        return;
    }

    struct slab* slab = p_desc->slab.slab_data;
    kmem_cache_free(slab->cache, ptr);
}