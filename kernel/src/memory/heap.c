#include "memory/heap.h"

#include <errno.h>
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

    void* base;  // Page base
    void* freelist;

    uint32_t in_use;  // Active objects
    uint32_t total;   // Total capacity
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] kmem_cache_cpu {
    void** freelist;
    uint32_t count;            // Current fill level
    uint32_t limit;            // Max capacity
    struct slab* cached_slab;  // Slab hint
};

struct kmem_cache {
    spinlock_t lock;
    struct dlist_head partial;

    size_t obj_size;  // Logical size
    size_t size;      // Aligned/Padded size
    size_t align;
    size_t flags;

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

static void
format_slab(kmem_cache_t* cache, struct slab* slab, void* page_base, size_t total_objs) {
    slab->base   = page_base;
    slab->in_use = 0;
    slab->total  = total_objs;
    slab->cache  = cache;
    dlist_init(&slab->list);

    char* base     = (char*)page_base;
    slab->freelist = base;

    for (size_t i = 0; i < total_objs - 1; ++i) {
        *(void**)(base + (i * cache->size)) = base + ((i + 1) * cache->size);

        if (cache->ctor) {
            cache->ctor(base + ((total_objs - 1) * cache->size));
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

        errno = ENOMEM;
        return nullptr;
    }

    void* page        = (void*)to_higher_half((uintptr_t)phys);
    struct slab* slab = nullptr;

    if (likely(!(cache->flags & SLAB_NO_OFFSLAB))) {
        // Don't track metadata cache in itself yet
        slab = kmem_cache_alloc(&cache_metadata);

        if (!slab) {
            pmm_free(phys);
            return nullptr;
        }

        format_slab(cache, slab, page, PAGE_SIZE / cache->size);
    } else {
        slab             = (struct slab*)((char*)page + PAGE_SIZE - sizeof(struct slab));
        size_t available = PAGE_SIZE - sizeof(struct slab);
        format_slab(cache, slab, page, available / cache->size);
    }

    struct page* p_desc = virt_to_page(page);
    p_desc->flags |= PAGE_FLAG_SLAB;
    p_desc->slab.slab_data = slab;

    acquire_spinlock(&cache->lock);
    dlist_add(&slab->list, &cache->partial);
    release_spinlock(&cache->lock);

    return slab;
}

static int slab_refill(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    acquire_spinlock(&cache->lock);

    if (dlist_empty(&cache->partial)) {
        release_spinlock(&cache->lock);

        if (!slab_grow(cache)) {
            return 0;
        }

        acquire_spinlock(&cache->lock);
    }

    struct slab* slab = dlist_entry(cache->partial.next, struct slab, list);
    int refilled      = 0;

    while (slab->freelist && refilled < BATCH_SIZE) {
        void* obj  = slab->freelist;
        void* next = *(void**)obj;

        if (next) {
            prefetch(next);
        }

        slab->freelist = next;
        slab->in_use++;

        cc->freelist[cc->count++] = obj;
        refilled++;

        if (!slab->freelist) {
            dlist_del(&slab->list);
            break;
        }
    }

    release_spinlock(&cache->lock);
    return refilled;
}

static void slab_flush(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    acquire_spinlock(&cache->lock);

    const uint32_t target = cc->count / 2;
    while (cc->count > target) {
        void* obj = cc->freelist[--cc->count];

        if (cache->flags & SLAB_DEBUG_FREE) {
            memset((uint8_t*)obj + sizeof(void*), POISON_FREE, cache->obj_size - sizeof(void*));
        }

        struct page* p_desc = virt_to_page(obj);
        struct slab* slab   = p_desc->slab.slab_data;

        *(void**)obj   = slab->freelist;
        slab->freelist = obj;
        slab->in_use--;

        if (slab->in_use == slab->total - 1) {
            dlist_add(&slab->list, &cache->partial);
        } else if (slab->in_use == 0) {
            dlist_del(&slab->list);

            p_desc->flags &= ~PAGE_FLAG_SLAB;
            p_desc->buddy.ref_count   = 1;
            p_desc->buddy.section_idx = 0;

            pmm_free((void*)from_higher_half((uintptr_t)slab->base));

            if (!(cache->flags & SLAB_NO_OFFSLAB)) {
                release_spinlock(&cache->lock);
                kmem_cache_free(&cache_metadata, slab);
                acquire_spinlock(&cache->lock);
            }
        }
    }

    release_spinlock(&cache->lock);
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

    dlist_init(&cache->partial);
    create_spinlock(&cache->lock);

    size_t struct_size = sizeof(struct kmem_cache_cpu) * mp_request.response->cpu_count;
    size_t mag_size    = CPU_CACHE_SIZE * sizeof(void*) * mp_request.response->cpu_count;
    void* cpu_phys     = pmm_alloc(div_roundup(struct_size + mag_size, PAGE_SIZE));

    if (!cpu_phys) {
        kmem_cache_free(&cache_boot, cache);
        return nullptr;
    }

    cache->cpu_slab = (struct kmem_cache_cpu*)to_higher_half((uintptr_t)cpu_phys);
    char* mag_base  = (char*)cache->cpu_slab + struct_size;

    for (size_t i = 0; i < mp_request.response->cpu_count; ++i) {
        cache->cpu_slab[i].count    = 0;
        cache->cpu_slab[i].limit    = CPU_CACHE_SIZE;
        cache->cpu_slab[i].freelist = (void**)(mag_base + (i * CPU_CACHE_SIZE * sizeof(void*)));
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
    uint32_t flags = arch_save_flags();

    if (unlikely(!cache->cpu_slab)) {
        arch_restore_flags(flags);

        if (dlist_empty(&cache->partial)) {
            slab_grow(cache);
        }

        acquire_spinlock(&cache->lock);

        struct slab* slab = dlist_entry(cache->partial.next, struct slab, list);
        void* obj         = slab->freelist;

        slab->freelist = *(void**)obj;
        slab->in_use++;

        if (!slab->freelist) {
            dlist_del(&slab->list);
        }

        release_spinlock(&cache->lock);
        return obj;
    }

    struct kmem_cache_cpu* cc = &cache->cpu_slab[arch_get_core_idx()];
    void* obj                 = nullptr;

    if (likely(cc->count > 0)) {
        obj = cc->freelist[--cc->count];

        if (cc->count > 0) {
            prefetch(cc->freelist[cc->count - 1]);
        }
    } else {
        if (slab_refill(cache, cc) > 0) {
            obj = cc->freelist[--cc->count];
        }
    }

    arch_restore_flags(flags);

    if (obj) {
        *(void**)obj = nullptr;
        check_poison(cache, obj);
    }

    return obj;
}

void kmem_cache_free(kmem_cache_t* cache, void* obj) {
    if (!obj) {
        return;
    }

    if (cache->flags & SLAB_DEBUG_FREE) {
        memset((uint8_t*)obj + sizeof(void*), POISON_FREE, cache->obj_size - sizeof(void*));
    }

    uint32_t flags = arch_save_flags();

    if (unlikely(!cache->cpu_slab)) {
        arch_restore_flags(flags);

        acquire_spinlock(&cache->lock);
        struct slab* slab = virt_to_page(obj)->slab.slab_data;
        *(void**)obj      = slab->freelist;
        slab->freelist    = obj;
        slab->in_use--;
        release_spinlock(&cache->lock);
        return;
    }

    struct kmem_cache_cpu* cc = &cache->cpu_slab[arch_get_core_idx()];

    if (unlikely(cc->count >= cc->limit)) {
        slab_flush(cache, cc);
    }

    cc->freelist[cc->count++] = obj;
    arch_restore_flags(flags);
}

static void init_internal_cache(kmem_cache_t* cache, const char* name, size_t size) {
    strncpy(cache->name, name, SLAB_NAME_MAX);
    cache->obj_size = size;
    cache->size     = align_up(size, 8);
    cache->align    = 0;
    cache->flags    = SLAB_NO_OFFSLAB;
    cache->cpu_slab = nullptr;
    cache->ctor     = nullptr;
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
        KLOG_DEBUG("Here?\n");
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