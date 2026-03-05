#include "memory/heap.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "libs/dlist.h"
#include "libs/hashtable.h"
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

#define SLAB_CACHE_HASH_BITS 6
#define SLAB_CACHE_HASH_SIZE (1 << SLAB_CACHE_HASH_BITS)
#define SLAB_CACHE_HASH_MASK (SLAB_CACHE_HASH_SIZE - 1)

#define KMALLOC_SHIFT_LOW  3
#define KMALLOC_SHIFT_HIGH 12
#define KMALLOC_CACHES_NUM (KMALLOC_SHIFT_HIGH - KMALLOC_SHIFT_LOW + 1)

struct slab {
    struct dlist_head list;
    struct hlist_node h_node;

    void* base;  // Page base
    void* freelist;

    uint32_t in_use;  // Active objects
    uint32_t total;   // Total capacity
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] kmem_cache_cpu {
    void** freelist;
    uint32_t count;  // Current fill level
    uint32_t limit;  // Max capacity

    struct slab* cached_slab;  // Slab hint
};

struct kmem_cache {
    spinlock_t lock;
    struct dlist_head partial;
    struct hlist_head* slab_hash;  // hash table

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

static uint32_t num_cpus      = 1;
static uint32_t xa_node_count = 0;

static inline size_t obj_to_pfn(void* addr) {
    return (uintptr_t)addr >> PAGE_SHIFT;
}

static void map_insert(kmem_cache_t* cache, struct slab* slab) {
    uintptr_t pfn = obj_to_pfn(slab->base);
    ht_insert(cache->slab_hash, &slab->h_node, pfn, SLAB_CACHE_HASH_BITS);
}

static void map_remove(struct slab* slab) {
    ht_remove(&slab->h_node);
}

static struct slab* map_lookup(kmem_cache_t* cache, void* obj) {
    uintptr_t pfn = obj_to_pfn(obj);
    uint32_t idx  = ht_hash_val(pfn, SLAB_CACHE_HASH_BITS);

    struct hlist_node* curr = cache->slab_hash[idx].first;
    while (curr) {
        struct slab* s = ht_entry(curr, struct slab, h_node);

        if (obj_to_pfn(s->base) == pfn) {
            return s;
        }

        curr = curr->next;
    }

    return nullptr;
}

static void
format_slab(kmem_cache_t* cache, struct slab* slab, void* page_base, size_t total_objs) {
    slab->base   = page_base;
    slab->in_use = 0;
    dlist_init(&slab->list);
    slab->total = total_objs;

    char* base  = (char*)page_base;
    size_t size = cache->size;

    void* head     = base;
    slab->freelist = head;

    for (size_t i = 0; i < total_objs - 1; ++i) {
        void* curr = base + (i * size);
        void* next = base + ((i + 1) * size);

        *(void**)curr = next;

        if (cache->ctor) {
            cache->ctor(curr);
        }
    }

    void* tail    = base + ((total_objs - 1) * size);
    *(void**)tail = nullptr;

    if (cache->ctor) {
        cache->ctor(tail);
    }
}

static struct slab* slab_grow(kmem_cache_t* cache) {
    void* phys = pmm_alloc(1);

    if (!phys) {
        errno = ENOMEM;
        return nullptr;
    }

    void* page = (void*)to_higher_half((uintptr_t)phys);

    struct slab* slab = nullptr;
    if (likely(!(cache->flags & SLAB_NO_OFFSLAB))) {
        slab = kmem_cache_alloc(&cache_metadata);

        if (!slab) {
            KLOG_WARN("slab_grow: Failed to allocate metadata for cache %s", cache->name);
            pmm_free(phys);
            errno = ENOMEM;
            return nullptr;
        }

        format_slab(cache, slab, page, PAGE_SIZE / cache->size);
    } else {
        slab             = (struct slab*)((char*)page + PAGE_SIZE - sizeof(struct slab));
        size_t available = PAGE_SIZE - sizeof(struct slab);
        format_slab(cache, slab, page, available / cache->size);
    }

    acquire_spinlock(&cache->lock);
    map_insert(cache, slab);
    release_spinlock(&cache->lock);

    return slab;
}

static int slab_refill(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    acquire_spinlock(&cache->lock);

    if (dlist_empty(&cache->partial)) {
        release_spinlock(&cache->lock);

        struct slab* new_slab = slab_grow(cache);

        if (!new_slab) {
            return 0;
        }

        acquire_spinlock(&cache->lock);
        dlist_add(&new_slab->list, &cache->partial);
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
            memset(obj, POISON_FREE, cache->obj_size);
        }

        struct slab* slab = cc->cached_slab;
        size_t pfn        = obj_to_pfn(obj);

        if (unlikely(!slab || obj_to_pfn(slab->base) != pfn)) {
            slab            = map_lookup(cache, obj);
            cc->cached_slab = slab;
        }

        if (unlikely(!slab)) {
            continue;
        }

        *(void**)obj   = slab->freelist;
        slab->freelist = obj;
        slab->in_use--;

        if (slab->in_use == slab->total - 1) {
            dlist_add(&slab->list, &cache->partial);
        } else if (slab->in_use == 0) {
            dlist_del(&slab->list);
            map_remove(slab);

            pmm_free((void*)from_higher_half((uintptr_t)slab->base));

            if (!(cache->flags & SLAB_NO_OFFSLAB)) {
                release_spinlock(&cache->lock);
                kmem_cache_free(&cache_metadata, slab);
                acquire_spinlock(&cache->lock);

                if (cc->cached_slab == slab) {
                    cc->cached_slab = nullptr;
                }
            }
        }
    }

    release_spinlock(&cache->lock);
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

    static struct hlist_head boot_hash[SLAB_CACHE_HASH_SIZE];
    memset(boot_hash, 0, sizeof(struct hlist_head) * SLAB_CACHE_HASH_SIZE);
    cache->slab_hash = boot_hash;
}

static void boot_slab_subsystem(void) {
    num_cpus = mp_request.response->cpu_count;

    init_internal_cache(&cache_boot, "kmem_cache", sizeof(kmem_cache_t));
    init_internal_cache(&cache_metadata, "slab_metadata", sizeof(struct slab));

    static struct hlist_head metadata_hash[SLAB_CACHE_HASH_BITS];
    memset(metadata_hash, 0, sizeof(struct hlist_head) * SLAB_CACHE_HASH_SIZE);
    cache_metadata.slab_hash = metadata_hash;
}

void kheap_init(void) {
    boot_slab_subsystem();

    char name[SLAB_NAME_MAX];
    for (int i = 0; i < KMALLOC_CACHES_NUM; ++i) {
        size_t size = 1 << (i + KMALLOC_SHIFT_LOW);
        snprintf(name, sizeof(name), "km-%lu", size);
        kmalloc_caches[i] = kmem_cache_create(name, size, size, 0, nullptr);
    }
}

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, size_t flags, void (*ctor)(void*)) {
    kmem_cache_t* cache = kmem_cache_alloc(&cache_boot);

    if (!cache) {
        KLOG_ERROR("kmem_cache_create: Failed to allocate cache structure");
        errno = ENOMEM;
        return nullptr;
    }

    strncpy(cache->name, name, SLAB_NAME_MAX);

    if (align < 8) {
        align = 8;
    }

    cache->align    = align;
    cache->obj_size = size;

    // Redzone calculation
    size_t pad = 0;
    if (flags & SLAB_RED_ZONES) {
        pad = sizeof(uint64_t);
    }

    cache->size = align_up(size + pad, align);

    if (cache->size < sizeof(void*)) {
        cache->size = sizeof(void*);
    }

    cache->flags = flags;
    cache->ctor  = ctor;
    dlist_init(&cache->partial);
    create_spinlock(&cache->lock);

    size_t hash_bytes = sizeof(struct hlist_head) * SLAB_CACHE_HASH_SIZE;
    void* hash_phys   = pmm_alloc(div_roundup(hash_bytes, PAGE_SIZE));
    cache->slab_hash =
        hash_phys ? (struct hlist_head*)to_higher_half((uintptr_t)hash_phys) : nullptr;

    if (!cache->slab_hash) {
        KLOG_ERROR("kmem_cache_create: Failed to allocate hash for cache %s", name);
        kmem_cache_free(&cache_boot, cache);
        errno = ENOMEM;
        return nullptr;
    }

    memset(cache->slab_hash, 0, sizeof(struct hlist_head) * SLAB_CACHE_HASH_SIZE);

    size_t struct_size = sizeof(struct kmem_cache_cpu) * num_cpus;
    size_t mag_size    = CPU_CACHE_SIZE * sizeof(void*) * num_cpus;
    size_t total_req   = struct_size + mag_size;
    total_req          = align_up(total_req, PAGE_SIZE);

    void* cpu_phys = pmm_alloc(total_req / PAGE_SIZE);
    void* ptr      = cpu_phys ? (void*)to_higher_half((uintptr_t)cpu_phys) : nullptr;

    if (!ptr) {
        KLOG_ERROR("kmem_cache_create: Failed to allocate cpu_slab for cache %s", name);
        pmm_free((void*)from_higher_half((uintptr_t)cache->slab_hash));
        kmem_cache_free(&cache_boot, cache);
        errno = ENOMEM;
        return nullptr;
    }

    cache->cpu_slab = (struct kmem_cache_cpu*)ptr;
    char* mag_base  = (char*)ptr + struct_size;

    for (size_t i = 0; i < num_cpus; ++i) {
        cache->cpu_slab[i].count       = 0;
        cache->cpu_slab[i].limit       = CPU_CACHE_SIZE;
        cache->cpu_slab[i].freelist    = (void**)(mag_base + (i * CPU_CACHE_SIZE * sizeof(void*)));
        cache->cpu_slab[i].cached_slab = nullptr;
    }

    return cache;
}

static void* slab_alloc(kmem_cache_t* cache) {
    void* obj = nullptr;

    acquire_spinlock(&cache->lock);

    if (dlist_empty(&cache->partial)) {
        release_spinlock(&cache->lock);

        struct slab* new_slab = slab_grow(cache);

        if (!new_slab) {
            return nullptr;
        }

        acquire_spinlock(&cache->lock);
        dlist_add(&new_slab->list, &cache->partial);
    }

    struct slab* slab = dlist_entry(cache->partial.next, struct slab, list);

    if (unlikely(!slab->freelist)) {
        release_spinlock(&cache->lock);
        return nullptr;
    }

    obj        = slab->freelist;
    void* next = *(void**)obj;

    if (next) {
        prefetch(next);
    }

    slab->freelist = next;
    slab->in_use++;

    *(void**)obj = nullptr;

    if (!slab->freelist) {
        dlist_del(&slab->list);
    }

    release_spinlock(&cache->lock);
    return obj;
}

void* kmem_cache_alloc(kmem_cache_t* cache) {
    if (unlikely(!cache->cpu_slab)) {
        return slab_alloc(cache);
    }

    uint32_t cpu              = arch_get_core_idx();
    struct kmem_cache_cpu* cc = &cache->cpu_slab[cpu];

    if (likely(cc->count > 0)) {
        void* obj = cc->freelist[--cc->count];

        if (cc->count > 0) {
            prefetch(cc->freelist[cc->count - 1]);
        }

        return obj;
    }

    if (slab_refill(cache, cc) > 0) {
        return cc->freelist[--cc->count];
    }

    return nullptr;
}

void kmem_cache_free(kmem_cache_t* cache, void* obj) {
    if (!obj) {
        return;
    }

    if (unlikely(!cache->cpu_slab)) {
        acquire_spinlock(&cache->lock);

        struct slab* slab = map_lookup(cache, obj);

        if (slab) {
            *(void**)obj   = slab->freelist;
            slab->freelist = obj;
            slab->in_use--;
        }

        release_spinlock(&cache->lock);
        return;
    }

    uint32_t cpu              = arch_get_core_idx();
    struct kmem_cache_cpu* cc = &cache->cpu_slab[cpu];

    if (likely(cc->count < cc->limit)) {
        cc->freelist[cc->count++] = obj;
        return;
    }

    slab_flush(cache, cc);
    cc->freelist[cc->count++] = obj;
}

void kmem_cache_destroy(kmem_cache_t* cache) {
    pmm_free((void*)from_higher_half((uintptr_t)cache->cpu_slab));

    struct slab *pos, *n;
    dlist_for_each_entry_safe(pos, n, &cache->partial, list) {
        dlist_del(&pos->list);
        map_remove(pos);
        pmm_free((void*)from_higher_half((uintptr_t)pos->base));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) {
            kmem_cache_free(&cache_metadata, pos);
        }
    }

    pmm_free((void*)from_higher_half((uintptr_t)cache->slab_hash));
    kmem_cache_free(&cache_boot, cache);
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

void kfree(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    if (size > PAGE_SIZE) {
        pmm_free((void*)from_higher_half((uintptr_t)ptr));
        return;
    }

    size_t idx = 0;
    if (size > 8) {
        size_t blk = 64 - (size_t)clz(size - 1);
        idx        = blk - KMALLOC_SHIFT_LOW;
    }

    if (unlikely(idx >= KMALLOC_CACHES_NUM)) {
        return;
    }

    kmem_cache_free(kmalloc_caches[idx], ptr);
}