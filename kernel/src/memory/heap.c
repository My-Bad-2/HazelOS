#include "memory/heap.h"

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
#include "sched/rcu.h"

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

    _Atomic(void*) remote_freelist;

    _Atomic(uint32_t) in_use;
    _Atomic(bool) is_active;
    uint32_t total;

    struct rcu_head rcu;
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] kmem_cache_cpu {
    void* freelist;
    struct slab* active;
    struct slab* partial;
};

struct kmem_cache {
    struct dlist_head list;  // Node in global_cache_list
    _Atomic(uint32_t) refcount;

    spinlock_t lock;
    struct dlist_head partial_list;

    size_t obj_size;         // Logical size
    size_t offset_freelist;  // Safe offset to store the freelist pointer
    size_t size;             // Aligned/Padded size
    size_t align;
    size_t flags;
    size_t alloc_order;  // The power-of-two page multiplier

    size_t color_off;
    size_t color_max;
    size_t color_next;

    void (*ctor)(void*);
#if KERNEL_DEBUG
    char name[SLAB_NAME_MAX];
#endif

    struct kmem_cache_cpu* cpu_slab;
};

static struct dlist_head global_cache_list;
static spinlock_t global_cache_lock;

static kmem_cache_t cache_boot;
static kmem_cache_t cache_metadata;
static kmem_cache_t* kmalloc_caches[KMALLOC_CACHES_NUM];

static inline struct page* virt_to_page(void* addr) {
    return phys_to_page(from_higher_half((uintptr_t)addr));
}

static inline void** slab_freelist_ptr(kmem_cache_t* cache, void* obj) {
    return (void**)((char*)obj + cache->offset_freelist);
}

static void add_partial_sorted(kmem_cache_t* cache, struct slab* slab) {
    struct dlist_head* curr;
    dlist_for_each(curr, &cache->partial_list) {
        struct slab* s = dlist_entry(curr, struct slab, list);
        if (atomic_load(&slab->in_use) >= atomic_load(&s->in_use)) break;
    }

    dlist_add_tail(&slab->list, curr);
}

#if KERNEL_DEBUG
static void check_poison(kmem_cache_t* cache, void* obj) {
    if (cache->flags & SLAB_RED_ZONES) {
        uint8_t* redzone = (uint8_t*)obj + cache->obj_size;
        size_t pad       = cache->offset_freelist - cache->obj_size;
        for (size_t i = 0; i < pad; ++i) {
            if (unlikely(redzone[i] != POISON_END)) {
                KLOG_ERROR("Slab Redzone corruption in %s at %p", cache->name, obj);
                if (cache->flags & SLAB_PANIC) PANIC("Slab Memory Corruption!");
            }
        }
    }

    if (!(cache->flags & SLAB_DEBUG_FREE)) return;

    uint8_t* mem = (uint8_t*)obj;
    for (size_t i = 0; i < cache->obj_size; ++i) {
        if (unlikely(mem[i] != POISON_FREE)) {
            KLOG_ERROR("Slab Use-After-Free corruption in %s at %p", cache->name, obj);
            if (cache->flags & SLAB_PANIC) PANIC("Slab Memory Corruption!");
        }
    }
}
#endif

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
    atomic_init(&slab->is_active, false);
    dlist_init(&slab->list);

    char* base     = slab->base;
    slab->freelist = base;

    for (size_t i = 0; i < total_objs; ++i) {
        void* curr = base + (i * cache->size);
        void* next = (i == total_objs - 1) ? nullptr : base + ((i + 1) * cache->size);

        *slab_freelist_ptr(cache, curr) = next;

        if (cache->ctor) cache->ctor(curr);

#if KERNEL_DEBUG
        if (cache->flags & SLAB_RED_ZONES) {
            size_t pad = cache->offset_freelist - cache->obj_size;
            memset((char*)curr + cache->obj_size, POISON_END, pad);
        }
#endif
    }
}

static struct slab* slab_grow(kmem_cache_t* cache) {
    size_t num_pages   = 1ul << cache->alloc_order;
    size_t alloc_bytes = PAGE_SIZE * num_pages;

    void* phys = pmm_alloc(num_pages);
    if (!phys) {
#if KERNEL_DEBUG
        if (cache->flags & SLAB_PANIC) PANIC("OOM in slab_grow");
#endif
        return nullptr;
    }

    void* page        = (void*)to_higher_half((uintptr_t)phys);
    struct slab* slab = nullptr;
    size_t available  = alloc_bytes;

    if (likely(!(cache->flags & SLAB_NO_OFFSLAB))) {
        slab = kmem_cache_alloc(&cache_metadata);

        if (!slab) {
            pmm_free(phys);
            return nullptr;
        }
    } else {
        slab = (struct slab*)((char*)page + alloc_bytes - sizeof(struct slab));
        available -= sizeof(struct slab);
    }

    atomic_init(&slab->remote_freelist, nullptr);

    size_t total_objs = available / cache->size;
    size_t leftover   = available - (total_objs * cache->size);

    cache->color_max    = leftover / cache->color_off;
    size_t color_offset = cache->color_next * cache->color_off;

    cache->color_next++;
    if (cache->color_next > cache->color_max) cache->color_next = 0;

    format_slab(cache, slab, page, available / cache->size, color_offset);

    struct page* p_desc = virt_to_page(page);
    p_desc->flags |= PAGE_FLAG_SLAB;
    p_desc->slab.slab_data = slab;
    return slab;
}

// Retires the current active slab back to the global lists
static void deactivate_slab(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    if (!cc->active) return;

    struct slab* slab = cc->active;
    atomic_store(&slab->is_active, false);

    void* remote = atomic_exchange_explicit(&slab->remote_freelist, nullptr, memory_order_acq_rel);
    if (cc->freelist) {
        void* tail = cc->freelist;
        while (*slab_freelist_ptr(cache, tail)) tail = *slab_freelist_ptr(cache, tail);
        *slab_freelist_ptr(cache, tail) = remote;
        slab->freelist                  = cc->freelist;
    } else {
        slab->freelist = remote;
    }

    cc->freelist = nullptr;
    cc->active   = nullptr;

    if (atomic_load(&slab->in_use) == 0) {
        void* base_page     = (void*)((uintptr_t)slab->base & ~(PAGE_SIZE - 1));
        struct page* p_desc = virt_to_page(base_page);
        p_desc->flags &= ~PAGE_FLAG_SLAB;
        pmm_free((void*)from_higher_half((uintptr_t)base_page));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) kmem_cache_free(&cache_metadata, slab);
    } else if (atomic_load(&slab->in_use) < slab->total) {
        acquire_spinlock(&cache->lock);
        add_partial_sorted(cache, slab);
        release_spinlock(&cache->lock);
    }
}

static void rcu_free_slab_callback(struct rcu_head* head) {
    struct slab* slab   = (struct slab*)((char*)head - offsetof(struct slab, rcu));
    kmem_cache_t* cache = slab->cache;

    void* base_page     = (void*)align_down((uintptr_t)slab->base, PAGE_SIZE);
    struct page* p_desc = virt_to_page(base_page);
    p_desc->flags &= ~PAGE_FLAG_SLAB;

    pmm_free((void*)from_higher_half((uintptr_t)base_page));

    if (!(cache->flags & SLAB_NO_OFFSLAB)) kmem_cache_free(&cache_metadata, slab);
}

static void teardown_slab(kmem_cache_t* cache, struct slab* slab) {
    if (cache->flags & SLAB_TYPESAFE_BY_RCU) {
        call_rcu(&slab->rcu, rcu_free_slab_callback);
    } else {
        void* base_page     = (void*)align_down((uintptr_t)slab->base, PAGE_SIZE);
        struct page* p_desc = virt_to_page(base_page);
        p_desc->flags &= ~PAGE_FLAG_SLAB;

        pmm_free((void*)from_higher_half((uintptr_t)base_page));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) kmem_cache_free(&cache_metadata, slab);
    }
}

size_t kmem_cache_shrink(kmem_cache_t* cache) {
    size_t freed_pages = 0;
    struct slab *pos, *n;

    acquire_spinlock(&cache->lock);

    dlist_for_each_entry_safe(pos, n, &cache->partial_list, list) {
        if (atomic_load(&pos->in_use) == 0 && !atomic_load(&pos->is_active)) {
            dlist_del(&pos->list);
            teardown_slab(cache, pos);
            freed_pages += (1ul << cache->alloc_order);
        }
    }

    release_spinlock(&cache->lock);
    return freed_pages;
}

static void* slab_alloc_slow(kmem_cache_t* cache, struct kmem_cache_cpu* cc) {
    if (cc && cc->active) {
        void* remote =
            atomic_exchange_explicit(&cc->active->remote_freelist, nullptr, memory_order_acq_rel);
        if (remote) {
            cc->freelist = remote;
            void* obj    = cc->freelist;
            cc->freelist = *slab_freelist_ptr(cache, obj);
            atomic_fetch_add(&cc->active->in_use, 1);
            return obj;
        }
    }

    if (cc && cc->partial) {
        if (cc->active) deactivate_slab(cache, cc);

        cc->active  = cc->partial;
        cc->partial = nullptr;
        if (cc->active) atomic_store(&cc->active->is_active, true);

        cc->freelist         = cc->active->freelist;
        cc->active->freelist = nullptr;

        if (cc->freelist) {
            void* obj    = cc->freelist;
            cc->freelist = *slab_freelist_ptr(cache, obj);
            atomic_fetch_add(&cc->active->in_use, 1);
            return obj;
        }
    }

    acquire_spinlock(&cache->lock);
    if (cc && cc->active) deactivate_slab(cache, cc);

    struct slab* new_active  = nullptr;
    struct slab* new_partial = nullptr;

    if (!dlist_empty(&cache->partial_list)) {
        new_active = dlist_entry(cache->partial_list.next, struct slab, list);
        dlist_del_init(&new_active->list);

        if (!dlist_empty(&cache->partial_list)) {
            new_partial = dlist_entry(cache->partial_list.next, struct slab, list);
            dlist_del_init(&new_partial->list);
        }
    } else {
        new_active  = slab_grow(cache);
        new_partial = slab_grow(cache);
    }

    if (!new_active) {
        release_spinlock(&cache->lock);
        return nullptr;
    }

    if (cc) {
        cc->active  = new_active;
        cc->partial = new_partial;

        atomic_store(&new_active->is_active, true);
        cc->freelist         = new_active->freelist;
        new_active->freelist = nullptr;

        void* obj = cc->freelist;
        if (obj) {
            cc->freelist = *slab_freelist_ptr(cache, obj);
            atomic_fetch_add(&new_active->in_use, 1);
        }

        release_spinlock(&cache->lock);
        return obj;
    }

    void* obj = new_active->freelist;
    if (obj) {
        new_active->freelist = *slab_freelist_ptr(cache, obj);
        atomic_fetch_add(&new_active->in_use, 1);
    }

    if (new_active->freelist) add_partial_sorted(cache, new_active);

    release_spinlock(&cache->lock);
    return obj;
}

static kmem_cache_t*
find_mergeable_cache(size_t size, size_t align, size_t flags, void (*ctor)(void*)) {
    if (flags & SLAB_NEVER_MERGE) return nullptr;
    if (ctor) return nullptr;

#if KERNEL_DEBUG
    size_t pad = (flags & SLAB_RED_ZONES) ? sizeof(uint64_t) : 0;
#else
    size_t pad = 0;
#endif
    size_t offset     = align_up(size + pad, sizeof(void*));
    size_t final_size = align_up(offset + sizeof(void*), align);

    struct dlist_head* curr;
    acquire_spinlock(&global_cache_lock);
    dlist_for_each(curr, &global_cache_list) {
        kmem_cache_t* c = dlist_entry(curr, kmem_cache_t, list);

        if (c->flags & SLAB_NEVER_MERGE) continue;

        if (c->size == final_size || c->flags == flags && c->align == align && !c->ctor) {
            atomic_fetch_add(&c->refcount, 1);
            release_spinlock(&global_cache_lock);
            return c;
        }
    }

    release_spinlock(&global_cache_lock);
    return nullptr;
}

kmem_cache_t*
kmem_cache_create(const char* name, size_t size, size_t align, size_t flags, void (*ctor)(void*)) {
    if (flags & SLAB_HWCACHE_ALIGN) {
        align = align_up(align, CACHE_LINE_SIZE);
        size  = align_up(size, CACHE_LINE_SIZE);
    } else {
        align = (align < 8) ? 8 : align;
    }

    kmem_cache_t* merged = find_mergeable_cache(size, align, flags, ctor);
    if (merged) return merged;

    kmem_cache_t* cache = kmem_cache_alloc(&cache_boot);
    if (!cache) return nullptr;

#if KERNEL_DEBUG
    strncpy(cache->name, name, SLAB_NAME_MAX);
#endif
    cache->obj_size = size;
    cache->align    = align;
    cache->flags    = flags;
    cache->ctor     = ctor;

#if KERNEL_DEBUG
    const size_t pad = (flags & SLAB_RED_ZONES) ? sizeof(uint64_t) : 0;
#else
    const size_t pad = 0;
#endif

    cache->offset_freelist = align_up(size + pad, sizeof(void*));
    cache->size            = align_up(cache->offset_freelist + sizeof(void*), cache->align);

    cache->color_off  = CACHE_LINE_SIZE;
    cache->color_next = 0;
    cache->color_max  = 0;

    atomic_init(&cache->refcount, 1);
    dlist_init(&cache->partial_list);
    create_spinlock(&cache->lock);

    size_t best_order = 0;
    size_t max_order  = 3;

    for (size_t order = 0; order <= max_order; ++order) {
        size_t page_bytes = PAGE_SIZE << order;
        size_t available  = page_bytes;

        if (flags & SLAB_NO_OFFSLAB) available -= sizeof(struct slab);

        size_t objs = available / cache->size;
        if (objs == 0) continue;

        size_t waste = available - (objs * cache->size);
        if (waste <= (page_bytes / 8)) {
            best_order = order;
            break;
        }

        best_order = order;
    }

    cache->alloc_order = best_order;

    size_t struct_size = sizeof(struct kmem_cache_cpu) * mp_request.response->cpu_count;
    void* cpu_phys     = pmm_alloc(div_roundup(struct_size, PAGE_SIZE));
    cache->cpu_slab    = (struct kmem_cache_cpu*)to_higher_half((uintptr_t)cpu_phys);

    memset(cache->cpu_slab, 0, struct_size);
    return cache;
}

void kmem_cache_destroy(kmem_cache_t* cache) {
    if (!cache) return;
    if (atomic_fetch_sub(&cache->refcount, 1) > 1) return;

    acquire_spinlock(&global_cache_lock);
    dlist_del(&cache->list);
    release_spinlock(&global_cache_lock);

    if (cache->cpu_slab) {
        for (size_t i = 0; i < mp_request.response->cpu_count; ++i)
            deactivate_slab(cache, &cache->cpu_slab[i]);

        pmm_free((void*)from_higher_half((uintptr_t)cache->cpu_slab));
    }

    struct slab *pos, *n;
    dlist_for_each_entry_safe(pos, n, &cache->partial_list, list) {
        dlist_del(&pos->list);

        void* base_page     = (void*)align_down((uintptr_t)pos->base, PAGE_SIZE_SMALL);
        struct page* p_desc = virt_to_page(base_page);
        p_desc->flags &= ~PAGE_FLAG_SLAB;

        pmm_free((void*)from_higher_half((uintptr_t)base_page));

        if (!(cache->flags & SLAB_NO_OFFSLAB)) kmem_cache_free(&cache_metadata, pos);
    }

    kmem_cache_free(&cache_boot, cache);
}

void* kmem_cache_alloc(kmem_cache_t* cache) {
    if (unlikely(!cache->cpu_slab)) return slab_alloc_slow(cache, nullptr);

    uint32_t flags = arch_save_flags();
    arch_disable_interrupts();

    struct kmem_cache_cpu* cc = &cache->cpu_slab[arch_get_core_idx()];

    void* obj = cc->freelist;
    if (likely(obj)) {
        cc->freelist = *slab_freelist_ptr(cache, obj);
        atomic_fetch_add(&cc->active->in_use, 1);
        prefetch(cc->freelist, 1, 0);
    } else {
        obj = slab_alloc_slow(cache, cc);
    }

    arch_restore_flags(flags);

#if KERNEL_DEBUG
    if (obj) check_poison(cache, obj);
#endif

    return obj;
}

void kmem_cache_free(kmem_cache_t* cache, void* obj) {
    if (unlikely(!obj)) return;

#if KERNEL_DEBUG
    if (cache->flags & SLAB_DEBUG_FREE) memset(obj, POISON_FREE, cache->obj_size);
#endif

    uint32_t flags = arch_save_flags();
    arch_disable_interrupts();

    struct kmem_cache_cpu* cc = cache->cpu_slab ? &cache->cpu_slab[arch_get_core_idx()] : nullptr;
    struct slab* slab         = virt_to_page(obj)->slab.slab_data;

    // Core returning object to its own active slab
    if (likely(cc && slab == cc->active)) {
        *slab_freelist_ptr(cache, obj) = cc->freelist;
        cc->freelist                   = obj;
        atomic_fetch_sub(&slab->in_use, 1);
        arch_restore_flags(flags);
        return;
    }

    arch_restore_flags(flags);

    // Freeing remotely
    void* curr_remote = nullptr;
    do {
        curr_remote = atomic_load_explicit(&slab->remote_freelist, memory_order_acquire);
        *slab_freelist_ptr(cache, obj) = curr_remote;
    } while (!atomic_compare_exchange_weak_explicit(
        &slab->remote_freelist,
        &curr_remote,
        obj,
        memory_order_release,
        memory_order_relaxed
    ));

    uint32_t prior_in_use = atomic_fetch_sub(&slab->in_use, 1);

    if (prior_in_use == slab->total) {
        acquire_spinlock(&cache->lock);
        if (!atomic_load(&slab->is_active)) add_partial_sorted(cache, slab);
        release_spinlock(&cache->lock);
    } else if (prior_in_use == 1) {
        acquire_spinlock(&cache->lock);
        if (atomic_load(&slab->in_use) == 0 && !atomic_load(&slab->is_active)) {
            if (!dlist_empty(&slab->list)) dlist_del(&slab->list);

            release_spinlock(&cache->lock);

            teardown_slab(cache, slab);
            return;
        }

        release_spinlock(&cache->lock);
    }
}

static void init_internal_cache(kmem_cache_t* cache, const char* name, size_t size) {
#if KERNEL_DEBUG
    strncpy(cache->name, name, SLAB_NAME_MAX);
#endif

    cache->obj_size        = size;
    cache->offset_freelist = align_up(size, sizeof(void*));
    cache->size            = align_up(cache->offset_freelist + sizeof(void*), 8);
    cache->align           = 8;
    cache->flags           = SLAB_NO_OFFSLAB;
    cache->alloc_order     = 0;
    cache->cpu_slab        = nullptr;
    cache->ctor            = nullptr;

    cache->color_off  = CACHE_LINE_SIZE;
    cache->color_next = 0;
    cache->color_max  = 0;

    dlist_init(&cache->partial_list);
    create_spinlock(&cache->lock);
}

void kheap_init(void) {
    KLOG_INIT_START("Kernel Slab Allocator");
    dlist_init(&global_cache_list);
    create_spinlock(&global_cache_lock);

    init_internal_cache(&cache_boot, "kmem_cache", sizeof(kmem_cache_t));
    init_internal_cache(&cache_metadata, "slab_metadata", sizeof(struct slab));

    char name[SLAB_NAME_MAX];
    for (int i = 0; i < KMALLOC_CACHES_NUM; ++i) {
        size_t size = 1 << (i + KMALLOC_SHIFT_LOW);
        snprintf(name, sizeof(name), "km-%lu", size);
        kmalloc_caches[i] = kmem_cache_create(name, size, size, 0, nullptr);
    }

    KLOG_INIT_OK();
}

void* kmalloc(size_t size) {
    if (size == 0) return nullptr;

    if (size > PAGE_SIZE) {
        void* phys = pmm_alloc(div_roundup(size, PAGE_SIZE));
        if (!phys) return nullptr;
        return (void*)to_higher_half((uintptr_t)phys);
    }

    size_t idx = 0;
    if (size > 8) {
        size_t blk = 64 - (size_t)clz(size - 1);
        idx        = blk - KMALLOC_SHIFT_LOW;
    }

    if (unlikely(idx >= KMALLOC_CACHES_NUM)) return nullptr;
    return kmem_cache_alloc(kmalloc_caches[idx]);
}

void kfree(void* ptr) {
    if (!ptr) return;

    struct page* p_desc = virt_to_page(ptr);
    if (!(p_desc->flags & PAGE_FLAG_SLAB)) {
        pmm_free((void*)from_higher_half((uintptr_t)ptr));
        return;
    }

    struct slab* slab = p_desc->slab.slab_data;
    kmem_cache_free(slab->cache, ptr);
}