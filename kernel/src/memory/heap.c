#include "memory/heap.h"

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

#define PAGES_PER_SLAB 4
#define SLAB_SIZE      (PAGE_SIZE_SMALL * PAGES_PER_SLAB)

#define MIN_SHIFT   3
#define MAX_SHIFT   11
#define CACHE_COUNT (MAX_SHIFT - MIN_SHIFT + 1)

#define SLAB_MAGIC 0x51AB51AB

typedef struct slab_header {
    struct slab_header* next;
    struct slab_header* prev;

    struct kmem_cache* owner;
    void* free_list;

    size_t inuse_count;
    size_t max_objects;

    uint32_t color_offset;
    uint32_t magic;
} slab_header_t;

typedef struct {
    slab_header_t* active_slab;
    void* free_list;
} kmem_cpu_cache_t;

typedef struct kmem_cache {
    kmem_cpu_cache_t* cpu_cache;

    spinlock_t lock;
    slab_header_t* partial;
    size_t total_slabs;

    size_t obj_size;
    size_t color_next;
    size_t color_range;
} kmem_cache_t;

static kmem_cache_t cache_bin[CACHE_COUNT];

static irq_lock_t lock;
static size_t num_cpus = 0;

static void list_remove(slab_header_t** head, slab_header_t* node) {
    ASSERT(head);
    ASSERT(node);

    if (node->prev) {
        node->prev->next = node->next;
    } else {
        *head = node->next;
    }

    if (node->next) {
        node->next->prev = node->prev;
    }

    node->next = nullptr;
    node->prev = nullptr;
}

static void list_add(slab_header_t** head, slab_header_t* node) {
    ASSERT(head);
    ASSERT(node);

    node->next = *head;
    node->prev = nullptr;

    if (*head) {
        (*head)->prev = node;
    }

    *head = node;
}

static void kmem_cache_init(kmem_cache_t* cache, size_t obj_size) {
    ASSERT(cache);

    cache->partial = nullptr;
    create_spinlock(&cache->lock);

    if (obj_size < sizeof(void*)) {
        obj_size = sizeof(void*);
    }

    obj_size        = align_up(obj_size, 0x08);
    cache->obj_size = obj_size;

    size_t cache_size   = sizeof(kmem_cpu_cache_t) * num_cpus;
    size_t bytes_needed = align_up(cache_size, PAGE_SIZE_SMALL);

    cache->cpu_cache = (kmem_cpu_cache_t*)vmm_alloc(
        &kernel_space,
        bytes_needed,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    for (size_t i = 0; i < num_cpus; ++i) {
        cache->cpu_cache[i].active_slab = nullptr;
        cache->cpu_cache[i].free_list   = nullptr;
    }

    size_t overhead  = align_up(sizeof(slab_header_t), 0x10);
    size_t available = SLAB_SIZE - overhead;
    size_t max_objs  = available / cache->obj_size;

    cache->color_range = available - (max_objs * cache->obj_size);
    cache->color_next  = 0;
}

static void* cache_refill(kmem_cache_t* cache, uint32_t cpu) {
    acquire_spinlock(&cache->lock);

    slab_header_t* slab = cache->partial;

    if (slab) {
        list_remove(&cache->partial, slab);
    } else {
        void* ptr = vmm_alloc(
            &kernel_space,
            SLAB_SIZE,
            VMM_FLAG_READ | VMM_FLAG_WRITE,
            CACHE_WRITE_BACK,
            PAGE_SIZE_SMALL
        );

        if (!ptr) {
            release_spinlock(&cache->lock);
            return nullptr;
        }

        slab = (slab_header_t*)ptr;

        slab->owner       = cache;
        slab->inuse_count = 0;
        slab->magic       = SLAB_MAGIC;

        uint32_t offset = (uint32_t)cache->color_next;
        cache->color_next += 0x40;

        if (cache->color_next > cache->color_range) {
            cache->color_next = 0;
        }

        slab->color_offset = offset;

        uintptr_t base = (uintptr_t)ptr + sizeof(slab_header_t);
        base           = align_up(base, 0x10);
        base += offset;

        slab->free_list   = (void*)base;
        size_t available  = SLAB_SIZE - (base - (uintptr_t)ptr);
        slab->max_objects = available / cache->obj_size;

        void** runner = (void**)base;

        for (int i = 0; i < slab->max_objects - 1; ++i) {
            void** next = (void**)((uintptr_t)runner + cache->obj_size);
            *runner     = (void*)next;
            runner      = next;
        }

        *runner = nullptr;
    }

    release_spinlock(&cache->lock);

    // Update per-cpu state
    cache->cpu_cache[cpu].active_slab = slab;
    cache->cpu_cache[cpu].free_list   = slab->free_list;

    void* obj                       = cache->cpu_cache[cpu].free_list;
    cache->cpu_cache[cpu].free_list = *(void**)obj;
    slab->inuse_count++;

    return obj;
}

static void* kmem_cache_alloc(kmem_cache_t* cache) {
    ASSERT(cache);
    ASSERT(cache->cpu_cache);

    acquire_irq_lock(&lock);

    uint32_t cpu                = arch_get_core_idx();
    kmem_cpu_cache_t* cpu_cache = &cache->cpu_cache[cpu];

    void* obj = cpu_cache->free_list;

    if (obj) {
        cpu_cache->free_list = *(void**)obj;
        cpu_cache->active_slab->inuse_count++;

        goto cleanup;
    }

    obj = cache_refill(cache, cpu);

cleanup:
    release_irq_lock(&lock);
    return obj;
}

static void kmem_cache_free(void* ptr, slab_header_t* slab) {
    if (!ptr) {
        return;
    }

    kmem_cache_t* cache = slab->owner;

    acquire_irq_lock(&lock);
    uint32_t cpu                = arch_get_core_idx();
    kmem_cpu_cache_t* cpu_cache = &cache->cpu_cache[cpu];

    if (slab == cpu_cache->active_slab) {
        *(void**)ptr         = cpu_cache->free_list;
        cpu_cache->free_list = ptr;
        slab->inuse_count--;

        goto cleanup;
    }

    acquire_spinlock(&cache->lock);

    *(void**)ptr    = slab->free_list;
    slab->free_list = ptr;
    slab->inuse_count--;

    if (slab->inuse_count == 0) {
        list_remove(&cache->partial, slab);
        vmm_free(&kernel_space, slab, SLAB_SIZE);
    } else if (slab->inuse_count == slab->max_objects - 1) {
        list_add(&cache->partial, slab);
    }

    release_spinlock(&cache->lock);
cleanup:
    release_irq_lock(&lock);
}

void kheap_init(void) {
    num_cpus = mp_request.response->cpu_count;

    for (int i = 0; i < CACHE_COUNT; ++i) {
        size_t size = 1 << (MIN_SHIFT + i);
        kmem_cache_init(&cache_bin[i], size);
    }
}

void* aligned_kalloc(size_t alignment, size_t size) {
    if (size == 0) {
        return nullptr;
    }

    if (size > (1 << MAX_SHIFT) || alignment > (1 << MAX_SHIFT)) {
        size_t bytes = align_up(size, PAGE_SIZE_SMALL);
        size_t align = PAGE_SIZE_SMALL;

        if (bytes >= PAGE_SIZE_MEDIUM) {
            align = PAGE_SIZE_MEDIUM;
        } else if (bytes >= PAGE_SIZE_LARGE) {
            align = PAGE_SIZE_LARGE;
        }

        return vmm_alloc(
            &kernel_space,
            bytes,
            VMM_FLAG_READ | VMM_FLAG_WRITE,
            CACHE_WRITE_BACK,
            align
        );
    }

    if (alignment > size) {
        size = alignment;
    }

    if (size <= 8) {
        return kmem_cache_alloc(&cache_bin[0]);
    }

    int idx = (64 - clz(size - 1)) - MIN_SHIFT;
    return kmem_cache_alloc(&cache_bin[idx]);
}

void* kmalloc(size_t size) {
    return aligned_kalloc(8, size);
}

void kfree(void* ptr, size_t size) {
    if (!ptr) {
        return;
    }

    if (size <= (1 << MAX_SHIFT)) {
        uintptr_t header    = align_down((uintptr_t)ptr, SLAB_SIZE);
        slab_header_t* slab = (slab_header_t*)header;

        if (slab->magic == SLAB_MAGIC) {
            kmem_cache_free(ptr, slab);
            return;
        }
    }

    vmm_free(&kernel_space, ptr, size);
}