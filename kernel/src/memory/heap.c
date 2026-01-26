#include "memory/heap.h"

#include <errno.h>
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

#define SUPERBLOCK_SIZE  PAGE_SIZE_MEDIUM
#define SUPERBLOCK_MAGIC 0x5EACA110Cu

#define MIN_BLOCK_SIZE    16
#define MAX_SMALL_SIZE    8192
#define BIN_COUNT         10
#define MAGAZINE_CAPACITY 64
#define BATCH_SIZE        32

typedef struct superblock {
    size_t magic;
    uint32_t object_size;
    uint32_t used_objects;
    size_t total_objects;

    void* free_list;
    void* bump_ptr;
    void* end_ptr;

    struct superblock* next;
    struct superblock* prev;
} superblock_t;

typedef struct {
    void* rounds[MAGAZINE_CAPACITY];
    int top;
} magazine_t;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] {
    irq_lock_t lock;
    magazine_t bins[BIN_COUNT];
} cpu_heap_t;

typedef struct {
    interrupt_lock_t lock;
    superblock_t* active;
    superblock_t* partial;

    uint32_t color_next;
    uint32_t color_range;
} global_bin_t;

static uintptr_t heap_secret = 0;
static cpu_heap_t* cpu_heaps = nullptr;
static size_t num_cpus       = 0;
static global_bin_t global_bins[BIN_COUNT];

static size_t get_random_secret(void) {
    return kernel_address_request.response->physical_base;
}

static inline void* protect_ptr(void* target, void* loc) {
    return (void*)((uintptr_t)target ^ heap_secret ^ (uintptr_t)loc);
}

static inline void* decrypt_ptr(void* val, void* loc) {
    return (void*)((uintptr_t)val ^ heap_secret ^ (uintptr_t)loc);
}

static int get_bin_idx(size_t size) {
    if (size == 0) {
        return -1;
    }

    if (size <= 16) {
        return 0;
    }

    // 64 - clz(size - 1) gives log2 ceil. Since 16 = 2^4, we subtract 4.
    int idx = (64 - clz(size - 1)) - 4;
    return (idx < 0) ? 0 : idx;
}

static size_t get_bin_size(int idx) {
    if (idx == -1) {
        return 0;
    }

    return 1ul << (idx + 4);
}

static inline superblock_t* get_superblock(void* ptr) {
    return (superblock_t*)align_down((uintptr_t)ptr, SUPERBLOCK_SIZE);
}

static inline size_t power_of_two_ceil(size_t x) {
    if (x <= 1) {
        return 1;
    }

    return 1ul << (64 - clz(x - 1));
}

static superblock_t* allocate_superblock(size_t size) {
    int idx           = get_bin_idx(size);
    global_bin_t* bin = &global_bins[idx];

    void* ptr = vmalloc(
        &kernel_space,
        SUPERBLOCK_SIZE,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_MEDIUM
    );

    if (!ptr) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("Heap: superblock alloc failed size=0x%zx errno=%d\n", size, errno);
        return nullptr;
    }

    superblock_t* sb = (superblock_t*)ptr;

    size_t col_offset = 0;

    if (bin->color_range > 0) {
        col_offset = bin->color_next * (size_t)CACHE_LINE_SIZE;

        bin->color_next++;

        if (bin->color_next >= bin->color_range) {
            bin->color_next = 0;
        }
    }

    sb->magic        = SUPERBLOCK_MAGIC;
    sb->object_size  = (uint32_t)size;
    sb->used_objects = 0;
    sb->free_list    = nullptr;
    sb->next = sb->prev = nullptr;

    uintptr_t start = (uintptr_t)ptr + sizeof(superblock_t) + col_offset;

    size_t padding = (size - (start & (size - 1))) & (size - 1);

    sb->bump_ptr = (void*)(start + padding);
    sb->end_ptr  = (void*)((uintptr_t)ptr + PAGE_SIZE_MEDIUM);

    sb->total_objects = ((uintptr_t)sb->end_ptr - (uintptr_t)sb->bump_ptr) / size;

    return sb;
}

static int refill_magazines(int idx, void** dest, int count) {
    global_bin_t* bin = &global_bins[idx];
    size_t size       = 16ul << idx;
    int fetched       = 0;

    acquire_interrupt_lock(&bin->lock);

    superblock_t* sb = bin->active;

    while (fetched < count) {
        if (!sb || (sb->free_list == nullptr && sb->bump_ptr >= sb->end_ptr)) {
            if (bin->partial) {
                sb           = bin->partial;
                bin->partial = sb->next;

                if (bin->partial) {
                    bin->partial->prev = nullptr;
                }

                sb->next    = nullptr;
                bin->active = sb;
            } else {
                sb = allocate_superblock(size);

                if (!sb) {
                    if (errno == 0) {
                        errno = ENOMEM;
                    }

                    KLOG_WARN(
                        "Heap: refill superblock alloc failed idx=%d size=0x%zx errno=%d\n",
                        idx,
                        size,
                        errno
                    );
                    break;
                }

                bin->active = sb;
            }
        }

        void* obj = nullptr;

        if (sb->free_list) {
            obj        = sb->free_list;
            void* next = *(void**)obj;

            sb->free_list = decrypt_ptr(next, obj);
        } else if (sb->bump_ptr < sb->end_ptr) {
            obj          = sb->bump_ptr;
            sb->bump_ptr = (void*)((uintptr_t)sb->bump_ptr + size);
        }

        if (obj) {
            sb->used_objects++;
            dest[fetched++] = obj;
        }
    }

    release_interrupt_lock(&bin->lock);
    return fetched;
}

static void flush_magazines(int idx, void** src, int count) {
    global_bin_t* bin = &global_bins[idx];

    acquire_interrupt_lock(&bin->lock);

    for (int i = 0; i < count; ++i) {
        void* obj        = src[i];
        superblock_t* sb = get_superblock(obj);

        if (unlikely(sb->magic != SUPERBLOCK_MAGIC)) {
            PANIC("Heap Corruption: Invalid Superblock Magic!");
        }

        void* head = sb->free_list;
        void* next = protect_ptr(head, obj);

        *(void**)obj  = next;
        sb->free_list = obj;

        sb->used_objects--;

        if (sb->used_objects == 0) {
            if (bin->active != sb) {
                if (sb->prev) {
                    sb->prev->next = sb->next;
                }

                if (sb->next) {
                    sb->next->prev = sb->prev;
                }

                if (bin->partial == sb) {
                    bin->partial = sb->next;
                }

                vmfree(&kernel_space, sb, SUPERBLOCK_SIZE);
            }
        } else if (sb->used_objects == sb->total_objects - 1) {
            if (bin->active != sb) {
                sb->next = bin->partial;

                if (bin->partial) {
                    bin->partial->prev = sb;
                }

                bin->partial = sb;
                sb->prev     = nullptr;
            }
        }
    }

    release_interrupt_lock(&bin->lock);
}

void kheap_init(void) {
    heap_secret = get_random_secret() ^ (get_random_secret() << 32);

    for (int i = 0; i < BIN_COUNT; ++i) {
        size_t obj_size = get_bin_size(i);
        obj_size        = align_up(obj_size, 0x10);

        size_t overhead  = sizeof(superblock_t);
        size_t available = SUPERBLOCK_SIZE - heap_secret;

        size_t num_objs   = available / obj_size;
        size_t total_used = num_objs * obj_size;
        size_t waste      = available - total_used;

        // Calculate how many cache-line shifts we can perform inside this wasted space.
        if (waste >= CACHE_LINE_SIZE) {
            global_bins[i].color_range = (uint32_t)waste / CACHE_LINE_SIZE;
        } else {
            // No enough easte to shift even one cache line.
            global_bins[i].color_range = 0;
        }

        global_bins[i].color_next = 0;

        create_interrupt_lock(&global_bins[i].lock);
        global_bins[i].active  = nullptr;
        global_bins[i].partial = nullptr;
    }

    num_cpus = mp_request.response->cpu_count;

    if (num_cpus == 0) {
        num_cpus = 1;
    }

    size_t magazine_bytes = align_up(num_cpus * sizeof(cpu_heap_t), PAGE_SIZE_SMALL);

    cpu_heaps = vmalloc(
        &kernel_space,
        magazine_bytes,
        VMM_FLAG_READ | VMM_FLAG_WRITE,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    if (!cpu_heaps) {
        errno = ENOMEM;
        KLOG_ERROR("Heap: cpu heap alloc failed bytes=0x%zx errno=%d\n", magazine_bytes, errno);
        PANIC("Kernel Heap: Failed to allocate CPU Magazine");
    }

    for (int i = 0; i < num_cpus; ++i) {
        create_irq_lock(&cpu_heaps[i].lock);

        for (int j = 0; j < BIN_COUNT; ++j) {
            cpu_heaps[i].bins[j].top = 0;
        }
    }

    KLOG_INFO("Heap: init complete cpus=%zu magazine_bytes=0x%zx\n", num_cpus, magazine_bytes);
}

void* aligned_kalloc(size_t alignment, size_t size) {
    if (size == 0) {
        errno = EINVAL;
        KLOG_WARN("Heap: aligned_kalloc zero size\n");
        return nullptr;
    }

    if (alignment < 16) {
        alignment = 16;
    }

    // Power of 2 check: alignment & (alignment - 1) == 0
    if (!is_aligned(alignment, alignment)) {
        errno = EINVAL;
        KLOG_WARN("Heap: aligned_kalloc invalid alignment=0x%zx\n", alignment);
        return nullptr;
    }

    if (size <= MAX_SMALL_SIZE && alignment <= MAX_SMALL_SIZE) {
        size_t req_size = (size > alignment) ? size : alignment;
        req_size        = power_of_two_ceil(req_size);

        if (req_size < MIN_BLOCK_SIZE) {
            req_size = MIN_BLOCK_SIZE;
        }

        if (req_size <= MAX_SMALL_SIZE) {
            int idx      = get_bin_idx(req_size);
            uint32_t cpu = arch_get_core_idx();

            cpu_heap_t* cpu_heap = &cpu_heaps[cpu];
            magazine_t* mag      = &cpu_heap->bins[idx];

            acquire_irq_lock(&cpu_heap->lock);

            if (likely(mag->top > 0)) {
                void* ptr = mag->rounds[--mag->top];

                prefetch(ptr, 1, 3);

                if (mag->top > 0) {
                    prefetch(mag->rounds[mag->top - 1], 1, 3);
                }

                release_irq_lock(&cpu_heap->lock);
                return ptr;
            }

            int count = refill_magazines(idx, mag->rounds, BATCH_SIZE);

            if (unlikely(count == 0)) {
                if (errno == 0) {
                    errno = ENOMEM;
                }

                KLOG_WARN(
                    "Heap: refill failed idx=%d size=0x%zx align=0x%zx errno=%d\n",
                    idx,
                    req_size,
                    alignment,
                    errno
                );

                release_irq_lock(&cpu_heap->lock);
                return nullptr;
            }

            mag->top = count;

            void* ptr = mag->rounds[--mag->top];

            prefetch(ptr, 1, 3);

            if (mag->top > 0) {
                prefetch(mag->rounds[mag->top - 1], 1, 3);
            }

            release_irq_lock(&cpu_heap->lock);
            return ptr;
        }
    }

    size_t align = PAGE_SIZE_SMALL;

    if (alignment >= PAGE_SIZE_MEDIUM) {
        align = PAGE_SIZE_MEDIUM;
    } else if (alignment >= PAGE_SIZE_LARGE) {
        align = PAGE_SIZE_LARGE;
    }

    void* ptr =
        vmalloc(&kernel_space, size, VMM_FLAG_READ | VMM_FLAG_WRITE, CACHE_WRITE_BACK, align);

    if (!ptr) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_WARN(
            "Heap: aligned_kalloc vmm alloc failed size=0x%zx align=0x%zx errno=%d\n",
            size,
            align,
            errno
        );
    }

    return ptr;
}

void* kmalloc(size_t size) {
    return aligned_kalloc(16, size);
}

void kfree(void* ptr, size_t size) {
    if (unlikely(!ptr)) {
        errno = EINVAL;
        KLOG_WARN("Heap: kfree null pointer\n");
        return;
    }

    superblock_t* sb = get_superblock(ptr);

    if (sb->magic != SUPERBLOCK_MAGIC) {
        vmfree(&kernel_space, ptr, size);
        return;
    }

    int idx      = get_bin_idx(sb->object_size);
    uint32_t cpu = arch_get_core_idx();

    cpu_heap_t* cpu_heap = &cpu_heaps[cpu];
    magazine_t* mag      = &cpu_heap->bins[idx];

    acquire_irq_lock(&cpu_heap->lock);

    if (likely(mag->top < MAGAZINE_CAPACITY)) {
        mag->rounds[mag->top++] = ptr;
        release_irq_lock(&cpu_heap->lock);
        return;
    }

    flush_magazines(idx, mag->rounds, BATCH_SIZE);

    int remaining = mag->top - BATCH_SIZE;

    memmove(
        (void*)&mag->rounds[0],
        (void*)&mag->rounds[BATCH_SIZE],
        (size_t)remaining * sizeof(void*)
    );

    mag->top = remaining;

    mag->rounds[mag->top++] = ptr;
    release_irq_lock(&cpu_heap->lock);
}

void aligned_kfree(void* ptr, size_t size) {
    return kfree(ptr, size);
}