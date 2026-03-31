#ifndef KERNEL_MEMORY_VMA_H
#define KERNEL_MEMORY_VMA_H 1

#include "cpu/exception.h"
#include "libs/kobject.h"
#include "libs/rb_tree.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/pagemap.h"
#include "memory/vm_object.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAP_HUGE_SHIFT 26
#define MAP_HUGE_MASK  0x3f

#define PROT_NONE  0
#define PROT_EXEC  0x01
#define PROT_READ  0x02
#define PROT_WRITE 0x04

#define MAP_SHARED          0x001
#define MAP_PRIVATE         0x002
#define MAP_ANONYMOUS       0x004
#define MAP_FIXED_NOREPLACE 0x008
#define MAP_FIXED           0x010
#define MAP_GROWSDOWN       0x020
#define MAP_HUGETLB         0x040
#define MAP_POPULATE        0x080
#define MAP_STACK           0x100
#define MAP_LOCKED          0x200

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

#define MREMAP_MAYMOVE   0x01
#define MREMAP_FIXED     0x02
#define MREMAP_DONTUNMAP 0x04

struct vm_area {
    struct rb_node rb_node;

    size_t subtree_max_gap;
    size_t own_gap;

    uintptr_t start;
    uintptr_t end;

    struct vm_object* object;
    size_t object_offset;

    uint32_t flags;
    uint16_t cache;
    uint8_t page_shift;  // 12 for 4K, 21 for 2M, 30 for 1G
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] vm_space {
    struct kobject refcount;
    struct rb_root rb_root;
    struct process* owner;

    _Atomic(struct vm_area*) cached_vma;
    rwlock_t lock;

    uintptr_t allocation_hint;
};

struct vmm_fault_info {
    bool is_present;
    bool is_write;
    bool is_user;
    bool is_exec;
};

static inline size_t vma_size(struct vm_area* vma) {
    return vma->end - vma->start;
}

static inline size_t vma_page_size(struct vm_area* vma) {
    return 1ul << vma->page_shift;
}

bool vmm_is_user_region(uintptr_t addr, size_t size);

struct vm_space* vmm_create_space(struct process* owner);
void vmm_init_space(struct vm_space* space, struct process* owner);
void vmm_destroy_space(struct vm_space* space);
void vmm_space_release(struct kobject* ref);

void* vmalloc(
    struct vm_space* space,
    void* hint_addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
);

void vmfree(struct vm_space* space, void* ptr, size_t size);

struct vmm_fault_info arch_decode_fault_error(uintptr_t error_code);
bool vmm_handle_fault(struct vm_space* space, uintptr_t fault_addr, uint32_t error_code);
bool vmm_clone_space(struct vm_space* parent, struct vm_space* child);

void pf_handler(interrupt_trapframe_t* tf);

bool vmm_populate_vma_range(
    struct vm_space* space,
    struct vm_area* vma,
    uintptr_t start,
    size_t size
);

void* sys_mmap(
    struct vm_space* space,
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    long offset
);

int sys_munmap(struct vm_space* space, void* addr, size_t length);
int sys_mprotect(struct vm_space* space, void* addr, size_t size, int prot);

void* sys_mremap(
    struct vm_space* space,
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address
);

extern struct vm_space* kernel_space;
extern kmem_cache_t* vma_cache;

void vma_cache_init(void);

#ifdef __cplusplus
}
#endif

#endif