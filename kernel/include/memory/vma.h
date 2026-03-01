#ifndef KERNEL_MEMORY_VMA_H
#define KERNEL_MEMORY_VMA_H 1

#include "cpu/exception.h"
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

typedef struct vm_area {
    struct rb_node rb_node;

    size_t subtree_max_gap;  // Max gap in this subtree
    size_t own_gap;          // Gap between prev->end and this->start

    uintptr_t start;
    uintptr_t end;  // Exclusive: [Start, end)
    size_t size;
    size_t page_size;  // Actual page size used (4K, 2M or 1G)
    uint32_t flags;
    cache_type_t cache;

    vm_object_t* object;
    size_t object_offset;
} vm_area_t;

typedef struct [[gnu::aligned(CACHE_LINE_SIZE)]] {
    struct rb_root rb_root;
    pagemap_t* map;

    _Atomic(vm_area_t*) cached_vma;
    rwlock_t lock;

    uintptr_t start_limit;
    uintptr_t end_limit;
    uintptr_t allocation_hint;
} vm_space_t;

struct vmm_fault_info {
    bool is_present;
    bool is_write;
    bool is_user;
    bool is_exec;
};

void vmm_init_space(vm_space_t* space, pagemap_t* map, uintptr_t start, uintptr_t end);
void vmm_destroy_space(vm_space_t* space);

void* vmalloc(
    vm_space_t* space,
    void* hint_addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t alignment
);

void vmfree(vm_space_t* space, void* ptr, size_t size);

struct vmm_fault_info arch_decode_fault_error(uintptr_t error_code);
bool vmm_handle_fault(vm_space_t* space, uintptr_t fault_addr, uint32_t error_code);
bool vmm_clone_space(vm_space_t* parent, vm_space_t* child);

void pf_handler(interrupt_trapframe_t* tf);

bool vmm_populate_vma_range(vm_space_t* space, vm_area_t* vma, uintptr_t start, size_t size);

void* sys_mmap(
    vm_space_t* space,
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    long offset
);

int sys_munmap(vm_space_t* space, void* addr, size_t length);
int sys_mprotect(vm_space_t* space, void* addr, size_t size, int prot);

void* sys_mremap(
    vm_space_t* space,
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address
);

extern vm_space_t* kernel_space;
extern kmem_cache_t* vma_cache;

void vma_cache_init(void);

#ifdef __cplusplus
}
#endif

#endif