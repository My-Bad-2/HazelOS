#ifndef KERNEL_MEMORY_INTERNAL_VM_OBJECT_H
#define KERNEL_MEMORY_INTERNAL_VM_OBJECT_H 1

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/capability.h"
#include "libs/kobject.h"
#include "libs/spinlock.h"
#include "libs/xarray.h"
#include "sched/ipc.h"

#define PAGE_FLAG_DIRTY  0x001u
#define PAGE_FLAG_PINNED 0x002u

// Superpage tags
#define PAGE_FLAG_2M 0x004u
#define PAGE_FLAG_1G 0x008u

typedef enum {
    VM_OBJ_ANONYMOUS,
    VM_OBJ_PHYSICAL,  // Direct contiguous physical memory (MMIO)
    VM_OBJ_SHADOW,    // Copy-on-Write clones
    VM_OBJ_PAGER,     // Backed by an external userspace process
} vmo_type_t;

typedef struct vm_object {
    struct kobject kobj;
    vmo_type_t type;
    uint32_t read_ahead_cluster;
    size_t size;

    rwlock_t lock;
    xarray_t page_tree;

    struct vm_object* backing;
    size_t backing_offset;

    struct ipc_port* pager_port;
    uint64_t pager_key;
} vm_object_t;

// Initialization
void vm_object_init(void);

// Object Lifecycle
vm_object_t* vm_object_create(vmo_type_t type, size_t size);
vm_object_t*
vm_object_create_pager(size_t size, struct ipc_port* port, uint64_t key, uint32_t cluster_size);
vm_object_t* vm_object_create_shadow(vm_object_t* parent_obj, size_t offset, size_t size);
void vmo_release(struct kobject* kobj);

void vm_object_ref(vm_object_t* obj);
void vm_object_deref(vm_object_t* obj);

int vm_object_get_page(
    vm_object_t* obj,
    size_t offset,
    uint8_t page_shift,
    bool alloc_on_miss,
    bool is_write,
    uintptr_t* out_phys
);
int vm_object_pin_page(vm_object_t* obj, size_t offset, bool pin);

// Memory Management
void vm_object_collapse(vm_object_t* obj);
void vm_object_truncate(vm_object_t* obj, size_t start_offset, size_t end_offset);
int vm_object_evict_page(vm_object_t* obj, size_t offset);

int sys_vmo_supply_pages(
    struct cnode* root,
    uint64_t vmo_cap,
    size_t offset,
    void* user_data,
    size_t length
);

#endif