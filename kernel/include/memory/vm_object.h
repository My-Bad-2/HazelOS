#ifndef KERNEL_MEMORY_INTERNAL_VM_OBJECT_H
#define KERNEL_MEMORY_INTERNAL_VM_OBJECT_H 1

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "libs/spinlock.h"
#include "libs/xarray.h"

#define PAGE_FLAG_DIRTY  0x001u
#define PAGE_FLAG_PINNED 0x002u

typedef enum {
    VM_OBJ_ANONYMOUS,
    VM_OBJ_FILE,
    VM_OBJ_SHADOW,
} vm_object_type_t;

struct vm_object {
    rwlock_t lock;
    _Atomic(size_t) ref_count;

    vm_object_type_t type;
    size_t size;

    xarray_t pages;

    void* vnode;
    struct vm_object* backing;
};

struct vm_object* vm_object_create(vm_object_type_t type, size_t size);
void vm_object_ref(struct vm_object* obj);
void vm_object_deref(struct vm_object* obj);

struct vm_object* vm_object_create_shadow(struct vm_object* parent_obj);
uintptr_t
vm_object_get_page(struct vm_object* obj, size_t offset, bool allocate_on_miss, bool is_write);
uintptr_t vm_object_get_huge_page(struct vm_object* obj, size_t offset, bool is_write);

void vm_object_collapse(struct vm_object* obj);
void vm_object_truncate(struct vm_object* obj, size_t start_offset, size_t end_offset);
bool vm_object_pin_page(struct vm_object* obj, size_t offset, bool pin);

void vm_object_init(void);

#endif