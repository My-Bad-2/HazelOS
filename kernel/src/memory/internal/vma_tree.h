#ifndef KERNEL_MEMORY_INTERNAL_VMA_TREE_H
#define KERNEL_MEMORY_INTERNAL_VMA_TREE_H 1

#include "memory/vma.h"

bool vma_compute_subtree_gap(struct rb_node* node);
void vma_propagate_gap_up(struct rb_node* node);

void vmm_insert_vma(struct vm_space* space, struct vm_area* new_vma);
struct vm_area* vmm_find_vma_unsafe(struct vm_space* space, uintptr_t addr);

bool vmm_find_gap_bottom_up(struct vm_space* space, size_t size, size_t align, uintptr_t* addr);
bool vmm_find_gap_top_down(struct vm_space* space, size_t size, size_t align, uintptr_t* addr);

bool vmm_try_merge(
    struct vm_space* space,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    uint8_t page_shift,
    struct vm_object* object,
    size_t object_offset
);

struct vm_area* vmm_split_vma(struct vm_space* space, struct vm_area* vma, uintptr_t split_addr);

#endif