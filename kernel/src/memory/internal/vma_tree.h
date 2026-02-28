#ifndef KERNEL_MEMORY_INTERNAL_VMA_TREE_H
#define KERNEL_MEMORY_INTERNAL_VMA_TREE_H 1

#include "memory/vma.h"

bool vma_compute_subtree_gap(struct rb_node* node);
void vma_propagate_gap_up(struct rb_node* node);

void vmm_insert_vma(vm_space_t* space, vm_area_t* new_vma);
vm_area_t* vmm_find_vma_unsafe(vm_space_t* space, uintptr_t addr);

bool vmm_find_gap_bottom_up(vm_space_t* space, size_t size, size_t align, uintptr_t* addr);
bool vmm_find_gap_top_down(vm_space_t* space, size_t size, size_t align, uintptr_t* addr);

bool vmm_try_merge(
    vm_space_t* space,
    uintptr_t addr,
    size_t size,
    uint32_t flags,
    cache_type_t cache,
    size_t page_size
);

vm_area_t* vmm_split_vma(vm_space_t* space, vm_area_t* vma, uintptr_t split_addr);

#endif