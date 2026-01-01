#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* kmalloc(size_t size);
void kfree(void* ptr, size_t size);

void* aligned_kalloc(size_t alignment, size_t size);
void aligned_kfree(void* ptr, size_t size);

void kheap_init(void);

#ifdef __cplusplus
}
#endif

#endif