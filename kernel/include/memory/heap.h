#ifndef KERNEL_MEMORY_HEAP_H
#define KERNEL_MEMORY_HEAP_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* kmalloc(size_t size);
void* kaligned_alloc(size_t alignment, size_t size);

void kfree(void* ptr);
void kaligned_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif