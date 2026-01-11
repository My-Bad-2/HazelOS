#ifndef KERNEL_CPU_SIMD_H
#define KERNEL_CPU_SIMD_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void simd_init(void);
void simd_save(void* buffer);
void simd_restore(void* buffer);

void* simd_get_clean_state(void);
size_t simd_get_save_size(void);

#ifdef __cplusplus
}
#endif

#endif