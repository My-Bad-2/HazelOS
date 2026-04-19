#ifndef KERNEL_MEMORY_CACHE_H
#define KERNEL_MEMORY_CACHE_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CACHE_UNCACHEABLE = 0,
    CACHE_MMIO,
    CACHE_WRITE_THROUGH,
    CACHE_WRITE_PROTECTED,
    CACHE_WRITE_COMBINING,
    CACHE_WRITE_BACK,
    CACHE_DEVICE,
    CACHE_FRAMEBUFFER,
    CACHE_ROM,
} cache_type_t;

#ifdef __cplusplus
}
#endif

#endif
