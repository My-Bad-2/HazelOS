#ifndef KERNEL_LIBS_XARRAY_H
#define KERNEL_LIBS_XARRAY_H 1

#include <stddef.h>
#include <stdint.h>

#include "libs/spinlock.h"
#include "memory/heap.h"

#define XA_TAG_MASK  0x3ul
#define XA_MAX_DEPTH 64

typedef void* xa_entry_t;

typedef struct xa_node {
    uint8_t shift;
    uint32_t count;
    struct xa_node* slots[];
} xa_node_t;

typedef struct xarray {
    xa_node_t* root;
    rwlock_t lock;

    uint8_t bits;
    uint32_t slots;
    uint64_t mask;

    kmem_cache_t* node_cache;

    struct {
        xa_node_t* node;
        uint64_t index;
    } hint;
} xarray_t;

typedef struct {
    const xarray_t* xa;
    uint64_t index;

    struct {
        xa_node_t* node;
        uint8_t offset;
    } path[XA_MAX_DEPTH];

    int depth;
} xa_cursor_t;

typedef enum {
    XA_OK = 0,
    XA_ERR_NOMEM,
    XA_ERR_PARAM,
    XA_ERR_BOUNDS,
} xa_result_t;

void xa_init(xarray_t* xa, uint8_t bits);
void xa_destroy(xarray_t* xa);

xa_result_t xa_store(xarray_t* restrict xa, uint64_t index, xa_entry_t entry);
xa_entry_t xa_load(xarray_t* restrict xa, uint64_t index);

xa_entry_t xa_erase(xarray_t* restrict xa, uint64_t index);
xa_entry_t xa_find_after(xarray_t* restrict xa, uint64_t* restrict index);

void xa_cursor_reset(xa_cursor_t* cursor, const xarray_t* xa, uint64_t start_idx);
xa_entry_t xa_cursor_next(xa_cursor_t* cursor);

static inline xa_entry_t xa_tag_ptr(void* ptr, uint32_t tag) {
    return (xa_entry_t)((uintptr_t)ptr | (tag & XA_TAG_MASK));
}

static inline void* xa_untag_ptr(xa_entry_t ptr) {
    return (xa_entry_t)((uintptr_t)ptr & ~XA_TAG_MASK);
}

static inline uint32_t xa_get_tag(xa_entry_t entry) {
    return (uint32_t)((uintptr_t)entry & XA_TAG_MASK);
}

static inline xa_entry_t xa_mk_value(uint64_t val) {
    return (xa_entry_t)((val << 1) | 1);
}

static inline uint64_t xa_to_value(xa_entry_t entry) {
    return ((uintptr_t)entry) >> 1;
}

static inline bool xa_is_value(xa_entry_t entry) {
    return ((uintptr_t)entry & 1);
}

#define xa_for_each(xa, index, entry)                                            \
    for ((index) = 0, (entry) = xa_find_after(xa, &(index)); (entry) != nullptr; \
         (index)++, (entry)   = xa_find_after(xa, &(index)))

#define xa_for_each_cursor(cursor, xa, start_idx, entry)                           \
    for (xa_cursor_reset(cursor, xa, start_idx), (entry) = xa_cursor_next(cursor); \
         (entry) != nullptr;                                                       \
         (entry) = xa_cursor_next(cursor))

#endif