#ifndef KERNEL_LIBS_HANDLES_H
#define KERNEL_LIBS_HANDLES_H 1

#include <stdint.h>

#include "spinlock.h"

#define HANDLE_MAX      (UINT16_MAX + 1)
#define HANDLE_IDX_MASK (HANDLE_MAX - 1)

typedef uint32_t handle_t;

typedef struct [[gnu::aligned(16)]] {
    void* obj;            // Pointer to Process/Thread
    uint32_t generation;  // (Version counter)
    uint32_t next_free;   // Free list link
} handle_slot_t;

typedef struct {
    spinlock_t lock;
    handle_slot_t* slots;
    uint32_t next_free_idx;
    int active_count;
} handle_table_t;

void handle_table_init(handle_table_t* table);
handle_t handle_alloc(handle_table_t* table, void* ptr);
void* handle_lookup(handle_table_t* table, handle_t handle);
void* handle_free(handle_table_t* table, handle_t handle);

#endif