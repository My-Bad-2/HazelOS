#include "libs/xarray.h"
#ifndef KERNEL_LIBS_HANDLES_H
#define KERNEL_LIBS_HANDLES_H 1

#include <stdint.h>

#include "spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

// [32-bit generation] [32-bit index]
typedef uint64_t handle_t;

#define HANDLE_INVALID 0

typedef struct [[gnu::aligned(16)]] {
    void* obj;
    uint32_t next_free;
    uint32_t generation;  // Version counter
    uint32_t rights;      // rights
} handle_slot_t;

typedef struct {
    spinlock_t lock;
    xarray_t xa;
    uint32_t next_free_idx;
    uint32_t max_idx;
    int active_count;
} handle_table_t;

void handle_table_init(handle_table_t* table);
handle_t handle_alloc(handle_table_t* table, void* ptr, uint32_t rights);
void* handle_lookup(handle_table_t* table, handle_t handle, uint32_t rights);
void* handle_free(handle_table_t* table, handle_t handle);
int handle_get_rights(handle_table_t* table, handle_t handle, uint32_t* rights_out);

#ifdef __cplusplus
}
#endif

#endif