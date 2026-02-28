#include "libs/handles.h"

#include <errno.h>
#include <stdatomic.h>

#include "libs/spinlock.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

void handle_table_init(handle_table_t* table) {
    create_spinlock(&table->lock);

    table->active_count  = 0;
    table->next_free_idx = 0;

    table->slots = (handle_slot_t*)vmalloc(
        kernel_space,
        nullptr,
        sizeof(handle_slot_t) * HANDLE_MAX,
        VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    for (uint32_t i = 0; i < HANDLE_MAX - 1; ++i) {
        table->slots[i].obj        = nullptr;
        table->slots[i].generation = 0;
        table->slots[i].next_free  = i + 1;
    }

    table->slots[HANDLE_MAX - 1].next_free = (uint32_t)(-1);
}

handle_t handle_alloc(handle_table_t* table, void* ptr, uint32_t rights) {
    acquire_spinlock(&table->lock);

    if (table->next_free_idx == (uint32_t)-1) {
        release_spinlock(&table->lock);
        return 0;
    }

    uint32_t idx        = table->next_free_idx;
    handle_slot_t* slot = &table->slots[idx];

    table->next_free_idx = slot->next_free;

    uint32_t new_gen = slot->generation;

    if (new_gen == 0) {
        slot->generation++;
    }

    slot->obj    = ptr;
    slot->rights = rights;
    __atomic_store_n(&slot->generation, new_gen, memory_order_release);

    table->active_count++;
    release_spinlock(&table->lock);

    return (handle_t)((new_gen << 16) | idx);
}

void* handle_lookup(handle_table_t* table, handle_t handle, uint32_t rights) {
    uint32_t idx     = handle & HANDLE_IDX_MASK;
    uint32_t req_gen = (handle >> 16);

    if (idx >= HANDLE_MAX) {
        return nullptr;
    }

    handle_slot_t* slot = &table->slots[idx];

    uint32_t cur_gen = __atomic_load_n(&slot->generation, memory_order_acquire);

    if (cur_gen != req_gen) {
        return nullptr;
    }

    void* ptr         = slot->obj;
    uint32_t post_gen = __atomic_load_n(&slot->generation, memory_order_acquire);

    if (post_gen != req_gen || slot->obj == nullptr) {
        return nullptr;
    }

    // We check if the handle has all the bits requested in `required_rights`
    if ((slot->rights & rights) != rights) {
        // Access denied
        return nullptr;
    }

    return ptr;
}

void* handle_free(handle_table_t* table, handle_t handle) {
    create_spinlock(&table->lock);

    uint32_t idx     = handle & HANDLE_IDX_MASK;
    uint32_t req_gen = (handle >> 16);

    if (idx >= HANDLE_MAX) {
        return nullptr;
    }

    handle_slot_t* slot = &table->slots[idx];

    if (slot->generation != req_gen) {
        release_spinlock(&table->lock);
        return nullptr;
    }

    void* ptr = slot->obj;

    slot->obj = nullptr;

    slot->next_free      = table->next_free_idx;
    table->next_free_idx = idx;

    table->active_count--;

    release_spinlock(&table->lock);
    return ptr;
}

int handle_get_rights(handle_table_t* table, handle_t handle, uint32_t* rights_out) {
    uint32_t idx = handle & HANDLE_IDX_MASK;
    uint32_t gen = handle >> 16;

    if (idx >= HANDLE_MAX) {
        return -EBADF;
    }

    handle_slot_t* slot = &table->slots[idx];

    if (slot->generation != gen) {
        return -EBADF;
    }

    *rights_out = slot->rights;
    return 0;
}