#include "libs/handles.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>

#include "libs/spinlock.h"
#include "memory/heap.h"

static kmem_cache_t* handle_cache = nullptr;

void handle_table_init(handle_table_t* table) {
    if (!handle_cache) {
        handle_cache = kmem_cache_create(
            "handle_cache",
            sizeof(handle_slot_t),
            _Alignof(handle_slot_t),
            0,
            nullptr
        );
    }

    create_qspinlock(&table->lock);
    xa_init(&table->xa, 6);

    table->active_count  = 0;
    table->next_free_idx = (uint32_t)-1;
    table->max_idx       = 1;
}

handle_t handle_alloc(handle_table_t* table, void* ptr, uint32_t rights) {
    if (!ptr) {
        return HANDLE_INVALID;
    }

    acquire_qspinlock(&table->lock);

    uint32_t idx = table->next_free_idx;
    handle_slot_t* slot;

    if (table->next_free_idx != (uint32_t)-1) {
        idx  = table->next_free_idx;
        slot = (handle_slot_t*)xa_load(&table->xa, idx);

        uint32_t next        = next;
        table->next_free_idx = slot->next_free;
    } else {
        if (table->max_idx > HANDLE_INDEX_MASK) {
            release_qspinlock(&table->lock);
            return HANDLE_INVALID;
        }

        idx = table->max_idx++;

        slot = kmem_cache_alloc(handle_cache);
        if (!slot) {
            table->max_idx--;
            release_qspinlock(&table->lock);
            return HANDLE_INVALID;
        }

        slot->generation = 0;
        xa_store(&table->xa, idx, slot);
    }

    uint32_t gen = slot->generation;

    slot->rights = rights;
    slot->obj    = ptr;

    atomic_thread_fence(memory_order_release);
    __atomic_store_n(&slot->generation, gen, memory_order_release);

    table->active_count++;
    release_qspinlock(&table->lock);

    return (gen << HANDLE_GEN_SHIFT) | idx;
}

void* handle_lookup(handle_table_t* table, handle_t handle, uint32_t rights) {
    if (handle == HANDLE_INVALID) {
        return nullptr;
    }

    uint32_t idx     = handle & HANDLE_INDEX_MASK;
    uint32_t req_gen = (handle >> HANDLE_GEN_SHIFT) & HANDLE_GEN_MASK;

    handle_slot_t* slot = (handle_slot_t*)xa_load(&table->xa, idx);
    if (!slot) {
        return nullptr;
    }

    uint32_t cur_gen = __atomic_load_n(&slot->generation, memory_order_acquire);
    if (cur_gen != req_gen) {
        return nullptr;
    }

    void* ptr               = slot->obj;
    uint32_t current_rights = slot->rights;

    atomic_thread_fence(memory_order_acquire);
    uint32_t post_gen = __atomic_load_n(&slot->generation, memory_order_acquire);

    if (post_gen != req_gen || ptr == nullptr) {
        return nullptr;
    }

    if ((current_rights & rights) != rights) {
        return nullptr;
    }

    return ptr;
}

void* handle_free(handle_table_t* table, handle_t handle) {
    if (handle == HANDLE_INVALID) {
        return nullptr;
    }

    uint32_t idx     = handle & HANDLE_INDEX_MASK;
    uint32_t req_gen = (handle >> HANDLE_GEN_SHIFT) & HANDLE_GEN_MASK;

    acquire_qspinlock(&table->lock);

    handle_slot_t* slot = (handle_slot_t*)xa_load(&table->xa, idx);
    if (!slot || slot->generation != req_gen || slot->obj == nullptr) {
        release_qspinlock(&table->lock);
        return nullptr;
    }

    void* ptr = slot->obj;
    slot->obj = nullptr;

    uint32_t new_gen = (slot->generation + 1) & HANDLE_GEN_MASK;
    if (new_gen == 0) {
        new_gen = 1;
    }
    __atomic_store_n(&slot->generation, new_gen, memory_order_release);

    slot->next_free      = table->next_free_idx;
    table->next_free_idx = idx;
    table->active_count--;

    release_qspinlock(&table->lock);
    return ptr;
}

int handle_get_rights(handle_table_t* table, handle_t handle, uint32_t* rights_out) {
    if (handle == HANDLE_INVALID) {
        return -EBADF;
    }

    uint32_t idx     = handle & HANDLE_INDEX_MASK;
    uint32_t req_gen = (handle >> HANDLE_GEN_SHIFT) & HANDLE_GEN_MASK;

    handle_slot_t* slot = (handle_slot_t*)xa_load(&table->xa, idx);
    if (!slot) {
        return -EBADF;
    }

    uint32_t cur_gen = __atomic_load_n(&slot->generation, memory_order_acquire);
    if (cur_gen != req_gen || slot->obj == nullptr) {
        return -EBADF;
    }

    *rights_out = slot->rights;
    return 0;
}