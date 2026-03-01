#include "libs/xarray.h"

#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "libs/spinlock.h"
#include "memory/heap.h"

static inline xa_node_t* xa_node_alloc(xarray_t* xa, uint8_t shift) {
    xa_node_t* node = (xa_node_t*)kmem_cache_alloc(xa->node_cache);

    if (likely(node)) {
        size_t node_size = sizeof(xa_node_t) + (sizeof(xa_node_t*) * xa->slots);
        memset(node, 0, node_size);
        node->shift = shift;
    }

    return node;
}

static inline void xa_node_free(xarray_t* xa, xa_node_t* node) {
    kmem_cache_free(xa->node_cache, node);
}

void xa_init(xarray_t* xa, uint8_t bits) {
    xa->root       = nullptr;
    xa->hint.node  = nullptr;
    xa->hint.index = 0;

    xa->bits  = bits;
    xa->slots = 1u << bits;
    xa->mask  = xa->slots - 1;

    size_t node_size = sizeof(xa_node_t) + (sizeof(xa_node_t*) * xa->slots);

    xa->node_cache = kmem_cache_create("xarray_nodes", node_size, 0, 0, nullptr);

    create_rwlock(&xa->lock);
}

static void xa_destroy_node(xarray_t* xa, xa_node_t* node) {
    if (!node) {
        return;
    }

    if (node->shift > 0) {
        for (uint32_t i = 0; i < xa->slots; ++i) {
            if (node->slots[i]) {
                xa_destroy_node(xa, (xa_node_t*)node->slots[i]);
            }
        }
    }

    xa_node_free(xa, node);
}

void xa_destroy(xarray_t* xa) {
    if (unlikely(!xa)) return;

    acquire_write(&xa->lock);

    xa_destroy_node(xa, xa->root);

    if (xa->node_cache) {
        kmem_cache_destroy(xa->node_cache);
        xa->node_cache = nullptr;
    }

    xa->root      = nullptr;
    xa->hint.node = nullptr;

    release_write(&xa->lock);
}

xa_result_t xa_store(xarray_t* restrict xa, uint64_t index, xa_entry_t entry) {
    if (unlikely(!xa || xa->bits == 0)) {
        return XA_ERR_PARAM;
    }

    acquire_write(&xa->lock);

    uint64_t max_idx = -1ul;
    if (xa->root) {
        uint32_t total_bits = xa->root->shift + xa->bits;

        if (total_bits < sizeof(uint64_t) * 8) {
            max_idx = (1ul << total_bits) - 1;
        }
    }

    while (xa->root == nullptr || index > max_idx) {
        uint8_t next_shift = (xa->root) ? (xa->root->shift + xa->bits) : 0;

        if (xa->root && next_shift >= sizeof(uint64_t) * 8) {
            release_write(&xa->lock);
            return XA_ERR_BOUNDS;
        }

        xa_node_t* new_root = xa_node_alloc(xa, next_shift);
        if (unlikely(!new_root)) {
            release_write(&xa->lock);
            return XA_ERR_NOMEM;
        }

        if (xa->root) {
            new_root->slots[0] = xa->root;
            new_root->count    = 1;
        }

        xa->root = new_root;

        uint32_t total_bits = xa->root->shift + xa->bits;
        max_idx             = (total_bits < sizeof(uint64_t) * 8) ? (1ul << total_bits) - 1 : -1ul;
    }

    xa_node_t* node = xa->root;

    if (xa->hint.node && xa->hint.node->shift == 0 && ((index & ~xa->mask) == xa->hint.index)) {
        node = xa->hint.node;
        goto insert_entry;
    }

    uint64_t shift = node->shift;
    while (shift > 0) {
        uint64_t offset = (index >> shift) & xa->mask;

        if (node->slots[offset] == nullptr) {
            xa_node_t* child = xa_node_alloc(xa, shift - xa->bits);

            if (unlikely(!child)) {
                release_write(&xa->lock);
                return XA_ERR_NOMEM;
            }

            node->slots[offset] = child;
            node->count++;
        }

        node = node->slots[offset];
        shift -= xa->bits;
    }

    xa->hint.node  = node;
    xa->hint.index = index & ~xa->mask;

insert_entry:
    uint64_t offset = index & xa->mask;

    if (node->slots[offset] == nullptr && entry != nullptr) {
        node->count++;
    } else if (node->slots[offset] != nullptr && entry == nullptr) {
        node->count--;
    }

    node->slots[offset] = (xa_node_t*)entry;

    release_write(&xa->lock);
    return XA_OK;
}

xa_entry_t xa_load(xarray_t* restrict xa, uint64_t index) {
    if (!xa->root) {
        return nullptr;
    }

    acquire_read(&xa->lock);

    if (xa->hint.node && (index & ~xa->mask) == xa->hint.index) {
        xa_entry_t ret = (xa_entry_t)(xa_entry_t)xa->hint.node->slots[index & xa->mask];
        release_read(&xa->lock);
        return ret;
    }

    xa_node_t* node     = xa->root;
    uint32_t total_bits = node->shift + xa->bits;

    if (total_bits < sizeof(uint64_t) * 8 && index >= (1ul << total_bits)) {
        release_read(&xa->lock);
        return nullptr;
    }

    while (node && node->shift > 0) {
        uint64_t offset = (index >> node->shift) & xa->mask;
        node            = node->slots[offset];
    }

    if (!node) {
        release_read(&xa->lock);
        return nullptr;
    }

    xa->hint.node  = node;
    xa->hint.index = index & ~xa->mask;

    xa_entry_t ret = (xa_entry_t)node->slots[index & xa->mask];
    release_read(&xa->lock);
    return ret;
}

xa_entry_t xa_erase(xarray_t* restrict xa, uint64_t index) {
    if (!xa->root) {
        return nullptr;
    }

    acquire_write(&xa->lock);

    xa_node_t* path[16];
    int path_idx    = 0;
    xa_node_t* node = xa->root;

    while (node && node->shift > 0) {
        path[path_idx++] = node;
        uint64_t offset  = (index >> node->shift) & xa->mask;
        node             = node->slots[offset];
    }

    if (!node) {
        release_write(&xa->lock);
        return nullptr;
    }

    uint64_t offset = index & xa->mask;
    xa_entry_t val  = (xa_entry_t)node->slots[offset];

    if (val) {
        node->slots[offset] = nullptr;
        node->count--;

        if (xa->hint.node == node && xa->hint.index == (index & ~xa->mask)) {
            xa->hint.node  = nullptr;
            xa->hint.index = 0;
        }

        xa_node_t* curr = node;

        while (curr->count == 0) {
            if (path_idx == 0) {
                xa->root = nullptr;
                xa_node_free(xa, node);
                break;
            }

            xa_node_t* parent = path[path_idx - 1];
            uint64_t p_offset = (index >> parent->shift) & xa->mask;

            parent->slots[p_offset] = nullptr;
            parent->count--;

            xa_node_free(xa, node);
            curr = parent;
        }
    }

    release_write(&xa->lock);
    return val;
}

xa_entry_t xa_find_after(xarray_t* restrict xa, uint64_t* restrict index) {
    if (unlikely(!xa->root || !xa || index == 0)) {
        return nullptr;
    }

    acquire_read(&xa->lock);

    xa_cursor_t cursor;
    xa_cursor_reset(&cursor, xa, *index);
    xa_entry_t entry = xa_cursor_next(&cursor);

    if (entry) {
        *index = cursor.index;
    }

    release_read(&xa->lock);
    return entry;
}

void xa_cursor_reset(xa_cursor_t* cursor, const xarray_t* xa, uint64_t start_idx) {
    cursor->xa    = xa;
    cursor->index = start_idx;
    cursor->depth = -1;

    if (unlikely(!xa || !xa->root)) {
        return;
    }

    xa_node_t* node = xa->root;

    uint32_t total_bits = node->shift + xa->bits;

    if (total_bits < sizeof(uint64_t) * 8 && start_idx >= (1ul << total_bits)) {
        return;
    }

    cursor->depth          = 0;
    cursor->path[0].node   = node;
    cursor->path[0].offset = 0;

    int d = 0;
    while (node->shift > 0) {
        uint64_t shift  = node->shift;
        uint64_t offset = (start_idx >> shift) & xa->mask;

        cursor->path[d].node   = node;
        cursor->path[d].offset = (uint8_t)offset;

        if (node->slots[offset] == nullptr) {
            break;
        }

        node = node->slots[offset];
        d++;
    }

    cursor->path[d].node   = node;
    cursor->path[d].offset = (uint8_t)(start_idx & xa->mask);
    cursor->depth          = d;
}

xa_entry_t xa_cursor_next(xa_cursor_t* cursor) {
    if (cursor->depth < 0) {
        return nullptr;
    }

    while (cursor->depth >= 0) {
        int d           = cursor->depth;
        xa_node_t* node = cursor->path[d].node;
        uint8_t offset  = cursor->path[d].offset;

        if (offset >= cursor->xa->slots) {
            cursor->depth--;

            if (cursor->depth >= 0) {
                cursor->path[cursor->depth].offset++;
            }

            continue;
        }

        xa_node_t* child = node->slots[offset];

        if (!child) {
            cursor->path[d].offset++;
            continue;
        }

        if (node->shift == 0) {
            uint64_t found_idx = 0;
            cursor->path[d].offset++;

            uint64_t reconstructed_index = 0;
            for (int i = 0; i <= cursor->depth; ++i) {
                uint64_t shift = cursor->path[i].node->shift;
                uint64_t off   = cursor->path[i].offset - (i == cursor->depth ? 1 : 0);

                reconstructed_index |= (off << shift);
            }

            cursor->index = reconstructed_index;
            return (xa_entry_t)child;
        } else {
            cursor->depth++;
            cursor->path[cursor->depth].node   = child;
            cursor->path[cursor->depth].offset = 0;
        }
    }

    return nullptr;
}