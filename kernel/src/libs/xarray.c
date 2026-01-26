#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "libs/spinlock.h"
#include "libs/xarray.h"

static void xa_node_reset(xa_node_t* node, uint8_t shift) {
    node->shift  = shift;
    node->count  = 0;

    memset((void*)node->slots, 0, sizeof(node->slots));
}

void xa_init(xarray_t* xa) {
    xa->root       = nullptr;
    xa->hint.node  = nullptr;
    xa->hint.index = 0;

    create_rwlock(&xa->lock);
}

xa_result_t
xa_store(xarray_t* restrict xa, uint64_t index, xa_entry_t* entry, xa_node_t** restrict spare) {
    if (unlikely(!xa || !spare)) {
        return XA_ERR_PARAM;
    }

    acquire_write(&xa->lock);

    uint64_t max_idx = -1ul;
    if (xa->root) {
        uint32_t total_bits = xa->root->shift + XA_BITS;

        if (total_bits < sizeof(uint64_t) * 8) {
            max_idx = (1ul << total_bits) - 1;
        }
    }

    while (xa->root == nullptr || index > max_idx) {
        if (*spare == nullptr) {
            release_write(&xa->lock);
            return XA_NEED_NODE;
        }

        xa_node_t* new_root = *spare;
        *spare              = nullptr;

        uint8_t next_shift = (xa->root) ? (xa->root->shift + XA_BITS) : 0;

        if (xa->root && next_shift >= sizeof(uint64_t) * 8) {
            release_write(&xa->lock);
            return XA_ERR_BOUNDS;
        }

        xa_node_reset(new_root, next_shift);

        if (xa->root) {
            new_root->slots[0] = xa->root;
            new_root->count    = 1;
        }

        xa->root = new_root;

        uint32_t total_bits = xa->root->shift + XA_BITS;
        max_idx             = (total_bits < sizeof(uint64_t) * 8) ? (1ul << total_bits) - 1 : -1ul;
    }

    xa_node_t* node = xa->root;

    if (xa->hint.node && xa->hint.node->shift == 0) {
        if ((index & ~XA_MASK) == xa->hint.index) {
            node = xa->hint.node;
            goto insert_entry;
        }
    }

    uint64_t shift = node->shift;

    while (shift > 0) {
        uint64_t offset = (index >> shift) & XA_MASK;

        if (node->slots[offset] == nullptr) {
            if (*spare == nullptr) {
                release_write(&xa->lock);
                return XA_NEED_NODE;
            }

            xa_node_t* child = *spare;
            *spare           = nullptr;

            xa_node_reset(child, shift - XA_BITS);
            node->slots[offset] = child;
            node->count++;
        }

        node = node->slots[offset];
        shift -= XA_BITS;
    }

    xa->hint.node  = node;
    xa->hint.index = index & ~XA_MASK;

insert_entry:
    uint64_t offset = index & XA_MASK;

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

    if (xa->hint.node && (index & ~XA_MASK) == xa->hint.index) {
        return (xa_entry_t)xa->hint.node->slots[index & XA_MASK];
    }

    acquire_read(&xa->lock);

    xa_node_t* node = xa->root;

    uint32_t total_bits = node->shift + XA_BITS;

    if (total_bits < sizeof(uint64_t) * 8) {
        if (index >= (1ul << total_bits)) {
            release_read(&xa->lock);
            return nullptr;
        }
    }

    while (node && node->shift > 0) {
        uint64_t offset = (index >> node->shift) & XA_MASK;
        node            = node->slots[offset];
    }

    if (!node) {
        release_read(&xa->lock);
        return nullptr;
    }

    xa->hint.node  = node;
    xa->hint.index = index & ~XA_MASK;

    xa_entry_t ret = (xa_entry_t)node->slots[index & XA_MASK];

    release_read(&xa->lock);
    return ret;
}

xa_entry_t xa_erase(xarray_t* restrict xa, uint64_t index, xa_node_t** freed_node) {
    if (freed_node) {
        *freed_node = nullptr;
    }

    if (!xa->root) {
        return nullptr;
    }

    acquire_write(&xa->lock);

    xa_node_t* path[16];
    int path_idx    = 0;
    xa_node_t* node = xa->root;

    while (node && node->shift > 0) {
        path[path_idx++] = node;
        uint64_t offset  = (index >> node->shift) & XA_MASK;
        node             = node->slots[offset];
    }

    if (!node) {
        release_write(&xa->lock);
        return nullptr;
    }

    uint64_t offset = index & XA_MASK;
    xa_entry_t val  = (xa_entry_t)node->slots[offset];

    if (val) {
        node->slots[offset] = nullptr;
        node->count--;

        if (xa->hint.node == node) {
            xa->hint.node = nullptr;
        }

        if (node->count == 0) {
            if (path_idx == 0) {
                if (freed_node) {
                    *freed_node = xa->root;
                }

                xa->root = nullptr;
            } else {
                xa_node_t* parent = path[path_idx - 1];
                uint64_t p_offset = (index >> parent->shift) & XA_MASK;

                parent->slots[p_offset] = nullptr;
                parent->count--;

                if (freed_node) {
                    *freed_node = node;
                }
            }
        }
    }

    release_write(&xa->lock);
    return val;
}

xa_entry_t xa_find_after(xarray_t* restrict xa, uint64_t* restrict index) {
    if (unlikely(!xa->root || !xa)) {
        return nullptr;
    }

    if (unlikely(!index)) {
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

    uint32_t total_bits = node->shift + XA_BITS;

    if (total_bits < sizeof(uint64_t) * 8) {
        if (start_idx >= (1ul << total_bits)) {
            return;
        }
    }

    cursor->depth          = 0;
    cursor->path[0].node   = node;
    cursor->path[0].offset = 0;

    int d = 0;
    while (node->shift > 0) {
        uint64_t shift  = node->shift;
        uint64_t offset = (start_idx >> shift) & XA_MASK;

        cursor->path[d].node   = node;
        cursor->path[d].offset = (uint8_t)offset;

        if (node->slots[offset] == nullptr) {
            break;
        }

        node = node->slots[offset];
        d++;
    }

    cursor->path[d].node   = node;
    cursor->path[d].offset = (uint8_t)(start_idx & XA_MASK);
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

        if (offset >= XA_SLOTS) {
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

            uint64_t mask_for_level = (1ul << (node->shift + XA_BITS)) - 1;
            cursor->index = (cursor->index & ~mask_for_level) | ((uint64_t)offset << node->shift);

            return (xa_entry_t)child;
        } else {
            cursor->depth++;
            cursor->path[cursor->depth].node   = child;
            cursor->path[cursor->depth].offset = 0;
        }
    }

    return nullptr;
}