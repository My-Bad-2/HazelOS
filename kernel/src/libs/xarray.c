#include "libs/xarray.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "libs/log.h"
#include "libs/math.h"
#include "libs/spinlock.h"
#include "memory/heap.h"

#if 0
static kmem_cache_t* xa_node_cache;

static void xa_node_reset(xa_node_t* node, uint8_t shift) {
    node->shift  = shift;
    node->count  = 0;
    node->bitmap = 0;
    node->offset = 0;

    memset((void*)node->slots, 0, sizeof(node->slots));
}

void xa_init(xarray_t* xa) {
    if (!xa_node_cache) {
        kmem_cache_create("xarray_node", sizeof(xa_node_t), 0, SLAB_HWCACHE_ALIGN, nullptr);
    }

    if (!xa_node_cache) {
        PANIC("XARRAY: Cannot create cache for xa_node");
        return;
    }

    xa->root       = nullptr;
    xa->hint.node  = nullptr;
    xa->hint.index = 0;

    create_rwlock(&xa->lock);
}

static void xa_destroy_recursive(xa_node_t* node) {
    if (!node) {
        return;
    }

    if (node->shift > 0) {
        for (int i = 0; i < XA_SLOTS; ++i) {
            if (node->slots[i]) {
                xa_destroy_recursive(node->slots[i]);
            }
        }
    }

    kmem_cache_free(xa_node_cache, node);
}

void xa_destory(xarray_t* xa) {
    acquire_write(&xa->lock);

    xa_destroy_recursive(xa->root);
    xa->root      = nullptr;
    xa->hint.node = nullptr;

    release_write(&xa->lock);
}

xa_result_t
xa_store(xarray_t* restrict xa, uint64_t index, xa_entry_t entry, xa_node_t** restrict spare) {
    if (unlikely(!xa || !spare)) {
        return XA_ERR_PARAM;
    }

    acquire_write(&xa->lock);

    uint64_t max_idx = UINT64_MAX;
    if (xa->root) {
        uint32_t total_bits = xa->root->shift + XA_BITS;

        if (total_bits < sizeof(uint64_t) * 8) {
            max_idx = (1ul << total_bits) - 1;
        }
    }

    while (!xa->root || index > max_idx) {
        if (!(*spare)) {
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
            new_root->bitmap |= 1ul;
            xa->root->offset = 0;
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

    while (node->shift > 0) {
        uint64_t offset = (index >> node->shift) & XA_MASK;
        prefetch(node->slots[offset]);

        if (node->slots[offset] == nullptr) {
            if (!entry) {
                release_write(&xa->lock);
                return XA_OK;
            }

            if (!(*spare)) {
                release_write(&xa->lock);
                return XA_NEED_NODE;
            }

            xa_node_t* child = *spare;
            *spare           = nullptr;

            xa_node_reset(child, node->shift - XA_BITS);
            child->offset = offset;

            node->slots[offset] = child;
            node->count++;

            __set_bit(offset, &node->bitmap);
        }

        node = node->slots[offset];
    }

    xa->hint.node  = node;
    xa->hint.index = index & ~XA_MASK;

insert_entry:
    uint64_t offset = index & XA_MASK;

    if (!entry) {
        if (!node->slots[offset]) {
            node->count++;
            __set_bit(offset, &node->bitmap);
        }

        node->slots[offset] = (xa_node_t*)entry;
    } else {
        if (node->slots[offset]) {
            node->slots[offset] = nullptr;
            node->count--;

            __clear_bit(offset, &node->bitmap);
        }
    }

    release_write(&xa->lock);
    return XA_OK;
}

xa_entry_t xa_load(xarray_t* restrict xa, uint64_t index) {
    if (!xa->root) {
        return nullptr;
    }

    acquire_read(&xa->lock);

    xa_node_t* node     = xa->root;
    uint32_t total_bits = node->shift + XA_BITS;

    if (total_bits < sizeof(uint64_t) * 8 && index >= (1ul << total_bits)) {
        release_read(&xa->lock);
        return nullptr;
    }

    while (node && node->shift > 0) {
        uint64_t offset = (index >> node->shift) & XA_MASK;

        if (!__test_bit(offset, &node->bitmap)) {
            release_read(&xa->lock);
            return nullptr;
        }

        node = node->slots[offset];
    }

    xa_entry_t val = nullptr;
    if (node && __test_bit(index & XA_MASK, &node->bitmap)) {
        val = (xa_entry_t)node->slots[index & XA_MASK];
    }

    release_read(&xa->lock);
    return val;
}

xa_entry_t xa_erase(xarray_t* restrict xa, uint64_t index) {
    if (!xa->root) {
        return nullptr;
    }

    acquire_write(&xa->lock);

    xa_node_t* path[XA_MAX_DEPTH];
    int path_idx    = 0;
    xa_node_t* node = xa->root;

    while (node->shift > 0) {
        path[path_idx++] = node;
        uint64_t offset  = (index >> node->shift) & XA_MASK;

        if (!__test_bit(offset, &node->bitmap)) {
            release_write(&xa->lock);
            return nullptr;
        }

        node = node->slots[offset];
    }

    uint64_t offset = index & XA_MASK;
    if (!__test_bit(offset, &node->bitmap)) {
        release_write(&xa->lock);
        return nullptr;
    }

    xa_entry_t val      = (xa_entry_t)node->slots[offset];
    node->slots[offset] = nullptr;
    node->count--;
    __clear_bit(offset, &node->bitmap);

    if (xa->hint.node == node) {
        xa->hint.node = nullptr;
    }

    while (node->count == 0) {
        if (node == xa->root) {
            kmem_cache_free(xa_node_cache, node);
            xa->root = nullptr;
            break;
        }

        kmem_cache_free(xa_node_cache, node);

        if (path_idx > 0) {
            path_idx--;
            node = path[path_idx];

            uint64_t p_offset = (index >> node->shift) & XA_MASK;

            node->slots[p_offset] = nullptr;
            node->count--;

            __clear_bit(p_offset, &node->bitmap);
        } else {
            break;
        }
    }

    if (xa->root && xa->root->shift > 0 && xa->root->count == 1 &&
        __test_bit(0, &xa->root->bitmap)) {
        xa_node_t* old_root = xa->root;
        xa->root            = old_root->slots[0];
        kmem_cache_free(xa_node_cache, old_root);
    }

    release_write(&xa->lock);
    return val;
}

xa_entry_t xa_find_after(xarray_t* restrict xa, uint64_t* restrict index) {
    if (unlikely(!xa->root || !xa)) {
        return nullptr;
    }

    acquire_read(&xa->lock);

    uint64_t curr   = *index;
    xa_node_t* node = xa->root;
    uint8_t shift   = node->shift;

    if ((shift + XA_BITS) < 64 && curr >= (1ul << (shift + XA_BITS))) {
        release_read(&xa->lock);
        return nullptr;
    }

restart:
    while (shift > 0) {
        uint64_t offset = (curr >> shift) & XA_MASK;

        uint64_t mask   = (~0ul) << offset;
        uint64_t active = node->bitmap & mask;

        if (!active) {
            uint64_t step      = 1ul << shift;
            uint64_t next_base = (curr & ~((step << XA_BITS) - 1)) + (step << XA_BITS);

            if (next_base <= curr) {
                release_read(&xa->lock);
                return nullptr;
            }

            curr = next_base;

            node  = xa->root;
            shift = node->shift;
            goto restart;
        }

        uint64_t next_offset = (uint64_t)ffs((long)active);

        if (next_offset > offset) {
            uint64_t step = 1ul << shift;
            curr          = (curr & ~(step - 1)) & ~(XA_MASK << shift);
            curr |= (next_offset << shift);
        }

        node = node->slots[next_offset];
        shift -= XA_BITS;
    }

    uint64_t offset = curr & XA_MASK;
    uint64_t mask   = (~0UL) << offset;
    uint64_t active = node->bitmap & mask;

    if (!active) {
        curr  = (curr & ~XA_MASK) + XA_SLOTS;
        node  = xa->root;
        shift = node->shift;
        goto restart;
    }

    uint64_t found_offset = (uint64_t)ffs((long)active);
    *index                = (curr & ~XA_MASK) | found_offset;
    xa_entry_t val        = (xa_entry_t)node->slots[found_offset];

    release_read(&xa->lock);
    return val;
}

int xa_store_range(xarray_t* xa, uint64_t start, uint64_t end, xa_entry_t entry) {
    uint64_t curr    = start;
    xa_node_t* spare = nullptr;

    while (curr <= end) {
        if (!spare) {
            spare = kmem_cache_alloc(xa_node_cache, 0);

            if (!spare) {
                return -ENOMEM;
            }
        }

        xa_result_t res = xa_store(xa, curr, entry, &spare);

        if (res == XA_NEED_NODE) {
            continue;
        }

        if (res != XA_OK) {
            if (spare) {
                kmem_cache_free(xa_node_cache, spare);
            }

            return -EINVAL;
        }

        curr++;
    }

    if (spare) {
        kmem_cache_free(xa_node_cache, spare);
    }

    return 0;
}

#endif