#include "core/capability.h"

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "core/errors.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "sched/ipc.h"

static void cap_object_ref(uint8_t type, void* obj) {
    if (!obj) {
        return;
    }

    switch (type) {
        case CAP_TYPE_CHANNEL:
            kref_get(&((struct ipc_channel*)obj)->refcount);
            break;
        case CAP_TYPE_PORT_SET:
            kref_get(&((struct ipc_port_set*)obj)->refcount);
            break;
        case CAP_TYPE_NOTIFICATION:
            kref_get(&((struct ipc_notification*)obj)->refcount);
            break;
        case CAP_TYPE_REPLY:
            // TODO: kref_get to thread struct
        default:
            break;
    }
}

static void cap_object_unref(uint8_t type, void* obj) {
    if (!obj) {
        return;
    }

    switch (type) {
        case CAP_TYPE_CHANNEL:
            kref_put(&((struct ipc_channel*)obj)->refcount, ipc_channel_release);
            break;
        case CAP_TYPE_PORT_SET:
            kref_put(&((struct ipc_port_set*)obj)->refcount, ipc_port_set_release);
            break;
        case CAP_TYPE_NOTIFICATION:
            kref_put(&((struct ipc_notification*)obj)->refcount, ipc_notification_release);
            break;
        case CAP_TYPE_REPLY:
            // TODO: kref_put to thread struct
        default:
            break;
    }
}

void cnode_init(
    struct cnode* node,
    struct capability* memory,
    size_t count,
    uint64_t prefix,
    uint8_t index
) {
    node->slots       = memory;
    node->capacity    = count;
    node->path_prefix = prefix;
    node->index_shift = index;
    slist_init(&node->free_list);
    create_qspinlock(&node->lock);

    for (size_t i = 0; i < count; ++i) {
        struct capability* cap = &node->slots[i];
        atomic_init(&cap->object_ptr, 0);
        atomic_init(&cap->generation, 1);

        cap->badge  = 0;
        cap->rights = 0;
        cap->type   = CAP_TYPE_NONE;

        create_qspinlock(&cap->lock);
        slist_push(&cap->free_node, &node->free_list);
    }
}

struct capability* cap_alloc(struct cnode* node, uint64_t* out_cap_id) {
    size_t irq_state             = acquire_qinterrupt_lock(&node->lock);
    struct slist_node* free_node = slist_pop(&node->free_list);
    release_qinterrupt_lock(&node->lock, irq_state);

    if (unlikely(!free_node)) {
        return nullptr;
    }

    struct capability* cap = slist_entry(free_node, struct capability, free_node);
    uint64_t index         = (uint64_t)(cap - node->slots);
    uint64_t gen           = atomic_load_explicit(&cap->generation, memory_order_relaxed);

    if (out_cap_id) {
        // Compose the unforgeable 64-bit ID: Generation | CNode Path | (Local Index << Level Shift)
        *out_cap_id = (gen << 56) | node->path_prefix | (index << node->index_shift);
    }

    return cap;
}

int cap_delegate(struct capability* src, struct capability* child, uint16_t reduced_rights) {
    if (unlikely(!src || !child)) {
        return ERR_INVALID_CAP;
    }

    void* obj = (void*)atomic_load_explicit(&src->object_ptr, memory_order_relaxed);

    // Ephemeral Capability
    if (reduced_rights & RIGHT_WEAK) {
        acquire_qspinlock(&child->lock);

        // Point child to parent cap slot, not the object memory
        atomic_store_explicit(&child->object_ptr, (uintptr_t)src, memory_order_release);
        child->type = CAP_TYPE_WEAK;

        // Badge stores the target's current generation for ABA check
        child->badge  = atomic_load_explicit(&src->generation, memory_order_relaxed);
        child->rights = src->rights & ~RIGHT_WEAK;

        release_qspinlock(&child->lock);
        return ERR_OK;
    }

    cap_object_ref(src->type, obj);

    acquire_qspinlock(&child->lock);
    atomic_store_explicit(&child->object_ptr, (uintptr_t)obj, memory_order_release);
    child->type   = src->type;
    child->rights = src->rights & reduced_rights;
    child->badge  = src->badge;
    release_qspinlock(&child->lock);

    return ERR_OK;
}

static inline void cap_free_slot(struct cnode* pool, struct capability* cap) {
    atomic_fetch_add_explicit(&cap->generation, 1, memory_order_release);
    atomic_store_explicit(&cap->object_ptr, 0, memory_order_release);

    cap->rights = 0;
    cap->badge  = 0;
    cap->type   = CAP_TYPE_NONE;

    size_t irq_state = acquire_qinterrupt_lock(&pool->lock);
    slist_push(&cap->free_node, &pool->free_list);
    release_qinterrupt_lock(&pool->lock, irq_state);
}

int cap_close(struct cnode* root, uint64_t cap_id) {
    uint8_t expected_gen = (cap_id >> 56) & 0xff;
    uint16_t l1_idx      = (cap_id >> CSPACE_L1_SHIFT) & CSPACE_L1_MASK;
    uint16_t l2_idx      = (cap_id >> CSPACE_L2_SHIFT) & CSPACE_L2_MASK;
    uint16_t l3_idx      = cap_id & CSPACE_L3_MASK;

    struct cnode* target_cnode = root;
    if (unlikely(l1_idx >= root->capacity)) {
        return ERR_INVALID_CAP;
    }

    struct capability* target_cap = &root->slots[l1_idx];

    if (target_cap->type == CAP_TYPE_CNODE) {
        struct cnode* l2 =
            (struct cnode*)atomic_load_explicit(&target_cap->object_ptr, memory_order_acquire);
        if (unlikely(!l2 || l2_idx >= l2->capacity)) {
            return ERR_INVALID_CAP;
        }

        target_cnode = l2;
        target_cap   = &l2->slots[l2_idx];

        if (target_cap->type == CAP_TYPE_CNODE) {
            struct cnode* l3 =
                (struct cnode*)atomic_load_explicit(&target_cap->object_ptr, memory_order_acquire);
            if (unlikely(!l3 || l3_idx >= l3->capacity)) {
                return ERR_INVALID_CAP;
            }

            target_cnode = l3;
            target_cap   = &l3->slots[l3_idx];
        }
    }

    uint8_t current_gen = atomic_load_explicit(&target_cap->generation, memory_order_acquire);
    if (unlikely(current_gen != expected_gen)) {
        return ERR_INVALID_CAP;
    }

    acquire_qspinlock(&target_cap->lock);

    void* obj    = (void*)atomic_load_explicit(&target_cap->object_ptr, memory_order_acquire);
    uint8_t type = target_cap->type;

    atomic_fetch_add_explicit(&target_cap->generation, 1, memory_order_release);
    atomic_store_explicit(&target_cap->object_ptr, 0, memory_order_release);
    target_cap->rights = 0;
    target_cap->badge  = 0;
    target_cap->type   = CAP_TYPE_NONE;

    release_qspinlock(&target_cap->lock);

    size_t irq_state = acquire_qinterrupt_lock(&target_cnode->lock);
    slist_push(&target_cap->free_node, &target_cnode->free_list);
    release_qinterrupt_lock(&target_cnode->lock, irq_state);

    if (type != CAP_TYPE_WEAK && type != CAP_TYPE_CNODE) {
        cap_object_unref(type, obj);
    }

    return ERR_OK;
}

int cap_move(
    struct cnode* src_root,
    uint64_t src_cap_id,
    struct cnode* dest_root,
    uint64_t* new_cap_id
) {
    uint8_t expected_gen = (src_cap_id >> 56) & 0xFF;
    uint16_t l1_idx      = (src_cap_id >> CSPACE_L1_SHIFT) & CSPACE_L1_MASK;
    uint16_t l2_idx      = (src_cap_id >> CSPACE_L2_SHIFT) & CSPACE_L2_MASK;
    uint16_t l3_idx      = src_cap_id & CSPACE_L3_MASK;

    struct cnode* src_cnode = src_root;

    if (unlikely(l1_idx >= src_root->capacity)) {
        return ERR_INVALID_CAP;
    }

    struct capability* src_cap = &src_root->slots[l1_idx];
    if (src_cap->type == CAP_TYPE_CNODE) {
        struct cnode* l2 =
            (struct cnode*)atomic_load_explicit(&src_cap->object_ptr, memory_order_acquire);

        if (unlikely(!l2 || l2_idx >= l2->capacity)) {
            return ERR_INVALID_CAP;
        }

        src_cnode = l2;
        src_cap   = &l2->slots[l2_idx];

        if (src_cap->type == CAP_TYPE_CNODE) {
            struct cnode* l3 =
                (struct cnode*)atomic_load_explicit(&src_cap->object_ptr, memory_order_acquire);

            if (unlikely(!l3 || l3_idx >= l3->capacity)) {
                return ERR_INVALID_CAP;
            }

            src_cnode = l3;
            src_cap   = &l3->slots[l3_idx];
        }
    }

    uint8_t current_gen = atomic_load_explicit(&src_cap->generation, memory_order_acquire);
    if (unlikely(current_gen != expected_gen || (src_cap->rights & RIGHT_WRITE) != RIGHT_WRITE)) {
        return ERR_INVALID_CAP;
    }

    uint64_t local_new_id;
    struct capability* dest_cap = cap_alloc(dest_root, &local_new_id);
    if (!dest_cap) {
        return ERR_NO_MEM;
    }

    acquire_qspinlock(&src_cap->lock);
    acquire_qspinlock(&dest_cap->lock);

    atomic_store_explicit(
        &dest_cap->object_ptr,
        atomic_load_explicit(&src_cap->object_ptr, memory_order_relaxed),
        memory_order_release
    );
    dest_cap->type   = src_cap->type;
    dest_cap->rights = src_cap->rights;
    dest_cap->badge  = src_cap->badge;

    atomic_fetch_add_explicit(&src_cap->generation, 1, memory_order_release);
    atomic_store_explicit(&src_cap->object_ptr, 0, memory_order_release);
    src_cap->rights = 0;
    src_cap->badge  = 0;
    src_cap->type   = CAP_TYPE_NONE;

    release_qspinlock(&dest_cap->lock);
    release_qspinlock(&src_cap->lock);

    size_t irq_state = acquire_qinterrupt_lock(&src_cnode->lock);
    slist_push(&src_cap->free_node, &src_cnode->free_list);
    release_qinterrupt_lock(&src_cnode->lock, irq_state);

    if (new_cap_id) {
        *new_cap_id = local_new_id;
    }

    return ERR_OK;
}

int sys_cap_delegate(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* new_cap_id
) {
    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) {
        return ERR_INVALID_CAP;
    }

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) {
        return ERR_INVALID_CAP;
    }

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, reduced_rights);

    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = local_new_id;
        }
    } else {
        cap_close(root_cnode, local_new_id);
    }

    return status;
}

int sys_cap_close(struct cnode* root_cnode, uint64_t target_id) {
    return cap_close(root_cnode, target_id);
}

int sys_cap_copy(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint64_t* new_cap_id
) {
    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) {
        return ERR_INVALID_CAP;
    }

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) {
        return ERR_INVALID_CAP;
    }

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, RIGHT_ALL);
    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = local_new_id;
        }
    } else {
        cap_close(dest_cnode, local_new_id);
    }

    return status;
}

int sys_cap_mint(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t new_rights,
    uint32_t badge_val,
    uint64_t* new_cap_id
) {
    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (!src_cap) {
        return ERR_INVALID_CAP;
    }

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) {
        return ERR_INVALID_CAP;
    }

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(dest_cnode, &local_new_id);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, new_rights);
    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = local_new_id;
        }

        new_cap->badge = badge_val;
    } else {
        cap_close(dest_cnode, local_new_id);
    }

    return status;
}

int sys_cap_alias(
    struct cnode* root_cnode,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* new_cap_id
) {
    struct capability* src_cap = cap_lookup(root_cnode, src_cap_id, RIGHT_GRANT);
    if (unlikely(!src_cap)) {
        return ERR_INVALID_CAP;
    }

    uint64_t local_new_id;
    struct capability* new_cap = cap_alloc(root_cnode, &local_new_id);
    if (unlikely(!new_cap)) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, reduced_rights);

    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = local_new_id;
        }
    } else {
        cap_close(root_cnode, local_new_id);
    }

    return status;
}