#include "core/capability.h"

#include <stdatomic.h>
#include <stdint.h>

#include "arch.h"
#include "compiler.h"
#include "core/errors.h"
#include "libs/dlist.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "memory/memory.h"
#include "sched/ipc.h"
#include "sched/process.h"
#include "sched/syscalls.h"

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

    dlist_init(&cap->children);
    dlist_init(&cap->sibling);
    cap->parent = nullptr;

    return cap;
}

int cap_delegate(struct capability* parent, struct capability* child, uint16_t reduced_rights) {
    if (unlikely(!parent || !child)) {
        return ERR_INVALID_CAP;
    }

    // Ephemeral Capability
    if (reduced_rights & RIGHT_WEAK) {
        acquire_qspinlock(&child->lock);

        // Point child to parent cap slot, not the object memory
        atomic_store_explicit(&child->object_ptr, (uintptr_t)parent, memory_order_release);
        child->type = CAP_TYPE_WEAK;

        // Badge stores the target's current generation for ABA check
        child->badge  = atomic_load_explicit(&parent->generation, memory_order_relaxed);
        child->rights = parent->rights & ~RIGHT_WEAK;
        child->parent = nullptr;

        release_qspinlock(&child->lock);
        return ERR_OK;
    }

    size_t irq_state = acquire_qinterrupt_lock(&parent->lock);
    acquire_qspinlock(&child->lock);

    atomic_store_explicit(
        &child->object_ptr,
        atomic_load_explicit(&parent->object_ptr, memory_order_relaxed),
        memory_order_release
    );

    child->type   = parent->type;
    child->rights = parent->rights & reduced_rights;
    child->badge  = parent->badge;
    child->parent = parent;

    dlist_add_tail(&child->sibling, &parent->children);

    release_qspinlock(&child->lock);
    release_qinterrupt_lock(&parent->lock, irq_state);

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

#define REVOKE_YIELD_THRESHOLD 32

static bool cap_revoke_internal(
    struct cnode* pool,
    struct capability* target,
    int* work_count,
    size_t* irq_state
) {
    struct capability *child, *temp;

    dlist_for_each_entry_safe(child, temp, &target->children, sibling) {
        if (*work_count > REVOKE_YIELD_THRESHOLD) {
            release_qinterrupt_lock(&target->lock, *irq_state);
            arch_pause();

            if (irq_state) {
                *irq_state = acquire_qinterrupt_lock(&target->lock);
            }

            if (work_count) {
                *work_count = 0;
            }

            return false;
        }

        acquire_qspinlock(&child->lock);

        if (!dlist_empty(&child->children)) {
            release_qspinlock(&child->lock);
            while (!cap_revoke_internal(pool, child, work_count, irq_state));
            acquire_qspinlock(&child->lock);
        }

        dlist_del_init(&child->sibling);
        child->parent = nullptr;

        atomic_fetch_add_explicit(&child->generation, 1, memory_order_release);
        atomic_store_explicit(&child->object_ptr, 0, memory_order_release);
        child->rights = 0;
        child->badge  = 0;
        child->type   = CAP_TYPE_NONE;

        acquire_qspinlock(&pool->lock);
        slist_push(&child->free_node, &pool->free_list);
        release_qspinlock(&pool->lock);

        if (work_count) {
            (*work_count)++;
        }

        release_qspinlock(&child->lock);
    }

    return true;
}

void cap_revoke(struct cnode* pool, struct capability* target) {
    if (unlikely(!target)) {
        return;
    }

    int work_count   = 0;
    size_t irq_state = acquire_qinterrupt_lock(&target->lock);
    while (!cap_revoke_internal(pool, target, &work_count, &irq_state));
    release_qinterrupt_lock(&target->lock, irq_state);
}

static inline size_t get_object_size(uint16_t type) {
    switch (type) {
        case CAP_TYPE_CHANNEL:
            return sizeof(struct ipc_channel);
        case CAP_TYPE_PORT_SET:
            return sizeof(struct ipc_port_set);
        case CAP_TYPE_THREAD:
            return sizeof(thread_t);
        case CAP_TYPE_FRAME:
        case CAP_TYPE_VSPACE:
            return PAGE_SIZE_SMALL;
        case CAP_TYPE_SCHED_CONTEXT:
            return sizeof(sched_entity_t);
        default:
            return 0;
    }
}

int cap_retype(
    struct capability* untyped_cap,
    uint16_t target_type,
    size_t count,
    struct cnode* dest_cnode,
    uint64_t* out_cap_ids
) {
    if (unlikely(!untyped_cap || untyped_cap->type != CAP_TYPE_UNTYPED)) {
        return ERR_INVALID_CAP;
    }

    if (unlikely(!(untyped_cap->rights & RIGHT_WRITE))) {
        return ERR_DENIED;
    }

    size_t obj_size = get_object_size(target_type);
    if (unlikely(obj_size == 0)) {
        return ERR_INVALID_CAP;
    }

    struct untyped_node* mem_node =
        (struct untyped_node*)atomic_load_explicit(&untyped_cap->object_ptr, memory_order_acquire);

    if (unlikely(!mem_node)) {
        return ERR_INVALID_CAP;
    }

    size_t total_alloc_size = obj_size * count;
    size_t irq_state        = acquire_qinterrupt_lock(&mem_node->lock);

    if (mem_node->free_offset + total_alloc_size > mem_node->total_size) {
        release_qinterrupt_lock(&mem_node->lock, irq_state);
        return ERR_NO_MEM;
    }

    uintptr_t current_paddr = mem_node->base_paddr + mem_node->free_offset;
    mem_node->free_offset += total_alloc_size;
    release_qinterrupt_lock(&mem_node->lock, irq_state);

    irq_state = acquire_qinterrupt_lock(&untyped_cap->lock);

    for (size_t i = 0; i < count; i++) {
        uint64_t new_cap_id;
        struct capability* new_cap = cap_alloc(dest_cnode, &new_cap_id);

        if (unlikely(!new_cap)) {
            release_qinterrupt_lock(&untyped_cap->lock, irq_state);
            return ERR_NO_MEM;
        }

        if (target_type == CAP_TYPE_CNODE) {
            struct cnode* new_sub_cnode = (struct cnode*)current_paddr;
            struct capability* slot_mem =
                (struct capability*)(current_paddr + sizeof(struct cnode));

            size_t requested_slots = (obj_size - sizeof(struct cnode)) / sizeof(struct capability);
            uint64_t new_prefix    = new_cap_id & 0x00fffffffffffffful;

            uint8_t new_shift = 0;
            if (dest_cnode->index_shift == CSPACE_L1_SHIFT) {
                new_shift = CSPACE_L2_SHIFT;
            } else if (dest_cnode->index_shift == CSPACE_L2_SHIFT) {
                new_shift = 0;
            }

            cnode_init(new_sub_cnode, slot_mem, requested_slots, new_prefix, new_shift);
        }

        acquire_qspinlock(&new_cap->lock);
        atomic_store_explicit(&new_cap->object_ptr, current_paddr, memory_order_release);
        new_cap->type   = target_type;
        new_cap->rights = RIGHT_ALL;
        new_cap->badge  = 0;
        new_cap->parent = untyped_cap;

        dlist_add_tail(&new_cap->sibling, &untyped_cap->children);
        release_qspinlock(&new_cap->lock);

        out_cap_ids[i] = new_cap_id;
        current_paddr += obj_size;
    }

    release_qinterrupt_lock(&untyped_cap->lock, irq_state);
    return ERR_OK;
}

static void sys_cap_revoke_untyped(struct cnode* pool, struct capability* untyped_cap) {
    cap_revoke(pool, untyped_cap);

    struct untyped_node* mem_node = (struct untyped_node*)(uintptr_t)
        atomic_load_explicit(&untyped_cap->object_ptr, memory_order_acquire);

    if (mem_node) {
        size_t irq_state      = acquire_qinterrupt_lock(&mem_node->lock);
        mem_node->free_offset = 0;
        release_qinterrupt_lock(&mem_node->lock, irq_state);
    }
}

int sys_cap_retype(
    struct cnode* root_cnode,
    uint64_t untyped_id,
    uint16_t target_type,
    size_t count,
    uint64_t dest_cnode_id,
    uint64_t* out_array
) {
    if (count == 0 || count > 1024) {
        return ERR_NO_MEM;
    }

    struct capability* untyped_cap = cap_lookup(root_cnode, untyped_id, RIGHT_WRITE);
    if (!untyped_cap) {
        return ERR_INVALID_CAP;
    }

    struct capability* dest_cnode_cap = cap_lookup(root_cnode, dest_cnode_id, RIGHT_CNODE_MUTATE);
    if (!dest_cnode_cap || dest_cnode_cap->type != CAP_TYPE_CNODE) {
        return ERR_INVALID_CAP;
    }

    struct cnode* dest_cnode =
        (struct cnode*)atomic_load_explicit(&dest_cnode_cap->object_ptr, memory_order_acquire);

    uint64_t new_ids[1024];

    int status = cap_retype(untyped_cap, target_type, count, dest_cnode, new_ids);
    if (status == ERR_OK && out_array) {
        if (copy_to_user(out_array, new_ids, count * sizeof(uint64_t)) != 0) {
            uint64_t mask = (dest_cnode->index_shift == 0) ? CSPACE_L3_MASK : CSPACE_L1_MASK;

            for (size_t i = 0; i < count; ++i) {
                uint16_t slot_idx               = (new_ids[i] >> dest_cnode->index_shift) & mask;
                struct capability* orphaned_cap = &dest_cnode->slots[slot_idx];

                cap_revoke(dest_cnode, orphaned_cap);
            }

            return ERR_FAULT;
        }
    }

    return status;
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

    uint64_t new_cap_id_;
    struct capability* new_cap = cap_alloc(dest_cnode, &new_cap_id_);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, reduced_rights);

    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = new_cap_id_;
        }
    }

    return status;
}

int sys_cap_revoke(struct cnode* root_cnode, uint64_t target_id) {
    struct capability* target_cap = cap_lookup(root_cnode, target_id, RIGHT_READ);
    if (!target_cap) {
        return ERR_INVALID_CAP;
    }

    if (target_cap->type == CAP_TYPE_UNTYPED) {
        sys_cap_revoke_untyped(root_cnode, target_cap);
    } else {
        cap_revoke(root_cnode, target_cap);
    }

    return ERR_OK;
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

    uint64_t new_cap_id_;
    struct capability* new_cap = cap_alloc(dest_cnode, &new_cap_id_);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, RIGHT_ALL);
    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = new_cap_id_;
        }
    } else {
        cap_free_slot(dest_cnode, new_cap);
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

    uint64_t new_cap_id_;
    struct capability* new_cap = cap_alloc(dest_cnode, &new_cap_id_);
    if (!new_cap) {
        return ERR_NO_MEM;
    }

    int status = cap_delegate(src_cap, new_cap, new_rights);
    if (status == ERR_OK) {
        if (new_cap_id) {
            *new_cap_id = new_cap_id_;
        }

        new_cap->badge = badge_val;
    } else {
        cap_free_slot(dest_cnode, new_cap);
    }

    return status;
}