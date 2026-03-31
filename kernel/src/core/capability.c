#include "core/capability.h"

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "core/errors.h"
#include "libs/kobject.h"
#include "libs/slist.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/vma.h"
#include "sched/ipc.h"
#include "sched/process.h"

#define MAX_CLONE_NODES 64

struct clone_ctx {
    struct cnode* old_nodes[MAX_CLONE_NODES];
    struct cnode* new_nodes[MAX_CLONE_NODES];
    size_t count;

    struct cnode* work_queue[MAX_CLONE_NODES];
    size_t head;
    size_t tail;
};

static kmem_cache_t* cnode_cache = nullptr;

static struct cnode* alloc_cnode_skeleton(struct cnode* template_cnode) {
    struct cnode* new_node = (struct cnode*)kmem_cache_alloc(cnode_cache);
    if (!new_node) return nullptr;

    struct capability* slots =
        (struct capability*)kmalloc(template_cnode->capacity * sizeof(struct capability));
    if (!slots) {
        kmem_cache_free(cnode_cache, new_node);
        return nullptr;
    }

    new_node->slots       = slots;
    new_node->capacity    = template_cnode->capacity;
    new_node->path_prefix = template_cnode->path_prefix;
    new_node->index_shift = template_cnode->index_shift;
    slist_init(&new_node->free_list);
    create_qspinlock(&new_node->lock);

    return new_node;
}

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
        case CAP_TYPE_THREAD:
            kref_get(&((struct thread*)obj)->kobj);
            break;
        case CAP_TYPE_PROCESS:
            kref_get(&((struct process*)obj)->kobj);
            break;
        case CAP_TYPE_VSPACE:
            kref_get(&((struct vm_space*)obj)->refcount);
            break;
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
        case CAP_TYPE_THREAD:
            kref_put(&((struct thread*)obj)->kobj, thread_release);
            break;
        case CAP_TYPE_PROCESS:
            kref_put(&((struct process*)obj)->kobj, process_release);
            break;
        case CAP_TYPE_VSPACE:
            kref_put(&((struct vm_space*)obj)->refcount, vmm_space_release);
            break;
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

struct cnode* create_cspace(void) {
    const size_t l1_capacity = 1024;
    size_t slots_size        = l1_capacity * sizeof(struct capability);

    if (!cnode_cache) {
        cnode_cache = kmem_cache_create(
            "cnode_cache",
            sizeof(struct cnode),
            _Alignof(struct cnode),
            0,
            nullptr
        );
    }

    struct cnode* root_cnode = (struct cnode*)kmem_cache_alloc(cnode_cache);
    if (unlikely(!root_cnode)) {
        return nullptr;
    }

    struct capability* slots_mem = (struct capability*)kmalloc(slots_size);
    if (unlikely(!slots_mem)) {
        kfree(root_cnode);
        return nullptr;
    }

    cnode_init(root_cnode, slots_mem, l1_capacity, 0, CSPACE_L1_SHIFT);

    // Burn Slot 0 (the NULL Capability)
    uint64_t burned_id;
    cap_alloc(root_cnode, &burned_id);

    uint64_t self_cap_id;
    struct capability* self_cap = cap_alloc(root_cnode, &self_cap_id);

    acquire_qspinlock(&self_cap->lock);
    atomic_store_explicit(&self_cap->object_ptr, (uintptr_t)root_cnode, memory_order_release);
    self_cap->type   = CAP_TYPE_CNODE;
    self_cap->rights = RIGHT_ALL;
    self_cap->badge  = 0;
    release_qspinlock(&self_cap->lock);

    return root_cnode;
}

void destroy_cspace(struct cnode* root) {
    if (!root) return;

    for (size_t i = 1; i < root->capacity; ++i) {
        struct capability* cap = &root->slots[i];

        uint8_t type = cap->type;
        if (type != CAP_TYPE_NONE && type != CAP_TYPE_WEAK) {
            uint8_t gen     = atomic_load_explicit(&cap->generation, memory_order_relaxed);
            uint64_t cap_id = ((uint64_t)gen << 56) | root->path_prefix | (i << root->index_shift);

            cap_close(root, cap_id);
        }
    }

    kfree(root->slots);
    kmem_cache_free(cnode_cache, root);
}

struct cnode* cnode_clone(struct cnode* parent) {
    if (unlikely(!parent)) return nullptr;

    struct clone_ctx* ctx = (struct clone_ctx*)kmalloc(sizeof(struct clone_ctx));
    if (!ctx) return nullptr;
    ctx->count = 0;
    ctx->head  = 0;
    ctx->tail  = 0;

    // Bootstrap the root node
    struct cnode* new_root = alloc_cnode_skeleton(parent);
    if (!new_root) {
        kfree(ctx);
        return nullptr;
    }

    // Add root to mapping table and work queue
    ctx->old_nodes[ctx->count] = parent;
    ctx->new_nodes[ctx->count] = new_root;
    ctx->count++;
    ctx->work_queue[ctx->tail++] = parent;

    // Process as Breadth-First Search queue
    while (ctx->head < ctx->tail) {
        struct cnode* old_node = ctx->work_queue[ctx->head++];

        struct cnode* new_node = nullptr;
        for (size_t i = 0; i < ctx->count; i++) {
            if (ctx->old_nodes[i] == old_node) {
                new_node = ctx->new_nodes[i];
                break;
            }
        }

        // Iterate exactly one level per slot
        for (size_t i = 0; i < old_node->capacity; i++) {
            struct capability* p_cap = &old_node->slots[i];
            struct capability* c_cap = &new_node->slots[i];

            atomic_init(&c_cap->object_ptr, 0);
            atomic_init(&c_cap->generation, 1);
            c_cap->badge  = 0;
            c_cap->rights = 0;
            c_cap->type   = CAP_TYPE_NONE;
            create_qspinlock(&c_cap->lock);

            // Snapshot the parent slot's state
            acquire_qspinlock(&p_cap->lock);
            uint8_t type    = p_cap->type;
            uint16_t rights = p_cap->rights;
            uint32_t badge  = p_cap->badge;
            void* obj       = (void*)atomic_load_explicit(&p_cap->object_ptr, memory_order_relaxed);
            release_qspinlock(&p_cap->lock);

            if (type == CAP_TYPE_NONE) {
                slist_push(&c_cap->free_node, &new_node->free_list);
                continue;
            }

            if (type == CAP_TYPE_CNODE) {
                struct cnode* old_child = (struct cnode*)obj;
                struct cnode* new_child = nullptr;

                // Have we seen this child before?
                for (size_t j = 0; j < ctx->count; j++) {
                    if (ctx->old_nodes[j] == old_child) {
                        new_child = ctx->new_nodes[j];
                        break;
                    }
                }

                // If not, we create it and queue it for future processing
                if (!new_child) {
                    if (ctx->count >= MAX_CLONE_NODES) {
                        // Graph is too large. Skip cloning this sub-branch to protect the kernel.
                        slist_push(&c_cap->free_node, &new_node->free_list);
                        continue;
                    }

                    new_child = alloc_cnode_skeleton(old_child);
                    if (!new_child) {
                        // Clean up the entire partially contructed CSpace and abort.
                        destroy_cspace(new_root);
                        kfree(ctx);
                        return nullptr;
                    }

                    // Map and enqueue it
                    ctx->old_nodes[ctx->count] = old_child;
                    ctx->new_nodes[ctx->count] = new_child;
                    ctx->count++;

                    ctx->work_queue[ctx->tail++] = old_child;
                }

                // Link the parent slot to the new child
                atomic_store_explicit(
                    &c_cap->object_ptr,
                    (uintptr_t)new_child,
                    memory_order_relaxed
                );
            } else if (type == CAP_TYPE_WEAK) {
                atomic_store_explicit(&c_cap->object_ptr, (uintptr_t)obj, memory_order_relaxed);
            } else {
                cap_object_ref(type, obj);
                atomic_store_explicit(&c_cap->object_ptr, (uintptr_t)obj, memory_order_relaxed);
            }

            c_cap->type   = type;
            c_cap->rights = rights;
            c_cap->badge  = badge;
        }
    }

    kfree(ctx);
    return new_root;
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