#ifndef KERNEL_CORE_CAPABILITY_H
#define KERNEL_CORE_CAPABILITY_H 1

#include <stdatomic.h>

#include "compiler.h"
#include "libs/slist.h"
#include "libs/spinlock.h"

#define CAP_TYPE_NONE         0
#define CAP_TYPE_THREAD       1
#define CAP_TYPE_PROCESS      2
#define CAP_TYPE_CHANNEL      3
#define CAP_TYPE_PORT_SET     4
#define CAP_TYPE_NOTIFICATION 5
#define CAP_TYPE_REPLY        6
#define CAP_TYPE_CNODE        7
#define CAP_TYPE_VSPACE       8
#define CAP_TYPE_WEAK         15

#define RIGHT_READ         (1 << 0)
#define RIGHT_WRITE        (1 << 1)
#define RIGHT_EXECUTE      (1 << 2)
#define RIGHT_SEND         (1 << 3)
#define RIGHT_RECEIVE      (1 << 4)
#define RIGHT_WAIT         (1 << 5)
#define RIGHT_GRANT        (1 << 6)
#define RIGHT_SIGNAL       (1 << 11)
#define RIGHT_CLOEXEC      (1 << 13)
#define RIGHT_CNODE_MUTATE (1 << 14)
#define RIGHT_WEAK         (1 << 15)
#define RIGHT_ALL          (0x7fff)

#define CSPACE_L1_SHIFT 22
#define CSPACE_L1_MASK  0x3ff
#define CSPACE_L2_SHIFT 12
#define CSPACE_L2_MASK  0x3ff
#define CSPACE_L3_MASK  0xfff

struct [[gnu::aligned(32)]] capability {
    atomic_uintptr_t object_ptr;
    uint32_t badge;
    uint16_t rights;
    uint8_t type;
    _Atomic(uint8_t) generation;

    struct slist_node free_node;
    qspinlock_t lock;
};

static_assert(sizeof(struct capability) == 32, "Capability struct must be exactly 32 bytes");

struct cnode {
    struct capability* slots;
    size_t capacity;
    uint64_t path_prefix;
    uint8_t index_shift;
    struct slist_head free_list;
    qspinlock_t lock;
};

struct untyped_node {
    uintptr_t base_paddr;
    size_t total_size;
    size_t free_offset;
    qspinlock_t lock;
};

static inline struct capability*
cap_lookup(struct cnode* node, uint64_t cap_id, uint32_t req_rights) {
    uint8_t expected_gen = (cap_id >> 56) & 0xff;

    uint16_t l1_idx = (cap_id >> CSPACE_L1_SHIFT) & CSPACE_L1_MASK;
    uint16_t l2_idx = (cap_id >> CSPACE_L2_SHIFT) & CSPACE_L2_MASK;
    uint16_t l3_idx = cap_id & CSPACE_L3_MASK;

    if (unlikely(l1_idx >= node->capacity)) return nullptr;

    struct capability* cap = &node->slots[l1_idx];
    if (cap->type == CAP_TYPE_CNODE) {
        struct cnode* l2 =
            (struct cnode*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

        if (unlikely(!l2 || l2_idx >= l2->capacity)) {
            return nullptr;
        }

        cap = &l2->slots[l2_idx];

        if (cap->type == CAP_TYPE_CNODE) {
            struct cnode* l3 =
                (struct cnode*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

            if (unlikely(!l3 || l3_idx >= l3->capacity)) {
                return nullptr;
            }

            cap = &l3->slots[l3_idx];
        }
    }

    // ABA & Rights Check
    uint8_t current_gen = atomic_load_explicit(&cap->generation, memory_order_acquire);
    if (unlikely(current_gen != expected_gen || (cap->rights & req_rights) != req_rights))
        return nullptr;

    // Resolve Ephemeral (Weak) Capabilities
    if (unlikely(cap->type == CAP_TYPE_WEAK)) {
        struct capability* target =
            (struct capability*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

        uint8_t target_gen = atomic_load_explicit(&target->generation, memory_order_acquire);

        // Weak cap's badge stores the generation the target should have
        if (target_gen != cap->badge || (target->rights & req_rights) != req_rights) return nullptr;
        return target;
    }

    return cap;
}

static inline void*
cap_resolve(struct cnode* root, uint64_t cap_id, uint16_t req_rights, uint8_t req_type) {
    struct capability* cap = cap_lookup(root, cap_id, req_rights);
    if (unlikely(!cap)) {
        return nullptr;
    }

    void* obj = (void*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

    uint8_t current_gen  = atomic_load_explicit(&cap->generation, memory_order_acquire);
    uint8_t expected_gen = (cap_id >> 56) & 0xff;

    if (unlikely(current_gen != expected_gen || cap->type != req_type || !obj)) {
        return nullptr;
    }

    return obj;
}

void cnode_init(
    struct cnode* node,
    struct capability* memory,
    size_t count,
    uint64_t prefix,
    uint8_t shift
);
struct cnode* create_cspace(void);
void destroy_cspace(struct cnode* root);
struct cnode* cnode_clone(struct cnode* parent);

struct capability* cap_alloc(struct cnode* node, uint64_t* out_cap_id);
int cap_delegate(struct capability* src, struct capability* child, uint16_t reduced_rights);
int cap_close(struct cnode* root, uint64_t cap_id);
int cap_move(
    struct cnode* src_root,
    uint64_t src_cap_id,
    struct cnode* dest_root,
    uint64_t* new_cap_id
);

int sys_cap_delegate(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* new_cap_id
);
int sys_cap_close(struct cnode* root_cnode, uint64_t target_id);
int sys_cap_copy(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint64_t* new_cap_id
);
int sys_cap_mint(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t new_rights,
    uint32_t badge_val,
    uint64_t* new_cap_id
);
int sys_cap_alias(
    struct cnode* root_cnode,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* new_cap_id
);

#endif