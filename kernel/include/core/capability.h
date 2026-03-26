#ifndef KERNEL_CORE_CAPABILITY_H
#define KERNEL_CORE_CAPABILITY_H 1

#include "compiler.h"
#include "libs/dlist.h"
#include "libs/slist.h"
#include "libs/spinlock.h"

#define CAP_TYPE_NONE          0
#define CAP_TYPE_UNTYPED       1
#define CAP_TYPE_FRAME         2
#define CAP_TYPE_VSPACE        3
#define CAP_TYPE_THREAD        4
#define CAP_TYPE_SCHED_CONTEXT 5
#define CAP_TYPE_CHANNEL       6
#define CAP_TYPE_REPLY         7
#define CAP_TYPE_PORT_SET      8
#define CAP_TYPE_CNODE         9
#define CAP_TYPE_IRQ_CONTROL   10
#define CAP_TYPE_IRQ_HANDLER   11
#define CAP_TYPE_IO_PORT       12
#define CAP_TYPE_WEAK          15

#define RIGHT_READ              (1 << 0)
#define RIGHT_WRITE             (1 << 1)
#define RIGHT_EXECUTE           (1 << 2)
#define RIGHT_SEND              (1 << 3)
#define RIGHT_RECEIVE           (1 << 4)
#define RIGHT_GRANT             (1 << 5)
#define RIGHT_GRANT_REPLY       (1 << 6)
#define RIGHT_THREAD_SUSPEND    (1 << 7)
#define RIGHT_THREAD_RESUME     (1 << 8)
#define RIGHT_THREAD_READ_REGS  (1 << 9)
#define RIGHT_THREAD_WRITE_REGS (1 << 10)
#define RIGHT_SIGNAL            (1 << 11)
#define RIGHT_WAIT              (1 << 12)
#define RIGHT_CNODE_MUTATE      (1 << 13)
#define RIGHT_CNODE_READ        (1 << 14)
#define RIGHT_WEAK              (1 << 15)
#define RIGHT_ALL               (0x7fff)

struct [[gnu::aligned(64)]] capability {
    atomic_uintptr_t object_ptr;
    uint32_t badge;
    uint16_t rights;
    uint8_t type;
    _Atomic(uint8_t) generation;

    union {
        struct {
            struct capability* parent;
            struct dlist_head children;
            struct dlist_head sibling;
        };

        struct slist_node free_node;
    };

    qspinlock_t lock;
};

static_assert(sizeof(struct capability) == 64, "Capability struct must be exactly 64 bytes");

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

#define CSPACE_L1_SHIFT 22
#define CSPACE_L1_MASK  0x3ff
#define CSPACE_L2_SHIFT 12
#define CSPACE_L2_MASK  0x3ff
#define CSPACE_L3_MASK  0xfff

static inline struct capability*
cap_lookup(struct cnode* node, uint64_t cap_id, uint32_t req_rights) {
    uint8_t expected_gen = (cap_id >> 56) & 0xff;

    uint16_t l1_idx = (cap_id >> CSPACE_L1_SHIFT) & CSPACE_L1_MASK;
    uint16_t l2_idx = (cap_id >> CSPACE_L2_SHIFT) & CSPACE_L2_MASK;
    uint16_t l3_idx = cap_id & CSPACE_L3_MASK;

    if (unlikely(l1_idx >= node->capacity)) {
        return nullptr;
    }

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
    if (unlikely(current_gen != expected_gen || (cap->rights & req_rights) != req_rights)) {
        return nullptr;
    }

    // Resolve Ephemeral (Weak) Capabilities
    if (unlikely(cap->type == CAP_TYPE_WEAK)) {
        struct capability* target =
            (struct capability*)atomic_load_explicit(&cap->object_ptr, memory_order_acquire);

        uint8_t target_gen = atomic_load_explicit(&target->generation, memory_order_acquire);

        // Weak cap's badge stores the generation the target should have
        if (target_gen != cap->badge || (target->rights & req_rights) != req_rights) {
            // Original object revoked/reused
            return nullptr;
        }

        return target;
    }

    return cap;
}

void cnode_init(
    struct cnode* node,
    struct capability* memory,
    size_t count,
    uint64_t prefix,
    uint8_t shift
);
struct capability* cap_alloc(struct cnode* node, uint64_t* out_cap_id);
int cap_delegate(struct capability* parent, struct capability* child, uint16_t reduced_rights);
void cap_revoke(struct cnode* pool, struct capability* target);
int cap_retype(
    struct capability* untyped_cap,
    uint16_t target_type,
    size_t count,
    struct cnode* dest_cnode,
    uint64_t* out_cap_ids
);

int sys_cap_retype(
    struct cnode* root_cnode,
    uint64_t untyped_id,
    uint16_t target_type,
    size_t count,
    uint64_t dest_cnode_id,
    uint64_t* out_array
);
int sys_cap_delegate(
    struct cnode* root_cnode,
    uint64_t dest_cnode_id,
    uint64_t src_cap_id,
    uint16_t reduced_rights,
    uint64_t* new_cap_id
);
int sys_cap_revoke(struct cnode* root_cnode, uint64_t target_id);
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

#endif