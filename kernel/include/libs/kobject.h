#ifndef KERNEL_LIBS_KOBJECT_H
#define KERNEL_LIBS_KOBJECT_H 1

#include <stdatomic.h>

#ifndef container_of
#define container_of(ptr, type, member)                   \
    ({                                                    \
        const typeof(((type*)0)->member)* __mptr = (ptr); \
        (type*)((char*)__mptr - offsetof(type, member));  \
    })
#endif

struct koid_allocator {
    uint64_t curr_id;
    uint64_t block_max_id;
};

struct kobject {
    atomic_int ref_count;
};

void koid_init(void);
uint64_t generate_koid(struct koid_allocator* core, uint8_t object_type);

static inline void kref_init(struct kobject* kfref) {
    atomic_init(&kfref->ref_count, 1);
}

static inline void kref_get(struct kobject* kref) {
    atomic_fetch_add_explicit(&kref->ref_count, 1, memory_order_relaxed);
}

static inline int kref_put(struct kobject* kref, void (*release)(struct kobject* kref)) {
    if (atomic_fetch_sub_explicit(&kref->ref_count, 1, memory_order_acq_rel) == 1) {
        release(kref);
        return 1;
    }

    return 0;
}

#define kref_entry(ptr, type, member) container_of(ptr, type, member)

#endif