#ifndef KERNEL_LIBS_KREF_H
#define KERNEL_LIBS_KREF_H 1

#include <stdatomic.h>

#ifndef container_of
#define container_of(ptr, type, member)                   \
    ({                                                    \
        const typeof(((type*)0)->member)* __mptr = (ptr); \
        (type*)((char*)__mptr - offsetof(type, member));  \
    })
#endif

struct kref {
    atomic_int ref_count;
};

static inline void kref_init(struct kref* kfref) {
    atomic_init(&kfref->ref_count, 1);
}

static inline void kref_get(struct kref* kref) {
    atomic_fetch_add_explicit(&kref->ref_count, 1, memory_order_relaxed);
}

static inline int kref_put(struct kref* kref, void (*release)(struct kref* kref)) {
    if (atomic_fetch_sub_explicit(&kref->ref_count, 1, memory_order_acq_rel) == 1) {
        release(kref);
        return 1;
    }

    return 0;
}

#define kref_entry(ptr, type, member) container_of(ptr, type, member)

#endif