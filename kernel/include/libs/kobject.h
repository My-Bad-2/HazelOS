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
    uint64_t koid;
    atomic_int ref_count;
};

void koid_init(void);
struct koid_allocator* koid_get_current_allocator(void);
uint64_t generate_koid(struct koid_allocator* core, uint8_t object_type);
void* get_object_from_koid(uint64_t koid, uint8_t type);
int register_koid(uint64_t koid, void* obj);

static inline void kref_init(struct kobject* obj, uint8_t type) {
    obj->koid = generate_koid(koid_get_current_allocator(), type);
    atomic_init(&obj->ref_count, 1);
}

static inline void kref_get(struct kobject* obj) {
    atomic_fetch_add_explicit(&obj->ref_count, 1, memory_order_relaxed);
}

static inline int kref_put(struct kobject* obj, void (*release)(struct kobject* kref)) {
    if (atomic_fetch_sub_explicit(&obj->ref_count, 1, memory_order_acq_rel) == 1) {
        if (release) release(obj);
        return 1;
    }

    return 0;
}

#define kref_entry(ptr, type, member) container_of(ptr, type, member)

#endif