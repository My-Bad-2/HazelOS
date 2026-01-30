#ifndef KERNEL_LIBS_HASHTABLE_H
#define KERNEL_LIBS_HASHTABLE_H 1

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"
#include "libs/log.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hlist_head {
    struct hlist_node* first;
};

struct hlist_node {
    struct hlist_node* next;
    struct hlist_node** pprev;
};

#define HT_KEY_PTR(ptr) ((uint64_t)(ptr) >> 3)

// bits is the log2 of table size
static inline uint32_t ht_hash_32(uint32_t val, unsigned int bits) {
    return (val * 0x9e3779b9u) >> (32 - bits);
}

static inline uint32_t ht_hash_64(uint64_t val, unsigned int bits) {
    return (val * 0x9e3779b97f4a7c15u) >> (64 - bits);
}

#define ht_hash_val(val, bits) \
    (sizeof(val) <= 4 ? ht_hash_32((uint32_t)(val), bits) : ht_hash_64((uint64_t)(val), bits))

static inline void ht_init_table(struct hlist_head* table, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        table[i].first = nullptr;
    }
}

static inline void ht_init_node(struct hlist_node* node) {
    node->next  = nullptr;
    node->pprev = nullptr;
}

static inline bool ht_unhashed(const struct hlist_node* node) {
    return !node->pprev;
}

static inline bool ht_empty(const struct hlist_head* head) {
    return !head->first;
}

static inline void __ht_link_node(struct hlist_head* head, struct hlist_node* node) {
    if (unlikely(!ht_unhashed(node))) {
        PANIC("Double Hash insert!");
        return;
    }

    struct hlist_node* first = head->first;

    node->next  = first;
    node->pprev = &head->first;
    head->first = node;

    if (likely(first)) {
        first->pprev = &node->next;
    }
}

#define ht_insert(table, node, key, bits)        \
    ({                                           \
        uint32_t __idx = ht_hash_val(key, bits); \
        __ht_link_node(&(table)[__idx], node);   \
    })

static inline void ht_remove(struct hlist_node* node) {
    if (unlikely(!node->pprev)) {
        return;
    }

    struct hlist_node* next   = node->next;
    struct hlist_node** pprev = node->pprev;

    *pprev = next;

    if (likely(next)) {
        next->pprev = pprev;
    }

    node->next  = nullptr;
    node->pprev = nullptr;
}

static inline void ht_splice_init(struct hlist_head* list, struct hlist_head* head) {
    if (!list->first) {
        return;
    }

    struct hlist_node* first = list->first;
    struct hlist_node* at    = head->first;

    first->pprev = &head->first;
    head->first  = first;

    struct hlist_node* tail = first;
    while (tail->next) {
        tail = tail->next;
    }

    tail->next = at;
    if (at) {
        at->pprev = &tail->next;
    }

    list->first = nullptr;
}

static inline size_t ht_count(const struct hlist_head* head) {
    size_t count = 0;

    struct hlist_node* n = head->first;
    while (n) {
        count++;
        n = n->next;
    }

    return count;
}

#ifndef container_of
#define container_of(ptr, type, member)                   \
    ({                                                    \
        const typeof(((type*)0)->member)* __mptr = (ptr); \
        (type*)((char*)__mptr - offsetof(type, member));  \
    })
#endif

#define ht_entry(ptr, type, member) container_of(ptr, type, member)

#define ht_for_each_entry(pos, head, member)                   \
    for (struct hlist_node* __node = (head)->first;            \
         __node && ({                                          \
             prefetch(__node->next);                           \
             (pos) = ht_entry(__node, typeof(*(pos)), member); \
             1;                                                \
         });                                                   \
         __node = __node->next)

#define ht_for_each_entry_safe(pos, n, head, member)           \
    for (struct hlist_node* __node = (head)->first;            \
         __node && ({                                          \
             (n) = __node->next;                               \
             1;                                                \
         }) &&                                                 \
         ({                                                    \
             prefetch(__node->next);                           \
             (pos) = ht_entry(__node, typeof(*(pos)), member); \
             1;                                                \
         });                                                   \
         __node = (n))

#ifdef __cplusplus
}
#endif

#endif