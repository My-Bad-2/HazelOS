#ifndef KERNEL_LIBS_SLIST_H
#define KERNEL_LIBS_SLIST_H 1

#include <stdatomic.h>

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef container_of
#define container_of(ptr, type, member)                   \
    ({                                                    \
        const typeof(((type*)0)->member)* __mptr = (ptr); \
        (type*)((char*)__mptr - offsetof(type, member));  \
    })
#endif

struct slist_node {
    struct slist_node* next;
};

struct slist_head {
    struct slist_node* first;
};

#define SLIST_HEAD_INIT(name) {.first = nullptr}

static inline void slist_init(struct slist_head* list) {
    list->first = nullptr;
}

static inline bool slist_empty(const struct slist_head* list) {
    return (list->first == nullptr);
}

static inline void slist_push(struct slist_node* new_node, struct slist_head* list) {
    new_node->next = list->first;
    list->first    = new_node;
}

static inline struct slist_node* slist_pop(struct slist_head* list) {
    struct slist_node* node = list->first;

    if (likely(node)) {
        list->first = node->next;
        node->next  = nullptr;
    }

    return node;
}

static inline struct slist_node* slist_del_after(struct slist_node* prev) {
    struct slist_node* to_del = prev->next;

    if (likely(to_del)) {
        prev->next   = to_del->next;
        to_del->next = nullptr;
    }

    return to_del;
}

static inline void slist_splice(struct slist_head* src, struct slist_head* dst) {
    if (unlikely(slist_empty(src))) {
        return;
    }

    struct slist_node* tail = src->first;
    while (tail->next) {
        tail = tail->next;
    }

    tail->next = dst->first;
    dst->first = src->first;
    slist_init(src);
}

static inline void slist_reverse(struct slist_head* list) {
    struct slist_node* prev = nullptr;
    struct slist_node* curr = list->first;
    struct slist_node* next = nullptr;

    if (unlikely(!curr)) {
        return;
    }

    while (curr) {
        next       = curr->next;
        curr->next = prev;
        prev       = curr;
        curr       = next;
    }

    list->first = prev;
}

static inline void slist_push_atomic(struct slist_node* new_node, struct slist_head* head) {
    struct slist_node* old_head = __atomic_load_n(&head->first, __ATOMIC_RELAXED);

    do {
        new_node->next = old_head;
    } while (!__atomic_compare_exchange_n(
        &head->first,
        &old_head,
        new_node,
        true,
        memory_order_release,
        memory_order_relaxed
    ));
}

static inline struct slist_node* slist_pop_all_atomic(struct slist_head* head) {
    return __atomic_exchange_n(&head->first, nullptr, memory_order_acquire);
}

#define slist_for_each(pos, head) for ((pos) = (head)->first; pos; (pos) = (pos)->next)

#define slist_for_each_entry(pos, head, member)                                      \
    for ((pos) = slist_entry((head)->first, typeof(*(pos)), member); &(pos)->member; \
         (pos) = slist_entry((pos)->member.next, typeof(*(pos)), member))

#define slist_entry(ptr, type, member) ((ptr) ? container_of(ptr, type, member) : nullptr)

#define slist_for_each_entry_safe(pos, n, head, member)                                       \
    for ((pos) = slist_entry((head)->first, typeof(*(pos)), member),                          \
        (n)    = ((pos) ? slist_entry((pos)->member.next, typeof(*(pos)), member) : nullptr); \
         &(pos)->member;                                                                      \
         (pos) = (n),                                                                         \
        (n)    = ((pos) ? slist_entry((pos)->member.next, typeof(*(pos)), member) : nullptr)) \
        if (n) {                                                                              \
            prefetch(&(n)->member);                                                           \
        }

#ifdef __cplusplus
}
#endif

#endif