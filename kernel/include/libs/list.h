#ifndef KERNEL_LIBS_LIST_H
#define KERNEL_LIBS_LIST_H 1

#include <stdbool.h>

struct list_node {
    struct list_node* next;
    struct list_node* prev;
};

static inline void list_init(struct list_node* sentinel) {
    sentinel->next = sentinel;
    sentinel->prev = sentinel;
}

#define LIST_INIT(name) {&(name), &(name)}

static inline void
__list_add(struct list_node* new_node, struct list_node* prev, struct list_node* next) {
    next->prev = new_node;
    prev->next = new_node;

    new_node->next = next;
    new_node->prev = prev;
}

static inline void list_push_front(struct list_node* sentinel, struct list_node* new_node) {
    __list_add(new_node, sentinel, sentinel->next);
}

static inline void list_push_back(struct list_node* sentinel, struct list_node* new_node) {
    __list_add(new_node, sentinel->prev, sentinel);
}

static inline void __list_del(struct list_node* prev, struct list_node* next) {
    next->prev = prev;
    prev->next = next;
}

static inline void list_remove(struct list_node* entry) {
    __list_del(entry->prev, entry->next);

    // Poison pointers to catch use-after-free bugs
    entry->next = nullptr;
    entry->prev = nullptr;
}

static inline bool list_empty(const struct list_node* sentinel) {
    return sentinel->next == sentinel;
}

#ifndef container_of
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif

#define list_for_each(pos, sentinel) \
    for ((pos) = (sentinel)->next; (pos) != (sentinel); (pos) = (pos)->next)

#define list_for_each_safe(pos, n, sentinel)                               \
    for ((pos) = (sentinel)->next, (n) = (pos)->next; (pos) != (sentinel); \
         (pos) = (n), (n) = (pos)->next)

#endif