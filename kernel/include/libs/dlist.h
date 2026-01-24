#ifndef KERNEL_LIBS_DLIST_H
#define KERNEL_LIBS_DLIST_H 1

#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef container_of
#define container_of(ptr, type, member)                  \
    ({                                                   \
        typeof(((type*)0)->member)* __mptr = (ptr);      \
        (type*)((char*)__mptr - offsetof(type, member)); \
    })
#endif

struct dlist_head {
    struct dlist_head *next, *prev;
};

#define DLIST_INIT(name) {&(name), &(name)}

static inline void dlist_init(struct dlist_head* list) {
    list->next = list;
    list->prev = list;
}

static inline void
__dlist_add(struct dlist_head* new, struct dlist_head* prev, struct dlist_head* next) {
    next->prev = new;
    new->next  = next;
    new->prev  = prev;
    prev->next = new;
}

static inline void __dlist_del(struct dlist_head* prev, struct dlist_head* next) {
    next->prev = prev;
    prev->next = next;
}

static inline void dlist_add(struct dlist_head* new, struct dlist_head* head) {
    __dlist_add(new, head, head->next);
}

static inline void dlist_add_tail(struct dlist_head* new, struct dlist_head* head) {
    __dlist_add(new, head->prev, head);
}

static inline void dlist_del(struct dlist_head* entry) {
    __dlist_del(entry->prev, entry->next);

    entry->next = nullptr;
    entry->prev = nullptr;
}

static inline void dlist_del_init(struct dlist_head* entry) {
    __dlist_del(entry->prev, entry->next);
    dlist_init(entry);
}

static inline bool dlist_empty(const struct dlist_head* head) {
    return head->next == head;
}

static inline void dlist_splice(struct dlist_head* list, struct dlist_head* head) {
    if (!dlist_empty(list)) {
        struct dlist_head* first = list->next;
        struct dlist_head* last  = list->prev;
        struct dlist_head* at    = head->next;

        first->prev = head;
        head->next  = first;

        last->next = at;
        at->prev   = last;

        dlist_init(list);
    }
}

#define dlist_entry(ptr, type, member) container_of(ptr, type, member)

#define dlist_for_each(pos, head) for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

#define dlist_for_each_entry(pos, head, member)                                               \
    for ((pos) = dlist_entry((head)->next, typeof(*(pos)), member); &(pos)->member != (head); \
         (pos) = dlist_entry((pos)->member.next, typeof(*(pos)), member))

#define dlist_for_each_entry_safe(pos, n, head, member)                          \
    for ((pos) = dlist_entry((head)->next, typeof(*(pos)), member),              \
        (n)    = dlist_entry((pos)->member.next, typeof(*(pos)), member);        \
         &(pos)->member != (head);                                               \
         (pos) = (n), (n) = dlist_entry((n)->member.next, typeof(*(n)), member)) \
        if (&(n)->member != (head)) {                                            \
            dlist_prefetch((n)->member.next);                                    \
        }

#ifdef __cplusplus
}
#endif

#endif