#ifndef KERNEL_LIBS_BP_TREE_H
#define KERNEL_LIBS_BP_TREE_H 1

#include <stdatomic.h>
#include <stdint.h>

// Order 16 fits nicely in 2 cache lines on a 64-bite system.
// (15 keys * 8) + (16 ptrs * 8) + overhead ~= 256 byes (4 lines)
#define BP_ORDER 16
#define BP_MIN   ((BP_ORDER - 1) / 2)

#ifndef container_of
#define container_of(ptr, type, member)                   \
    ({                                                    \
        const typeof(((type*)0)->member)* __mptr = (ptr); \
        (type*)((char*)__mptr - offsetof(type, member));  \
    })
#endif

struct bp_link {
    struct bp_link* prev;
    struct bp_link* next;
    void* parent;
};

struct [[gnu::aligned(CACHE_LINE_SIZE)]] bp_node {
    atomic_char is_leaf;
    atomic_ushort count;
    atomic_size_t max_gap;
    struct bp_node* parent;

    uintptr_t keys[BP_ORDER - 1];
    void* children[BP_ORDER];
};

typedef uintptr_t (*bp_key_fn)(const void* item);
typedef uintptr_t (*bp_end_fn)(const void* item);
typedef bool (*bp_merge_fn)(void* left, void* right);

typedef void* (*bp_alloc_fn)(size_t size, void* ctx);
typedef void (*bp_free_fn)(void* ptr, void* ctx);

struct bp_tree {
    struct bp_node* root;

    size_t item_offset;
    void* alloc_ctx;
    bp_alloc_fn alloc;
    bp_free_fn free;

    bp_key_fn get_start;
    bp_key_fn get_end;
    bp_merge_fn can_merge;

    size_t height;
    size_t count;
};

void bp_init(
    struct bp_tree* tree,
    size_t link_offset,
    bp_alloc_fn alloc,
    bp_free_fn free,
    void* ctx
);

void bp_set_callbacks(struct bp_tree* tree, bp_key_fn start, bp_key_fn end, bp_merge_fn merge);

int bp_insert(struct bp_tree* tree, void* item);
void* bp_remove(struct bp_tree* tree, uintptr_t key);
void* bp_search(struct bp_tree* tree, uintptr_t key);
void* bp_search_covering(struct bp_tree* tree, uintptr_t addr);

uintptr_t bp_find_free_gap(struct bp_tree* tree, size_t size);

#define bp_entry(ptr, type, member) container_of(ptr, type, member)

#endif