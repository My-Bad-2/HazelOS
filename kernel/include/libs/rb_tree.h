#ifndef KERNEL_LIBS_RB_TREE_H
#define KERNEL_LIBS_RB_TREE_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RB_RED = 0,
    RB_BLACK,
} rb_color_t;

struct rb_node {
    struct rb_node* rb_parent;
    struct rb_node* rb_right;
    struct rb_node* rb_left;
    rb_color_t rb_color;
};

struct rb_root {
    struct rb_node* rb_node;
};

struct rb_root_cached {
    struct rb_root rb_root;
    struct rb_node* rb_leftmost;
};

#define RB_ROOT        \
    (struct rb_root) { \
        nullptr        \
    }

#define RB_ROOT_CACHED        \
    (struct rb_root_cached) { \
        {nullptr}, nullptr    \
    }

#define RB_CLEAR_NODE(node) ((node)->rb_parent = (node))
#define RB_EMPTY_NODE(node) ((node)->rb_parent == (node))

#ifndef container_of
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

typedef bool (*rb_augment_f)(struct rb_node* node);

[[gnu::always_inline]] static inline void rb_init_node(struct rb_node* node) {
    RB_CLEAR_NODE(node);
    node->rb_right = node->rb_left = nullptr;
    node->rb_color                 = RB_RED;
}

[[gnu::always_inline]] static inline void
rb_link_node(struct rb_node* node, struct rb_node* parent, struct rb_node** rb_link) {
    node->rb_parent = parent;
    node->rb_color  = RB_RED;
    node->rb_left = node->rb_right = nullptr;

    *rb_link = node;
}

struct rb_node* rb_first(const struct rb_root* root);

static inline struct rb_node* rb_first_cached(const struct rb_root_cached* root) {
    return root->rb_leftmost;
}

struct rb_node* rb_next(const struct rb_node* node);
struct rb_node* rb_prev(const struct rb_node* node);

struct rb_node* rb_last(const struct rb_root* root);

[[gnu::noinline, gnu::cold]] void rb_insert_color(struct rb_node* node, struct rb_root* root);
void rb_erase(struct rb_node* node, struct rb_root* root);
void rb_replace_node(struct rb_node* victim, struct rb_node* new_node, struct rb_root* root);

void rb_insert_color_aug(struct rb_node* node, struct rb_root* root, rb_augment_f augment);
void rb_insert_augmented(struct rb_node* node, struct rb_root* root, rb_augment_f augment);
void rb_erase_augmented(struct rb_node* node, struct rb_root* root, rb_augment_f augment);

[[gnu::always_inline]] static inline void
rb_insert_color_cached(struct rb_node* node, struct rb_root_cached* root, bool leftmost) {
    if (leftmost) {
        root->rb_leftmost = node;
    }

    rb_insert_color(node, &root->rb_root);
}

[[gnu::always_inline]] static inline void
rb_erase_cached(struct rb_node* node, struct rb_root_cached* root) {
    if (root->rb_leftmost == node) {
        root->rb_leftmost = rb_next(node);
    }

    rb_erase(node, &root->rb_root);
}

#define rb_for_each(pos, root) for ((pos) = rb_first(root); pos; (pos) = rb_next(pos))

#define rb_for_each_entry(pos, root, member)                                       \
    for ((pos) = rb_entry(rb_first(root), typeof(*(pos)), member); &(pos)->member; \
         (pos) = rb_entry(rb_next(&(pos)->member), typeof(*(pos)), member))

#define rb_for_each_safe(pos, n, root)                                      \
    for ((pos) = rb_first(root), (n) = (pos) ? rb_next(pos) : nullptr; pos; \
         (pos) = (n), (n) = (pos) ? rb_next(pos) : nullptr)

#define rb_for_each_reverse(pos, root) for ((pos) = rb_last(root); pos; (pos) = rb_prev(pos))

#define rb_for_each_reverse_safe(pos, n, root)                             \
    for ((pos) = rb_last(root), (n) = (pos) ? rb_prev(pos) : nullptr; pos; \
         (pos) = (n), (n) = (pos) ? rb_prev(pos) : nullptr)

#ifdef __cplusplus
}
#endif

#endif