#include "libs/log.h"
#ifndef KERNEL_LIBS_RB_TREE_H
#define KERNEL_LIBS_RB_TREE_H 1

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rb_node {
    uintptr_t rb_parent_color;
    struct rb_node* rb_right;
    struct rb_node* rb_left;
};

struct rb_root {
    struct rb_node* rb_node;
};

#define RB_ROOT        \
    (struct rb_root) { \
        nullptr        \
    }

#define RB_CLEAR_NODE(node) ((node)->rb_parent_color = (uintptr_t)(node))

#define RB_EMPTY_NODE(node) ((node)->rb_parent_color == (uintptr_t)(node))

#define RB_RED   0
#define RB_BLACK 1

static inline struct rb_node* rb_parent(const struct rb_node* n) {
    return (struct rb_node*)(n->rb_parent_color & ~3ul);
}

static inline uintptr_t rb_color(const struct rb_node* n) {
    return n->rb_parent_color & 1;
}

static inline bool rb_is_red(const struct rb_node* n) {
    return rb_color(n) == RB_RED;
}

static inline bool rb_is_black(const struct rb_node* n) {
    return rb_color(n) == RB_BLACK;
}

static inline void __rb_set_parent(struct rb_node* n, struct rb_node* p) {
    n->rb_parent_color = rb_color(n) | (uintptr_t)p;
}

static inline void __rb_set_color(struct rb_node* n, size_t color) {
    n->rb_parent_color = (n->rb_parent_color & ~1ul) | color;
}

static inline void rb_init_node(struct rb_node* node) {
    RB_CLEAR_NODE(node);
    node->rb_right = nullptr;
    node->rb_left  = nullptr;
}

#ifndef container_of
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

static inline void __rb_rotate_left(struct rb_node* node, struct rb_root* root) {
    struct rb_node* right  = node->rb_right;
    struct rb_node* parent = rb_parent(node);

    node->rb_right = right->rb_left;

    if (node->rb_right) {
        __rb_set_parent(right->rb_left, node);
    }

    right->rb_left = node;
    __rb_set_parent(right, parent);

    if (parent) {
        if (node == parent->rb_left) {
            parent->rb_left = right;
        } else {
            parent->rb_right = right;
        }
    } else {
        root->rb_node = right;
    }

    __rb_set_parent(node, right);
}

static inline void __rb_rotate_right(struct rb_node* node, struct rb_root* root) {
    struct rb_node* left   = node->rb_left;
    struct rb_node* parent = rb_parent(node);

    node->rb_left = left->rb_right;

    if (node->rb_left) {
        __rb_set_parent(left->rb_right, node);
    }

    left->rb_right = node;
    __rb_set_parent(left, parent);

    if (parent) {
        if (node == parent->rb_right) {
            parent->rb_right = left;
        } else {
            parent->rb_left = left;
        }
    } else {
        root->rb_node = left;
    }

    __rb_set_parent(node, left);
}

static inline void rb_insert_color(struct rb_node* node, struct rb_root* root) {
    struct rb_node* parent = rb_parent(node);

    while (parent && rb_is_red(parent)) {
        struct rb_node* gparent = rb_parent(parent);

        if (parent == gparent->rb_left) {
            struct rb_node* uncle = gparent->rb_right;

            if (uncle && rb_is_red(uncle)) {
                __rb_set_color(uncle, RB_BLACK);
                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(gparent, RB_RED);

                node   = gparent;
                parent = rb_parent(node);
            } else {
                if (parent->rb_right == node) {
                    struct rb_node* tmp = nullptr;

                    __rb_rotate_left(parent, root);
                    tmp    = parent;
                    parent = node;
                    node   = tmp;
                }

                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(gparent, RB_RED);
                __rb_rotate_right(gparent, root);
            }
        } else {
            struct rb_node* uncle = gparent->rb_left;

            if (uncle && rb_is_red(uncle)) {
                __rb_set_color(uncle, RB_BLACK);
                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(gparent, RB_RED);

                node   = gparent;
                parent = rb_parent(node);
            } else {
                if (parent->rb_left == node) {
                    struct rb_node* tmp = nullptr;

                    __rb_rotate_right(parent, root);
                    tmp    = parent;
                    parent = node;
                    node   = tmp;
                }

                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(gparent, RB_RED);
                __rb_rotate_left(gparent, root);
            }
        }
    }

    __rb_set_color(root->rb_node, RB_BLACK);
}

static inline void
rb_link_node(struct rb_node* node, struct rb_node* parent, struct rb_node** rb_link) {
    node->rb_parent_color = (uintptr_t)parent;
    node->rb_left = node->rb_right = nullptr;
    *rb_link                       = node;
}

static inline struct rb_node* rb_first(const struct rb_root* root) {
    struct rb_node* n = root->rb_node;

    if (!n) {
        return nullptr;
    }

    while (n->rb_left) {
        n = n->rb_left;
    }

    return n;
}

static inline struct rb_node* rb_last(const struct rb_root* root) {
    struct rb_node* n = root->rb_node;

    if (!n) {
        return nullptr;
    }

    while (n->rb_right) {
        n = n->rb_right;
    }

    return n;
}

static inline struct rb_node* rb_next(const struct rb_node* node) {
    struct rb_node* parent = nullptr;

    if (unlikely(node->rb_right)) {
        node = node->rb_right;

        while (node->rb_left) {
            node = node->rb_left;
        }

        return (struct rb_node*)node;
    }

    while ((parent = rb_parent(node)) && node == parent->rb_right) {
        node = parent;
    }

    return parent;
}

static inline struct rb_node* rb_prev(const struct rb_node* node) {
    struct rb_node* parent = nullptr;

    if (unlikely(node->rb_left)) {
        node = node->rb_left;

        while (node->rb_right) {
            node = node->rb_right;
        }

        return (struct rb_node*)node;
    }

    while ((parent = rb_parent(node)) && node == parent->rb_left) {
        node = parent;
    }

    return parent;
}

#define rb_for_each(pos, root) for ((pos) = rb_first(root); pos; (pos) = rb_next(pos))

#define rb_for_each_entry(pos, root, member)                                       \
    for ((pos) = rb_entry(rb_first(root), typeof(*(pos)), member); &(pos)->member; \
         (pos) = rb_entry(rb_next(&(pos)->member), typeof(*(pos)), member))

#define rb_for_each_safe(pos, n, root)                                        \
    for ((pos) = rb_first(root), (n) = (pos) ? rb_next(pos) : nullptr; (pos); \
         (pos) = (n), (n) = (pos) ? rb_next(pos) : nullptr)

static inline void
rb_replace_node(struct rb_node* victim, struct rb_node* new_node, struct rb_root* root) {
    struct rb_node* parent = rb_parent(victim);

    new_node->rb_parent_color = victim->rb_parent_color;
    new_node->rb_left         = victim->rb_left;
    new_node->rb_right        = victim->rb_right;

    if (victim->rb_left) {
        __rb_set_parent(victim->rb_left, new_node);
    }

    if (victim->rb_right) {
        __rb_set_parent(victim->rb_right, new_node);
    }

    if (parent) {
        if (parent->rb_left == victim) {
            parent->rb_left = new_node;
        } else {
            parent->rb_right = new_node;
        }
    } else {
        root->rb_node = new_node;
    }
}

static inline void
__rb_erase_color(struct rb_node* node, struct rb_node* parent, struct rb_root* root) {
    struct rb_node* other = nullptr;

    while ((!node || rb_is_black(node)) && node != root->rb_node) {
        if (parent->rb_left == node) {
            other = parent->rb_right;

            if (rb_is_red(other)) {
                __rb_set_color(other, RB_BLACK);
                __rb_set_color(parent, RB_RED);
                __rb_rotate_left(parent, root);

                other = parent->rb_right;
            }

            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                (!other->rb_right || rb_is_black(other->rb_right))) {
                __rb_set_color(other, RB_RED);

                node   = parent;
                parent = rb_parent(node);
            } else {
                if (!other->rb_right || rb_is_black(other->rb_right)) {
                    __rb_set_color(other->rb_left, RB_BLACK);
                    __rb_set_color(other, RB_RED);
                    __rb_rotate_right(other, root);

                    other = parent->rb_right;
                }

                __rb_set_color(other, rb_color(parent));
                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(other->rb_right, RB_BLACK);
                __rb_rotate_left(parent, root);

                node = root->rb_node;
                break;
            }
        } else {
            other = parent->rb_left;

            if (rb_is_red(other)) {
                __rb_set_color(other, RB_BLACK);
                __rb_set_color(parent, RB_RED);
                __rb_rotate_right(parent, root);

                other = parent->rb_left;
            }

            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                (!other->rb_right || rb_is_black(other->rb_right))) {
                __rb_set_color(other, RB_RED);

                node   = parent;
                parent = rb_parent(node);
            } else {
                if (!other->rb_left || rb_is_black(other->rb_left)) {
                    __rb_set_color(other->rb_right, RB_BLACK);
                    __rb_set_color(other, RB_RED);
                    __rb_rotate_left(other, root);

                    other = parent->rb_left;
                }

                __rb_set_color(other, rb_color(parent));
                __rb_set_color(parent, RB_BLACK);
                __rb_set_color(other->rb_left, RB_BLACK);
                __rb_rotate_right(parent, root);

                node = root->rb_node;
                break;
            }
        }
    }

    if (node) {
        __rb_set_color(node, RB_BLACK);
    }
}

static inline void rb_erase(struct rb_node* node, struct rb_root* root) {
    struct rb_node* child     = node->rb_right;
    struct rb_node* tmp       = node->rb_left;
    struct rb_node* parent    = nullptr;
    struct rb_node* rebalance = nullptr;

    uintptr_t pc = 0;

    if (!tmp) {
        pc     = node->rb_parent_color;
        parent = (struct rb_node*)(pc & ~3ul);
        child  = node->rb_right;
    } else if (!child) {
        pc     = node->rb_parent_color;
        parent = (struct rb_node*)(pc & ~3ul);
        child  = node->rb_left;
    } else {
        struct rb_node* successor = child;
        struct rb_node* child2    = nullptr;

        while ((child2 = successor->rb_left)) {
            successor = child2;
        }

        child     = successor->rb_right;
        parent    = rb_parent(successor);
        rebalance = child;

        if (parent == node) {
            parent = successor;
        } else {
            parent->rb_left = child;

            if (child) {
                __rb_set_parent(child, parent);
            }

            parent = successor;
        }

        successor->rb_parent_color = node->rb_parent_color;
        successor->rb_left         = node->rb_left;
        successor->rb_right        = node->rb_right;

        __rb_set_parent(node->rb_left, successor);

        if (node->rb_right) {
            __rb_set_parent(node->rb_right, successor);
        }

        struct rb_node* orig_parent = rb_parent(node);

        if (orig_parent) {
            if (orig_parent->rb_left == node) {
                orig_parent->rb_left = successor;
            } else {
                orig_parent->rb_right = successor;
            }
        } else {
            root->rb_node = successor;
        }

        if (rb_color(node) == RB_BLACK) {
            __rb_erase_color(rebalance, parent, root);
        }

        return;
    }

    if (child) {
        __rb_set_parent(child, parent);
    }

    if (parent) {
        if (parent->rb_left == node) {
            parent->rb_left = child;
        } else {
            parent->rb_right = child;
        }
    } else {
        root->rb_node = child;
    }

    if ((pc & 1ul) == RB_BLACK) {
        __rb_erase_color(child, parent, root);
    }
}

#ifdef __cplusplus
}
#endif

#endif