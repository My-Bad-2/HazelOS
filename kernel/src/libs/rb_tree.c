#include "libs/rb_tree.h"

#include "compiler.h"

static inline void __rb_rotate_left(struct rb_node* node, struct rb_root* root) {
    struct rb_node* right  = node->rb_right;
    struct rb_node* parent = node->rb_parent;

    node->rb_right = right->rb_left;

    if (node->rb_right) {
        right->rb_left->rb_parent = node;
    }

    right->rb_left   = node;
    right->rb_parent = parent;

    if (parent) {
        if (node == parent->rb_left) {
            parent->rb_left = right;
        } else {
            parent->rb_right = right;
        }
    } else {
        root->rb_node = right;
    }

    node->rb_parent = right;
}

static inline void __rb_rotate_right(struct rb_node* node, struct rb_root* root) {
    struct rb_node* left   = node->rb_left;
    struct rb_node* parent = node->rb_parent;

    node->rb_left = left->rb_right;

    if (node->rb_left) {
        left->rb_right->rb_parent = node;
    }

    left->rb_right  = node;
    left->rb_parent = parent;

    if (parent) {
        if (node == parent->rb_right) {
            parent->rb_right = left;
        } else {
            parent->rb_left = left;
        }
    } else {
        root->rb_node = left;
    }

    node->rb_parent = left;
}

static inline void
__rb_rotate_left_aug(struct rb_node* node, struct rb_root* root, rb_augment_f augment) {
    struct rb_node* right  = node->rb_right;
    struct rb_node* parent = node->rb_parent;

    node->rb_right = right->rb_left;

    if (node->rb_right) {
        right->rb_left->rb_parent = node;
    }

    right->rb_left   = node;
    right->rb_parent = parent;

    if (parent) {
        if (node == parent->rb_left) {
            parent->rb_left = right;
        } else {
            parent->rb_right = right;
        }
    } else {
        root->rb_node = right;
    }

    node->rb_parent = right;

    if (augment) {
        augment(node);
        augment(right);
    }
}

static inline void
__rb_rotate_right_aug(struct rb_node* node, struct rb_root* root, rb_augment_f augment) {
    struct rb_node* left   = node->rb_left;
    struct rb_node* parent = node->rb_parent;

    node->rb_left = left->rb_right;

    if (node->rb_left) {
        left->rb_right->rb_parent = node;
    }

    left->rb_right  = node;
    left->rb_parent = parent;

    if (parent) {
        if (node == parent->rb_right) {
            parent->rb_right = left;
        } else {
            parent->rb_left = left;
        }
    } else {
        root->rb_node = left;
    }

    node->rb_parent = left;

    if (augment) {
        augment(node);
        augment(left);
    }
}

[[gnu::noinline, gnu::cold]] static void
__rb_erase_color(struct rb_node* node, struct rb_node* parent, struct rb_root* root) {
    struct rb_node* other = nullptr;

    while ((!node || node->rb_color == RB_BLACK) && node != root->rb_node) {
        if (parent->rb_left == node) {
            other = parent->rb_right;

            if (other->rb_color == RB_RED) {
                other->rb_color  = RB_BLACK;
                parent->rb_color = RB_RED;

                __rb_rotate_left(parent, root);
                other = parent->rb_right;
            }

            if ((!other->rb_left || other->rb_left->rb_color == RB_BLACK) &&
                (!other->rb_right || other->rb_right->rb_color == RB_BLACK)) {
                other->rb_color = RB_RED;
                node            = parent;
                parent          = node->rb_parent;
            } else {
                if (!other->rb_right || other->rb_right->rb_color == RB_BLACK) {
                    other->rb_left->rb_color = RB_BLACK;
                    other->rb_color          = RB_RED;

                    __rb_rotate_right(other, root);
                    other = parent->rb_right;
                }

                other->rb_color           = parent->rb_color;
                parent->rb_color          = RB_BLACK;
                other->rb_right->rb_color = RB_BLACK;

                __rb_rotate_left(parent, root);
                node = root->rb_node;
                break;
            }
        } else {
            other = parent->rb_left;

            if (other->rb_color == RB_RED) {
                other->rb_color  = RB_BLACK;
                parent->rb_color = RB_RED;

                __rb_rotate_right(parent, root);
                other = parent->rb_left;
            }
            if ((!other->rb_left || other->rb_left->rb_color == RB_BLACK) &&
                (!other->rb_right || other->rb_right->rb_color == RB_BLACK)) {
                other->rb_color = RB_RED;
                node            = parent;
                parent          = node->rb_parent;
            } else {
                if (!other->rb_left || other->rb_left->rb_color == RB_BLACK) {
                    other->rb_right->rb_color = RB_BLACK;
                    other->rb_color           = RB_RED;
                    __rb_rotate_left(other, root);
                    other = parent->rb_left;
                }

                other->rb_color          = parent->rb_color;
                parent->rb_color         = RB_BLACK;
                other->rb_left->rb_color = RB_BLACK;

                __rb_rotate_right(parent, root);
                node = root->rb_node;
                break;
            }
        }
    }

    if (node) {
        node->rb_color = RB_BLACK;
    }
}

[[gnu::noinline, gnu::cold]] static void __rb_erase_color_aug(
    struct rb_node* node,
    struct rb_node* parent,
    struct rb_root* root,
    rb_augment_f augment
) {
    struct rb_node* other = nullptr;

    while ((!node || node->rb_color == RB_BLACK) && node != root->rb_node) {
        if (parent->rb_left == node) {
            other = parent->rb_right;

            if (other->rb_color == RB_RED) {
                other->rb_color  = RB_BLACK;
                parent->rb_color = RB_RED;

                __rb_rotate_left_aug(parent, root, augment);
                other = parent->rb_right;
            }

            if ((!other->rb_left || other->rb_left->rb_color == RB_BLACK) &&
                (!other->rb_right || other->rb_right->rb_color == RB_BLACK)) {
                other->rb_color = RB_RED;
                node            = parent;
                parent          = node->rb_parent;
            } else {
                if (!other->rb_right || other->rb_right->rb_color == RB_BLACK) {
                    if (other->rb_right) {
                        other->rb_left->rb_color = RB_BLACK;
                    }

                    other->rb_color = RB_RED;

                    __rb_rotate_right_aug(other, root, augment);
                    other = parent->rb_right;
                }

                other->rb_color  = parent->rb_color;
                parent->rb_color = RB_BLACK;
                if (other->rb_right) {
                    other->rb_right->rb_color = RB_BLACK;
                }

                __rb_rotate_left_aug(parent, root, augment);
                node = root->rb_node;
                break;
            }
        } else {
            other = parent->rb_left;

            if (other->rb_color == RB_RED) {
                other->rb_color  = RB_BLACK;
                parent->rb_color = RB_RED;

                __rb_rotate_right_aug(parent, root, augment);
                other = parent->rb_left;
            }
            if ((!other->rb_left || other->rb_left->rb_color == RB_BLACK) &&
                (!other->rb_right || other->rb_right->rb_color == RB_BLACK)) {
                other->rb_color = RB_RED;
                node            = parent;
                parent          = node->rb_parent;
            } else {
                if (!other->rb_left || other->rb_left->rb_color == RB_BLACK) {
                    if (other->rb_right) {
                        other->rb_right->rb_color = RB_BLACK;
                    }

                    other->rb_color = RB_RED;
                    __rb_rotate_left_aug(other, root, augment);
                    other = parent->rb_left;
                }

                other->rb_color  = parent->rb_color;
                parent->rb_color = RB_BLACK;

                if (other->rb_left) {
                    other->rb_left->rb_color = RB_BLACK;
                }

                __rb_rotate_right_aug(parent, root, augment);
                node = root->rb_node;
                break;
            }
        }
    }

    if (node) {
        node->rb_color = RB_BLACK;
    }
}

void rb_insert_color(struct rb_node* node, struct rb_root* root) {
    struct rb_node* parent = node->rb_parent;

    while (parent && parent->rb_color == RB_RED) {
        struct rb_node* gparent = parent->rb_parent;

        if (parent == gparent->rb_left) {
            {
                struct rb_node* uncle = gparent->rb_right;

                if (uncle && uncle->rb_color == RB_RED) {
                    uncle->rb_color   = RB_BLACK;
                    parent->rb_color  = RB_BLACK;
                    gparent->rb_color = RB_RED;

                    node   = gparent;
                    parent = node->rb_parent;
                    continue;
                }
            }

            if (parent->rb_right == node) {
                __rb_rotate_left(parent, root);

                struct rb_node* tmp = parent;
                parent              = node;
                node                = tmp;
            }

            parent->rb_color  = RB_BLACK;
            gparent->rb_color = RB_RED;
            __rb_rotate_right(gparent, root);
        } else {
            {
                struct rb_node* uncle = gparent->rb_left;

                if (uncle && uncle->rb_color == RB_RED) {
                    uncle->rb_color   = RB_BLACK;
                    parent->rb_color  = RB_BLACK;
                    gparent->rb_color = RB_RED;

                    node   = gparent;
                    parent = node->rb_parent;

                    continue;
                }
            }

            if (parent->rb_left == node) {
                __rb_rotate_right(parent, root);
                struct rb_node* tmp = parent;
                parent              = node;
                node                = tmp;
            }

            parent->rb_color  = RB_BLACK;
            gparent->rb_color = RB_RED;
            __rb_rotate_left(gparent, root);
        }
    }

    root->rb_node->rb_color = RB_BLACK;
}

void rb_erase(struct rb_node* node, struct rb_root* root) {
    struct rb_node* child  = node->rb_right;
    struct rb_node* tmp    = node->rb_left;
    struct rb_node* parent = nullptr;

    if (!child && !tmp && node->rb_color == RB_RED) {
        parent = node->rb_parent;

        if (parent) {
            if (parent->rb_left == node) {
                parent->rb_left = nullptr;
            } else {
                parent->rb_right = nullptr;
            }
        } else {
            root->rb_node = nullptr;
        }

        return;
    }

    struct rb_node* rebalance = nullptr;
    rb_color_t color;

    if (!tmp) {
        parent = node->rb_parent;
        color  = node->rb_color;
        child  = node->rb_right;
    } else if (!child) {
        parent = node->rb_parent;
        color  = node->rb_color;
        child  = node->rb_left;
    } else {
        struct rb_node *successor = child, *child2;

        while ((child2 = successor->rb_left)) {
            successor = child2;
        }

        child     = successor->rb_right;
        parent    = successor->rb_parent;
        color     = successor->rb_color;
        rebalance = child;

        if (parent == node) {
            parent = successor;
        } else {
            parent->rb_left = child;

            if (child) {
                child->rb_parent = parent;
            }

            parent = successor;
        }

        successor->rb_parent = node->rb_parent;
        successor->rb_color  = node->rb_color;
        successor->rb_right  = node->rb_right;
        successor->rb_left   = node->rb_left;

        if (node->rb_left) {
            node->rb_left->rb_parent = successor;
        }

        if (node->rb_right) {
            node->rb_right->rb_parent = successor;
        }

        if (node->rb_parent) {
            if (node->rb_parent->rb_left == node) {
                node->rb_parent->rb_left = successor;
            } else {
                node->rb_parent->rb_right = successor;
            }
        } else {
            root->rb_node = successor;
        }

        if (color == RB_BLACK) {
            __rb_erase_color(rebalance, parent, root);
        }

        return;
    }

    if (child) {
        child->rb_parent = parent;
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

    if (color == RB_BLACK) {
        __rb_erase_color(child, parent, root);
    }
}

struct rb_node* rb_first(const struct rb_root* root) {
    struct rb_node* n = root->rb_node;

    if (!n) {
        return nullptr;
    }

    while (n->rb_left) {
        n = n->rb_left;
    }

    return n;
}

struct rb_node* rb_next(const struct rb_node* node) {
    struct rb_node* parent;

    if (unlikely(node->rb_right)) {
        node = node->rb_right;

        while (node->rb_left) {
            node = node->rb_left;
        }

        return (struct rb_node*)node;
    }

    while ((parent = node->rb_parent) && node == parent->rb_right) {
        node = parent;
    }

    return parent;
}

struct rb_node* rb_prev(const struct rb_node* node) {
    struct rb_node* parent;

    if (likely(node->rb_left)) {
        node = node->rb_left;

        while (node->rb_right) {
            node = node->rb_right;
        }

        return (struct rb_node*)node;
    }

    while ((parent = node->rb_parent) && node == parent->rb_left) {
        node = parent;
    }

    return parent;
}

struct rb_node* rb_last(const struct rb_root* root) {
    struct rb_node* node = root->rb_node;

    if (!node) {
        return nullptr;
    }

    while (node->rb_right) {
        node = node->rb_right;
    }

    return node;
}

void rb_replace_node(struct rb_node* victim, struct rb_node* new_node, struct rb_root* root) {
    struct rb_node* parent = victim->rb_parent;

    new_node->rb_parent = parent;
    new_node->rb_color  = victim->rb_color;
    new_node->rb_left   = victim->rb_left;
    new_node->rb_right  = victim->rb_right;

    if (victim->rb_left) {
        victim->rb_left->rb_parent = new_node;
    }

    if (victim->rb_right) {
        victim->rb_right->rb_parent = new_node;
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

void rb_insert_color_aug(struct rb_node* node, struct rb_root* root, rb_augment_f augment) {
    struct rb_node* parent = node->rb_parent;

    while (parent && parent->rb_color == RB_RED) {
        struct rb_node* gparent = parent->rb_parent;

        if (parent == gparent->rb_left) {
            struct rb_node* uncle = gparent->rb_right;

            if (uncle && uncle->rb_color == RB_RED) {
                uncle->rb_color   = RB_BLACK;
                parent->rb_color  = RB_BLACK;
                gparent->rb_color = RB_RED;

                node   = gparent;
                parent = node->rb_parent;
                continue;
            }

            if (parent->rb_right == node) {
                __rb_rotate_left_aug(parent, root, augment);

                struct rb_node* tmp = parent;
                parent              = node;
                node                = tmp;
            }

            parent->rb_color  = RB_BLACK;
            gparent->rb_color = RB_RED;

            __rb_rotate_right_aug(gparent, root, augment);
        } else {
            struct rb_node* uncle = gparent->rb_left;

            if (uncle && uncle->rb_color == RB_RED) {
                uncle->rb_color   = RB_BLACK;
                parent->rb_color  = RB_BLACK;
                gparent->rb_color = RB_RED;

                node   = gparent;
                parent = node->rb_parent;
                continue;
            }

            if (parent->rb_left == node) {
                __rb_rotate_right_aug(parent, root, augment);

                struct rb_node* tmp = parent;
                parent              = node;
                node                = tmp;
            }

            parent->rb_color  = RB_BLACK;
            gparent->rb_color = RB_RED;
            __rb_rotate_left_aug(gparent, root, augment);
        }
    }

    root->rb_node->rb_color = RB_BLACK;
}

void rb_insert_augmented(struct rb_node* node, struct rb_root* root, rb_augment_f augment) {
    if (!augment) {
        return;
    }

    augment(node);

    struct rb_node* parent = node->rb_parent;

    while (parent) {
        if (!augment(parent)) {
            break;
        }

        parent = parent->rb_parent;
    }

    rb_insert_color_aug(node, root, augment);
}

void rb_erase_augmented(struct rb_node* node, struct rb_root* root, rb_augment_f augment) {
    if (RB_EMPTY_NODE(node)) {
        return;
    }

    struct rb_node* child     = node->rb_right;
    struct rb_node* tmp       = node->rb_left;
    struct rb_node* parent    = nullptr;
    struct rb_node* rebalance = nullptr;
    struct rb_node* deepest   = nullptr;
    rb_color_t color;

    if (!tmp) {
        parent  = node->rb_parent;
        color   = node->rb_color;
        child   = node->rb_right;
        deepest = parent;
    } else if (!child) {
        parent  = node->rb_parent;
        color   = node->rb_color;
        child   = node->rb_left;
        deepest = parent;
    } else {
        struct rb_node* successor = child;
        struct rb_node* child2    = nullptr;

        while ((child2 = successor->rb_left)) {
            successor = child2;
        }

        child     = successor->rb_right;
        parent    = successor->rb_parent;
        color     = successor->rb_color;
        rebalance = child;

        deepest = (parent == node) ? successor : parent;

        if (parent == node) {
            parent = successor;
        } else {
            parent->rb_left = child;

            if (child) {
                child->rb_parent = parent;
            }
        }

        successor->rb_parent = node->rb_parent;
        successor->rb_color  = node->rb_color;
        successor->rb_right  = node->rb_right;
        successor->rb_left   = node->rb_left;

        if (node->rb_left) {
            node->rb_left->rb_parent = successor;
        }

        if (node->rb_right) {
            node->rb_right->rb_parent = successor;
        }

        if (node->rb_parent) {
            if (node->rb_parent->rb_left == node) {
                node->rb_parent->rb_left = successor;
            } else {
                node->rb_parent->rb_right = successor;
            }
        } else {
            root->rb_node = successor;
        }

        augment(successor);

        if (color == RB_BLACK) {
            __rb_erase_color_aug(rebalance, parent, root, augment);
        }

        goto propagate;
    }

    if (child) {
        child->rb_parent = parent;
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

    if (color == RB_BLACK) {
        __rb_erase_color_aug(child, parent, root, augment);
    }

propagate:
    while (deepest && !RB_EMPTY_NODE(deepest)) {
        augment(deepest);
        deepest = deepest->rb_parent;
    }
}