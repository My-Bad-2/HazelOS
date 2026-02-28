#include "libs/bp_tree.h"

#include <stdint.h>
#include <string.h>

#include "libs/log.h"

static struct bp_node* bp_alloc_node(struct bp_tree* tree, bool leaf) {
    struct bp_node* n = tree->alloc(sizeof(struct bp_node), tree->alloc_ctx);

    if (n) {
        memset(n, 0, sizeof(struct bp_node));
        n->is_leaf = leaf;
    }

    return n;
}

static void bp_free_node(struct bp_tree* tree, struct bp_node* n) {
    tree->free(n, tree->alloc_ctx);
}

static struct bp_link* get_link(struct bp_tree* tree, void* item) {
    return (struct bp_link*)((char*)item + tree->item_offset);
}

static void* get_item_from_link(struct bp_tree* tree, struct bp_link* link) {
    if (!link) {
        return nullptr;
    }

    return (char*)link - tree->item_offset;
}

static size_t calculate_node_gap(struct bp_tree* tree, struct bp_node* node) {
    size_t max = 0;

    if (node->is_leaf) {
        for (int i = 0; i < node->count; ++i) {
            void* curr = node->children[i];

            // Check gap between this item and the next one
            uintptr_t curr_end   = tree->get_end(curr);
            uintptr_t next_start = 0;
            bool infinite_gap    = false;

            if (i < node->count - 1) {
                void* next_item = node->children[i + 1];
                next_start      = tree->get_start(next_item);
            } else {
                struct bp_link* link = get_link(tree, curr);

                if (link->next) {
                    void* next_item = get_item_from_link(tree, link->next);
                    next_start      = tree->get_start(next_item);
                } else {
                    infinite_gap = true;
                    max          = UINTPTR_MAX;
                }
            }

            if (!infinite_gap) {
                if (next_start > curr_end) {
                    size_t gap = next_start - curr_end;

                    if (gap > max) {
                        max = gap;
                    }
                }
            }
        }
    } else {
        for (int i = 0; i <= node->count; ++i) {
            struct bp_node* child = (struct bp_node*)node->children[i];

            if (child->max_gap > max) {
                max = child->max_gap;
            }
        }
    }

    return max;
}

static void update_gap_upwards(struct bp_tree* tree, struct bp_node* node) {
    while (node) {
        size_t new_gap = calculate_node_gap(tree, node);

        if (new_gap == node->max_gap) {
            break;
        }

        node->max_gap = new_gap;
        node          = node->parent;
    }
}

static void bp_reparent_items(struct bp_tree* tree, struct bp_node* new_owner) {
    if (new_owner->is_leaf) {
        for (int i = 0; i < new_owner->count; ++i) {
            void* item           = new_owner->children[i];
            struct bp_link* link = get_link(tree, item);
            link->parent         = new_owner;
        }
    } else {
        for (int i = 0; i <= new_owner->count; ++i) {
            struct bp_node* child = (struct bp_node*)new_owner->children[i];
            child->parent         = new_owner;
        }
    }
}

static void
bp_split_child(struct bp_tree* tree, struct bp_node* parent, int index, struct bp_node* child) {
    struct bp_node* new_node = bp_alloc_node(tree, child->is_leaf);
    int t                    = BP_ORDER / 2;

    if (child->is_leaf) {
        int split_idx   = t;
        new_node->count = child->count - split_idx;

        for (int i = 0; i < new_node->count; ++i) {
            new_node->keys[i]     = child->keys[split_idx + i];
            new_node->children[i] = child->children[split_idx + i];
        }
    } else {
        int split_idx   = t;
        new_node->count = child->count - split_idx - 1;

        for (int i = 0; i < new_node->count; ++i) {
            new_node->keys[i] = child->keys[split_idx + 1 + i];
        }

        for (int i = 0; i <= new_node->count; ++i) {
            new_node->children[i] = child->children[split_idx + 1 + i];
        }
    }

    child->count = t;

    bp_reparent_items(tree, new_node);
    new_node->parent = parent;

    bp_reparent_items(tree, new_node);
    new_node->parent = parent;

    for (int i = parent->count; i > index; --i) {
        parent->children[i + 1] = parent->children[i];
        parent->keys[i]         = parent->keys[i - 1];
    }

    parent->children[index + 1] = new_node;

    if (child->is_leaf) {
        parent->keys[index] = new_node->keys[0];
    } else {
        parent->keys[index] = child->keys[t];
    }

    parent->count++;

    child->max_gap    = calculate_node_gap(tree, child);
    new_node->max_gap = calculate_node_gap(tree, new_node);

    update_gap_upwards(tree, parent);
}

static void bp_stitch_links(struct bp_tree* tree, struct bp_node* leaf, int index) {
    void* current_item       = leaf->children[index];
    struct bp_link* new_link = get_link(tree, current_item);

    new_link->parent = leaf;

    struct bp_link* prev_link = nullptr;
    struct bp_link* next_link = nullptr;

    if (index > 0) {
        void* left_neighbor = leaf->children[index - 1];
        prev_link           = get_link(tree, left_neighbor);
    } else {
        if (leaf->count > 1) {
            void* old_head = leaf->children[1];
            prev_link      = get_link(tree, old_head)->prev;
        } else {
            prev_link = nullptr;
        }
    }

    if (index < leaf->count - 1) {
        void* right_neighbor = leaf->children[index + 1];
        next_link            = get_link(tree, right_neighbor);
    } else {
        if (leaf->count > 1) {
            void* old_tail = leaf->children[index - 1];
            next_link      = get_link(tree, old_tail)->next;
        } else {
            next_link = nullptr;
        }
    }

    new_link->prev = prev_link;
    new_link->next = next_link;

    if (prev_link) {
        prev_link->next = new_link;
    }

    if (next_link) {
        next_link->prev = new_link;
    }
}

static int bp_insert_nonfull(struct bp_tree* tree, struct bp_node* node, void* item) {
    uintptr_t key = tree->get_start(item);
    int i         = node->count - 1;

    if (node->is_leaf) {
        while (i >= 0 && key < node->keys[i]) {
            node->keys[i + 1]     = node->keys[i];
            node->children[i + 1] = node->children[i];
            i--;
        }

        int insert_pos = i + 1;

        node->keys[insert_pos]     = key;
        node->children[insert_pos] = item;
        node->count++;

        bp_stitch_links(tree, node, insert_pos);

        update_gap_upwards(tree, node);
        return 0;
    } else {
        while (i >= 0 && key < node->keys[i]) {
            i--;
        }

        i++;

        struct bp_node* child = (struct bp_node*)node->children[i];

        if (child->count == BP_ORDER - 1) {
            bp_split_child(tree, node, i, child);

            if (key > node->keys[i]) {
                i++;
            }
        }

        return bp_insert_nonfull(tree, (struct bp_node*)node->children[i], item);
    }
}

static void bp_link_item(struct bp_tree* tree, struct bp_node* leaf, int index, void* new_item) {
    struct bp_link* new_link  = get_link(tree, new_item);
    struct bp_link* prev_link = nullptr;
    struct bp_link* next_link = nullptr;

    if (index < leaf->count - 1) {
        void* next_item = leaf->children[index + 1];
        next_link       = get_link(tree, next_item);
    } else {
        if (index > 0) {
            void* left_neighbor = leaf->children[index - 1];
            next_link           = get_link(tree, left_neighbor)->next;
        }
    }

    if (index > 0) {
        void* prev_item = leaf->children[index - 1];
        prev_link       = get_link(tree, prev_item);
    } else if (index < leaf->count - 1) {
        void* right_neighbor = leaf->children[index + 1];
        prev_link            = get_link(tree, right_neighbor)->prev;
    }

    new_link->prev   = prev_link;
    new_link->next   = next_link;
    new_link->parent = leaf;

    if (prev_link) {
        prev_link->next = new_link;
    }

    if (next_link) {
        next_link->prev = new_link;
    }
}

static void bp_unlink_item(struct bp_tree* tree, void* item) {
    struct bp_link* link = get_link(tree, item);

    if (link->prev) {
        link->prev->next = link->next;
    }

    if (link->next) {
        link->next->prev = link->prev;
    }

    link->prev = link->next = link->parent = nullptr;
}

static void bp_borrow_from_left(
    struct bp_tree* tree,
    struct bp_node* node,
    struct bp_node* left,
    int parent_idx
) {
    int i;

    for (i = node->count; i > 0; i--) {
        node->keys[i]     = node->keys[i - 1];
        node->children[i] = node->children[i - 1];
    }

    if (node->is_leaf) {
        node->keys[0]     = left->keys[left->count - 1];
        node->children[0] = left->children[left->count - 1];

        struct bp_link* link = get_link(tree, node->children[0]);
        link->parent         = node;

        node->parent->keys[parent_idx] = node->keys[0];
    } else {
        node->keys[0]     = node->parent->keys[parent_idx];
        node->children[0] = left->children[left->count];

        ((struct bp_node*)node->children[0])->parent = node;

        node->parent->keys[parent_idx] = left->keys[left->count - 1];
    }

    node->count++;
    left->count--;

    update_gap_upwards(tree, node);
    update_gap_upwards(tree, left);
}

static void bp_borrow_from_right(
    struct bp_tree* tree,
    struct bp_node* node,
    struct bp_node* right,
    int parent_idx
) {
    if (node->is_leaf) {
        node->keys[node->count]     = right->keys[0];
        node->children[node->count] = right->children[0];

        struct bp_link* link = get_link(tree, node->children[node->count]);
        link->parent         = node;

        node->parent->keys[parent_idx] = right->keys[1];
    } else {
        node->keys[node->count]         = node->parent->keys[parent_idx];
        node->children[node->count + 1] = right->children[0];

        ((struct bp_node*)node->children[node->count + 1])->parent = node;

        node->parent->keys[parent_idx] = right->keys[0];
    }

    node->count++;

    for (int i = 0; i < right->count - 1; i++) {
        right->keys[i]     = right->keys[i + 1];
        right->children[i] = right->children[i + 1];
    }

    if (!node->is_leaf) {
        for (int i = 0; i < right->count; i++) {
            right->children[i] = right->children[i + 1];
        }
    }

    right->count--;

    update_gap_upwards(tree, node);
    update_gap_upwards(tree, right);
}

static void
bp_merge_nodes(struct bp_tree* tree, struct bp_node* left, struct bp_node* right, int parent_idx) {
    int start_idx = left->count;

    if (left->is_leaf) {
        for (int i = 0; i < right->count; i++) {
            left->keys[start_idx + i]     = right->keys[i];
            left->children[start_idx + i] = right->children[i];

            struct bp_link* link = get_link(tree, right->children[i]);
            link->parent         = left;
        }

        left->count += right->count;
    } else {
        left->keys[start_idx] = left->parent->keys[parent_idx];
        left->count++;

        for (int i = 0; i < right->count; i++) {
            left->keys[start_idx + 1 + i] = right->keys[i];
        }

        for (int i = 0; i <= right->count; i++) {
            left->children[start_idx + 1 + i]                            = right->children[i];
            ((struct bp_node*)left->children[start_idx + 1 + i])->parent = left;
        }

        left->count += right->count;
    }

    struct bp_node* parent = left->parent;
    for (int i = parent_idx; i < parent->count - 1; i++) {
        parent->keys[i]         = parent->keys[i + 1];
        parent->children[i + 1] = parent->children[i + 2];
    }

    parent->count--;

    bp_free_node(tree, right);

    left->max_gap = calculate_node_gap(tree, left);
}

static void bp_fix_underflow(struct bp_tree* tree, struct bp_node* node) {
    if (node == tree->root) {
        if (node->count == 0 && !node->is_leaf) {
            struct bp_node* new_root = node->children[0];
            new_root->parent         = nullptr;
            tree->root               = new_root;
            tree->height--;
            bp_free_node(tree, node);
        }

        return;
    }

    if (node->count >= BP_MIN) {
        update_gap_upwards(tree, node);
        return;
    }

    struct bp_node* parent = node->parent;
    int idx                = 0;

    while (idx <= parent->count && parent->children[idx] != node) {
        idx++;
    }

    if (idx > 0) {
        struct bp_node* left = parent->children[idx - 1];
        if (left->count > BP_MIN) {
            bp_borrow_from_left(tree, node, left, idx - 1);
            return;
        }
    }

    if (idx < parent->count) {
        struct bp_node* right = parent->children[idx + 1];
        if (right->count > BP_MIN) {
            bp_borrow_from_right(tree, node, right, idx);
            return;
        }
    }

    if (idx > 0) {
        struct bp_node* left = parent->children[idx - 1];
        bp_merge_nodes(tree, left, node, idx - 1);
        bp_fix_underflow(tree, parent);
    } else {
        struct bp_node* right = parent->children[idx + 1];
        bp_merge_nodes(tree, node, right, idx);
        bp_fix_underflow(tree, parent);
    }
}

void bp_init(
    struct bp_tree* tree,
    size_t link_offset,
    bp_alloc_fn alloc,
    bp_free_fn free,
    void* ctx
) {
    memset(tree, 0, sizeof(struct bp_tree));
    tree->item_offset = link_offset;
    tree->alloc       = alloc;
    tree->free        = free;
    tree->alloc_ctx   = ctx;
}

void bp_set_callbacks(struct bp_tree* tree, bp_key_fn start, bp_key_fn end, bp_merge_fn merge) {
    tree->get_start = start;
    tree->get_end   = end;
    tree->can_merge = merge;
}

int bp_insert(struct bp_tree* tree, void* item) {
    if (!tree->root) {
        struct bp_node* root = bp_alloc_node(tree, true);

        if (!root) {
            return -1;
        }

        root->keys[0]     = tree->get_start(item);
        root->children[0] = item;
        root->count       = 1;
        root->parent      = nullptr;

        struct bp_link* link = get_link(tree, item);
        link->parent         = root;
        link->prev           = nullptr;
        link->next           = nullptr;

        tree->root   = root;
        tree->height = 1;
        tree->count  = 1;

        root->max_gap = calculate_node_gap(tree, root);
        tree->cached  = item;

        return 0;
    }

    struct bp_node* root = tree->root;

    if (root->count == BP_ORDER - 1) {
        struct bp_node* new_root = bp_alloc_node(tree, false);

        if (!new_root) {
            return -1;
        }

        new_root->children[0] = root;
        new_root->count       = 0;
        new_root->parent      = nullptr;

        root->parent = new_root;

        tree->root = new_root;
        tree->height++;

        bp_split_child(tree, new_root, 0, root);

        int i         = 0;
        uintptr_t key = tree->get_start(item);

        if (key > new_root->keys[0]) {
            i++;
        }

        int ret = bp_insert_nonfull(tree, (struct bp_node*)new_root->children[i], item);

        if (ret == 0) {
            tree->count++;
            tree->cached = item;
        }

        return ret;
    }

    int ret = bp_insert_nonfull(tree, root, item);

    if (ret == 0) {
        tree->count++;
        tree->cached = item;
    }

    return ret;
}

void* bp_remove(struct bp_tree* tree, uintptr_t key) {
    if (!tree->root) {
        return nullptr;
    }

    struct bp_node* curr = tree->root;

    while (!curr->is_leaf) {
        int i = 0;

        while (i < curr->count && key >= curr->keys[i]) {
            i++;
        }

        curr = (struct bp_node*)curr->children[i];
    }

    int pos = -1;
    for (int i = 0; i < curr->count; i++) {
        if (tree->get_start(curr->children[i]) == key) {
            pos = i;
            break;
        }
    }

    if (pos == -1) {
        return nullptr;
    }

    void* item = curr->children[pos];

    if (tree->cached == item) {
        tree->cached = nullptr;

        struct bp_link* link = get_link(tree, item);
        if (link->prev) {
            tree->cached = get_item_from_link(tree, link->prev);
        }
    }

    bp_unlink_item(tree, item);

    for (int i = pos; i < curr->count - 1; i++) {
        curr->keys[i]     = curr->keys[i + 1];
        curr->children[i] = curr->children[i + 1];
    }

    curr->count--;
    tree->count--;

    if (tree->root == curr) {
        if (curr->count == 0) {
            bp_free_node(tree, curr);
            tree->root   = nullptr;
            tree->height = 0;
        } else {
            update_gap_upwards(tree, curr);
        }
    } else if (curr->count < BP_MIN) {
        bp_fix_underflow(tree, curr);
    } else {
        update_gap_upwards(tree, curr);
    }

    return item;
}

void* bp_search(struct bp_tree* tree, uintptr_t key) {
    if (!tree->root) {
        return nullptr;
    }

    struct bp_node* curr = tree->root;

    while (!curr->is_leaf) {
        int i = 0;
        while (i < curr->count && key >= curr->keys[i]) {
            i++;
        }

        curr = (struct bp_node*)curr->children[i];
    }

    int i = 0;
    while (i < curr->count) {
        if (curr->keys[i] == key) {
            tree->cached = curr->children[i];
            return curr->children[i];
        }

        if (curr->keys[i] > key) {
            return nullptr;
        }

        i++;
    }

    return nullptr;
}

void* bp_search_covering(struct bp_tree* tree, uintptr_t addr) {
    if (!tree->root) {
        return nullptr;
    }

    struct bp_node* curr = tree->root;

    while (!curr->is_leaf) {
        int i = 0;
        while (i < curr->count && addr >= curr->keys[i]) {
            i++;
        }

        curr = (struct bp_node*)curr->children[i];
    }

    int i = 0;
    while (i < curr->count && addr >= curr->keys[i]) {
        i++;
    }

    if (i > 0) {
        void* candidate = curr->children[i - 1];

        uintptr_t start = tree->get_start(candidate);
        uintptr_t end   = tree->get_end(candidate);

        if (addr >= start && addr < end) {
            tree->cached = curr->children[i];
            return candidate;
        }
    }

    return nullptr;
}

uintptr_t bp_find_free_gap(struct bp_tree* tree, size_t size) {
    struct bp_node* curr = tree->root;

    if (!curr || curr->max_gap < size) {
        return 0;
    }

    while (!curr->is_leaf) {
        bool found_path = false;

        for (int i = 0; i <= curr->count; i++) {
            struct bp_node* child = (struct bp_node*)curr->children[i];

            if (child->max_gap >= size) {
                curr       = child;
                found_path = true;
                break;
            }
        }

        if (!found_path) {
            return 0;
        }
    }

    for (int i = 0; i < curr->count; i++) {
        void* item = curr->children[i];

        struct bp_link* link = get_link(tree, item);
        uintptr_t item_end   = tree->get_end(item);
        uintptr_t next_start = (uintptr_t)-1;

        if (link->next) {
            void* next_item = get_item_from_link(tree, link);
            next_start      = tree->get_start(next_item);
        }

        if (next_start - item_end >= size) {
            return item_end;
        }
    }

    return 0;
}

uintptr_t bp_find_gap_bottom_up(struct bp_tree* tree, uintptr_t min_addr, size_t size) {
    if (!tree->root) {
        return min_addr;
    }

    struct bp_node* curr = tree->root;

    while (!curr->is_leaf) {
        int i = 0;
        while (i < curr->count && min_addr >= curr->keys[i]) {
            ++i;
        }

        curr = (struct bp_node*)curr->children[i];
    }

    void* prev_item = nullptr;

    int i = 0;
    for (; i < curr->count; ++i) {
        uintptr_t item_start = tree->get_start(curr->children[i]);
        if (item_start >= min_addr) {
            break;
        }

        prev_item = curr->children[i];
    }

    struct bp_link* link = nullptr;
    void* curr_item      = nullptr;

    if (i < curr->count) {
        curr_item = curr->children[i];
        link      = get_link(tree, curr_item);
    } else if (curr->count > 0) {
        void* last                = curr->children[curr->count - 1];
        struct bp_link* last_link = get_link(tree, last);

        if (last_link->next) {
            link      = last_link->next;
            curr_item = get_item_from_link(tree, link);
        } else {
            uintptr_t last_end = tree->get_end(last);
            return (last_end < min_addr) ? min_addr : last_end;
        }
    }

    uintptr_t gap_start = min_addr;

    if (prev_item) {
        uintptr_t prev_end = tree->get_end(prev_item);

        if (prev_end > gap_start) {
            gap_start = prev_end;
        }
    } else if (link && link->prev) {
        void* prev_vma     = get_item_from_link(tree, link->prev);
        uintptr_t prev_end = tree->get_end(prev_vma);

        if (prev_end > gap_start) {
            gap_start = prev_end;
        }
    }

    while (curr_item) {
        uintptr_t item_start = tree->get_start(curr_item);

        if (item_start > gap_start && (item_start - gap_start) >= size) {
            return gap_start;
        }

        gap_start = tree->get_end(curr_item);
        link      = get_link(tree, curr_item);

        if (link->next) {
            curr_item = get_item_from_link(tree, link->next);
        } else {
            return gap_start;
        }
    }

    return gap_start;
}

uintptr_t bp_find_gap_top_down(struct bp_tree* tree, uintptr_t max_addr, size_t size) {
    if (!tree->root) {
        return max_addr;
    }

    struct bp_node* curr = tree->root;
    while (!curr->is_leaf) {
        int i = 0;

        while (i < curr->count && max_addr >= curr->keys[i]) {
            ++i;
        }

        curr = (struct bp_node*)curr->children[i];
    }

    int i = 0;
    while (i < curr->count && max_addr >= tree->get_start(curr->children[i])) {
        ++i;
    }

    void* curr_item = nullptr;
    if (i > 0) {
        curr_item = curr->children[i - 1];
    } else {
        if (curr->count > 0) {
            struct bp_link* link = get_link(tree, curr->children[0]);

            if (link->prev) {
                curr_item = get_item_from_link(tree, link->prev);
            }
        }
    }

    if (!curr_item) {
        return max_addr - size;
    }

    uintptr_t ceiling = max_addr;
    while (curr_item) {
        uintptr_t item_start = tree->get_start(curr_item);
        uintptr_t item_end   = tree->get_end(curr_item);

        if (item_end > ceiling) {
            ceiling = item_start;
        } else {
            if (ceiling - item_end >= size) {
                return ceiling - size;
            }

            ceiling = item_start;
        }

        struct bp_link* link = get_link(tree, curr_item);
        if (link->prev) {
            curr_item = get_item_from_link(tree, link->prev);
        } else {
            curr_item = nullptr;
        }
    }

    if (ceiling >= size) {
        return ceiling - size;
    }

    return 0;
}