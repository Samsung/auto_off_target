#ifndef _LINUX_INTERVAL_TREE_H
#define _LINUX_INTERVAL_TREE_H

#include "rbtree.h"

extern void interval_tree_remove(struct interval_tree_node *node, struct rb_root *root);
extern struct interval_tree_node * interval_tree_iter_next(struct interval_tree_node *node, uintptr_t start, uintptr_t last);
extern void interval_tree_print(struct rb_root *root);
extern void interval_tree_destroy(struct rb_root *root);


#endif	/* _LINUX_INTERVAL_TREE_H */
