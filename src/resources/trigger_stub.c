/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#include <stddef.h>
#include <stdint.h>
#include "aot.h"
#include "rbtree.h"
#include <assert.h>

#ifdef __linux__
  #define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})
#else
  #ifdef _WIN32
    #define container_of(ptr, type, member) (type *)( (char *)(ptr) - offsetof(type,member) )
  #endif
#endif

typedef struct {
  const char* symbol;
  size_t index;
  size_t size;
} triggerstub_triple_t;

struct triggerstub_node {
	struct rb_node node;
	const char* s;
	size_t index;
	size_t size;
};

struct rb_root triggerstubset_root = RB_ROOT;

struct triggerstub_node* triggerstubset_search(const char* s) {

	struct rb_node *node = triggerstubset_root.rb_node;

	while (node) {
		struct triggerstub_node* data = container_of(node, struct triggerstub_node, node);

		if (strcmp(s,data->s)<0) {
			node = node->rb_left;
		}
		else if (strcmp(s,data->s)>0) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

int triggerstubset_insert(const char* s, size_t index, size_t size) {

	struct triggerstub_node* data = calloc(1,sizeof(struct triggerstub_node));
	struct rb_node **new, *parent = 0;
	data->s = calloc(1,strlen(s)+1);
	data->index = index;
	data->size = size;
	strcpy(data->s,s);
	new = &(triggerstubset_root.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct triggerstub_node* this = container_of(*new, struct triggerstub_node, node);

		parent = *new;
		if (strcmp(data->s,this->s)<0)
			new = &((*new)->rb_left);
		else if (strcmp(data->s,this->s)>0)
			new = &((*new)->rb_right);
		else {
		    free((void*)data->s);
		    free(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node_internal(&data->node, parent, new);
	rb_insert_color_internal(&data->node, &triggerstubset_root);

	return 1;
}

void triggerstubset_destroy(struct rb_root* root) {

    struct rb_node * p = rb_first(root);
    while(p) {
        struct triggerstub_node* data = (struct triggerstub_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        free((void*)data->s);
        free(data);
    }
}

size_t triggerstubset_count(const struct rb_root* root) {

	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

long flat_index(const char* trigger_name) {

	struct triggerstub_node* node = triggerstubset_search(trigger_name);
	if (!node) {
		return -1;
	}
	return (long)node->index;
}

unsigned long flat_size(const char* trigger_name) {

	struct triggerstub_node* node = triggerstubset_search(trigger_name);
	assert(node);
	return node->size;
}
