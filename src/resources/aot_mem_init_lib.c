/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#include <string.h>
#include <stdlib.h>
#include "aot_mem_init_lib.h"
#include "aot_fuzz_lib.h"

void* memset(void* dst, int ch, size_t count);
void* malloc(size_t size);
void free(void* ptr);
int printf(const char* format, ...);

struct aot_ptr_node* aot_ptrs_head = 0; // points to the beginning of the aot pointers list
struct aot_ptr_node* aot_ptrs_tail = 0; // points to the current tail of the aot pointers list
struct aot_ptr_node* aot_init_vars_head = 0;
struct aot_ptr_node* aot_init_vars_tail = 0;

void _aot_ptrs_append(void* ptr, struct aot_ptr_node* head, struct aot_ptr_node* tail, char* name) {
	if (!ptr) {
		return;
	}

	struct aot_ptr_node* new_node = (struct aot_ptr_node*)malloc(sizeof(struct aot_ptr_node));
	new_node->ptr = ptr;
    new_node->next = 0;
	new_node->name = name;

	if (!head) { // this is the first item in the list
		head = new_node;
		tail = new_node;
	} else {
		tail->next = new_node;
		tail = new_node;
	}
}

int _aot_ptrs_remove(void* ptr, struct aot_ptr_node* head, struct aot_ptr_node* tail){
	if (!ptr) {
		return 0;
	}

	if (!head) {
		// the list is empty
		return 0;
	}
	struct aot_ptr_node* tmp = head;
	struct aot_ptr_node* prev_tmp = 0;
	while (tmp) {
		if (tmp->ptr == ptr) {
			if (tmp == head) {
				head = tmp->next;
			}
			else if (tmp == tail) {
				tail = prev_tmp;
				tail->next = 0;
			}
			else {
				prev_tmp->next = tmp->next;
			}
			// free the node
			free(tmp);
			return 0;
		}
		prev_tmp = tmp;
		tmp = tmp->next;
	}
	return 1;
}


void aot_ptrs_append(void* ptr) {
	_aot_ptrs_append(ptr, aot_ptrs_head, aot_ptrs_tail, 0);
}

int aot_ptrs_remove(void* ptr) {
	return _aot_ptrs_remove(ptr, aot_ptrs_head, aot_ptrs_tail);
}

void aot_GC() {
	// iterate through the pointers list and free the memory
	while (aot_ptrs_head) {
		// free the pointer
		if (aot_ptrs_head->ptr) {
			free(aot_ptrs_head->ptr);
		}
		// free the node
		struct aot_ptr_node* tmp = aot_ptrs_head;
		aot_ptrs_head = tmp->next;
		free(tmp);		
	}
	aot_ptrs_head = 0;
	aot_ptrs_tail = 0;
	while (aot_init_vars_head) {
		// free the node
		struct aot_ptr_node* tmp = aot_init_vars_head;
		aot_init_vars_head = tmp->next;
		free(tmp);		
	}
	aot_init_vars_head = 0;
	aot_init_vars_tail = 0;
}

/* ----------------------------- */
/* Memory init function */
/* ----------------------------- */
int aot_memory_init(void* ptr, unsigned long long size, int fuzz, const char* name) {
    if (!fuzz) {
        memset(ptr, 0, size);
    }
    else {
        return fuzz_that_data(ptr, 0, size, name);
    }
	return 0;
}

int aot_memory_init_ptr(void** ptr, unsigned long size, unsigned long count, int fuzz, const char* name) {
	unsigned total_size = size * count;
	// make UBSAN happy by requesting the allocated pointers to be 64bytes aligned
	int ret = posix_memalign(ptr, 64, total_size);
	if (ret)
		return -1;

    // add the allocated pointer to the list
	aot_ptrs_append(*ptr);

    if (!fuzz) {
        memset(*ptr, 0, total_size);
    }
    else {
        return fuzz_that_data(*ptr, 0, total_size, name);
    }
	return 0;
}

unsigned long long aot_memory_init_bitfield(unsigned int bitcount, int fuzz, const char* name) {

	unsigned long long result = 0;
	if (fuzz) {
		result = get_fuzz_data_bitfield(bitcount, name);	
	}

	return result;
}

int aot_memory_init_func_ptr(void** dst, void* src) {
	*dst = src;
	return 0;
}

int aot_protect_ptr(void** ptr) {
	*ptr = (void*)AOT_PROTECTED_PTR;
	return 0;
}

void aot_memory_free_ptr(void** ptr) {
	if (0 != *ptr)
		free(*ptr);
	*ptr = 0;
}


/* this function was added to make it possible to set pointers regardless 
of their const qualifiers */
void aot_memory_setptr(void** dst, void* src) {
	if (!dst)
		return;
	*dst = src;
}

void aot_memory_setint(void* ptr, unsigned long int val, unsigned size) {
	memcpy(ptr, &val, size);
}

int aot_check_init_status(char* name, int status) {
	if (0 != status) {
		printf("Init failed for %s with status %d\n", name, status);
	}
	return status;
}

void aot_register_init_var(void* ptr, const char* name) {
	_aot_ptrs_append(ptr, aot_init_vars_head, aot_init_vars_tail, name);
}

void* aot_fetch_init_var(const char* name) {
	// iterate through the pointers list and find the pointer by name
	struct aot_ptr_node* node = aot_init_vars_head;

	if (!node) {
		// the list is empty
		return 0;
	}
	while (node) {
		if (node->name && !strcmp(node->name, name)) {
			return node->ptr;
		}
		node = node->next;
	}
}

