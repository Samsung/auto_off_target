/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#include <string.h>
#include "aot_mem_init_lib.h"
#include "aot_fuzz_lib.h"

void* memset(void* dst, int ch, size_t count);
void* malloc(size_t size);
void free(void* ptr);
int printf(const char* format, ...);

struct aot_ptr_node* aot_ptrs_head = 0; // points to the beginning of the aot pointers list
struct aot_ptr_node* aot_ptrs_tail = 0; // points to the current tail of the aot pointers list

void aot_ptrs_append(void* ptr) {
	if (!ptr) {
		return;
	}

	struct aot_ptr_node* new_node = (struct aot_ptr_node*)malloc(sizeof(struct aot_ptr_node));
	new_node->ptr = ptr;
    new_node->next = 0;

	if (!aot_ptrs_head) { // this is the first item in the list
		aot_ptrs_head = new_node;
		aot_ptrs_tail = new_node;
	} else {
		aot_ptrs_tail->next = new_node;
		aot_ptrs_tail = new_node;
	}
}

int aot_ptrs_remove(void* ptr){
	if (!ptr) {
		return 0;
	}

	if (!aot_ptrs_head) {
		// the list is empty
		return 0;
	}
	struct aot_ptr_node* tmp = aot_ptrs_head;
	struct aot_ptr_node* prev_tmp = 0;
	while (tmp) {
		if (tmp->ptr == ptr) {
			if (tmp == aot_ptrs_head) {
				aot_ptrs_head = tmp->next;
			}
			else if (tmp == aot_ptrs_tail) {
				aot_ptrs_tail = prev_tmp;
				aot_ptrs_tail->next = 0;
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

void aot_GC() {
	// iterate through the pointers list and free the memory
	struct aot_ptr_node* node = aot_ptrs_head;

	if (!aot_ptrs_head) {
		// the list is empty
		return;
	}
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
}

/* ----------------------------- */
/* Memory init function */
/* ----------------------------- */
int aot_memory_init(void* ptr, unsigned long long size, int fuzz, const char* name) {
	memset(ptr, 0, size);
    if (fuzz) {
        return fuzz_that_data(ptr, 0, size, name);
    }
	return 0;
}

int aot_memory_init_ptr(void** ptr, unsigned long size, unsigned long count, int fuzz, const char* name) {
	unsigned total_size = size * count;
	*ptr = malloc(total_size);
	if (0 == *ptr)
		return -1;
	memset(*ptr, 0, total_size);

    // add the allocated pointer to the list
	aot_ptrs_append(*ptr);

    if (fuzz) {
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

int aot_check_init_status(char* name, int status) {
	if (0 != status) {
		printf("Init failed for %s with status %d\n", name, status);
	}
	return status;
}

