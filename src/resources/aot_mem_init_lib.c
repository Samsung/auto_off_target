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

