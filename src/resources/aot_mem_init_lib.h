/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#ifndef AOT_MEM_INIT_LIB_H
#define AOT_MEM_INIT_LIB_H

struct aot_ptr_node {
    struct aot_ptr_node* next;
    void* ptr;
    char* name;
};

int aot_memory_init(void* ptr, unsigned long long size, int fuzz, const char* name);
int aot_memory_init_ptr(void** ptr, unsigned long size, unsigned long count, int fuzz, const char* name);
unsigned long long aot_memory_init_bitfield(unsigned int bitcount, int fuzz, const char* name);
int aot_memory_init_func_ptr(void** dst, void* src);
int aot_protect_ptr(void** ptr);
void aot_memory_free_ptr(void** ptr);
void aot_ptrs_append(void* ptr, struct aot_ptr_node* head, struct aot_ptr_node* tail, char* name);
int aot_ptrs_remove(void* ptr, struct aot_ptr_node* head, struct aot_ptr_node* tail);
void aot_GC();
void aot_memory_setptr(void** dst, void* src);
void aot_memory_setint(void* ptr, unsigned long int val, unsigned size);
int aot_check_init_status(char* name, int status);
void aot_register_init_var(void* ptr, const char* name);
void* aot_fetch_init_var(const char* name);
#endif