Once you generate an off-target you surely noticed functions aot_* called in the data initialization part of the main function.
Those are memory / fuzzing API used by AoT to abstract away the low level data init and fuzzing from the user.

Here is a brief overview of how they work.

* Memory init functions:

int aot_memory_init(void* ptr, unsigned long long size, int fuzz, const char* name);

int aot_memory_init_ptr(void** ptr, unsigned long size, unsigned long count, int fuzz, const char* name);

unsigned long long aot_memory_init_bitfield(unsigned int bitcount, int fuzz, const char* name);

int aot_memory_init_func_ptr(void** dst, void* src);

void aot_memory_free_ptr(void** ptr);

void aot_memory_setptr(void** dst, void* src);

int aot_check_init_status(char* name, int status);

* Fuzzing functions 

int init_fuzzing(int argc, char* argv[]);
int fuzz_that_data(void* ptr, unsigned long size, const char* name);

// getting fuzzer data to initialize a bitfield

unsigned long long get_fuzz_data_bitfield(unsigned int bitcount, const char* name);

struct obj_tag_map {
    void* userptr;
    void* tagptr;
    struct obj_tag_map* next;
};

void aot_tag_memory(void* objtagptr, int tag);
