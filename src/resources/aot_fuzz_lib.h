/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#ifndef AOT_FUZZ_LIB_H
#define AOT_FUZZ_LIB_H

// Fuzzing lib, only for the hackers

#define AOT_SPECIAL_PTR 0x40710000 // 0x10000 is the lowest possible mapping address on Ubuntu as per /proc/sys/vm/mmap_min_addr 
#define AOT_REGION_SIZE 0x2000000 // 32MB

extern unsigned char* aot_fuzz_buffer;         // buffer stores the data from the fuzzer received as the program input
extern unsigned char* aot_fuzz_buffer_ptr;     // stores where we currently are in the buffer
extern unsigned long aot_fuzz_buffer_capacity; // stores the number of bytes read from the fuzzer

int init_fuzzing(int argc, char* argv[]);
int fuzz_that_data(void* ptr, void* src, unsigned long size, const char* name);

// getting fuzzer data to initialize a bitfield
unsigned long long get_fuzz_data_bitfield(unsigned int bitcount, const char* name);

struct obj_tag_map {
    void* userptr;
    void* tagptr;
    struct obj_tag_map* next;
};

void aot_tag_memory(void* objtagptr, unsigned long size, int tag);

#endif