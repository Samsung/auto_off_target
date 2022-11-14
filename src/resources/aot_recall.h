/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

// Create AoT_Recall file with name `filename`
int fl_create(const char* filename);

// Add fuzzer output to recall file
int fl_add(void* dst, void* src, unsigned long long size, void* data);

// Save memory location of OT entry point argument to recall file
int fl_save_arg(void* ptr, const char* name);
#define AOT_RECALL_SAVE_ARG(PTR)        if(fl_save_arg(PTR, #PTR)) exit(1)

// Save arbitrary other value to recall file (ex. interface type)
int fl_save_other(int type, const char* value);
enum RECALL_FL_OTHER_TYPES {
    RECALL_FL_OTHER_TYPES_INTERFACE,
};
void exit(int exit_code);
#define AOT_RECALL_SAVE_INTERFACE(INTERFACE)    \
        if(fl_save_other(RECALL_FL_OTHER_TYPES_INTERFACE, INTERFACE)) exit(1)
