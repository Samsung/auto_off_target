/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "aot_recall.h"

#define AOT_RECALL_INFO(X, ...)           fprintf(stderr, "[AOT_RECALL] %s> Info: " X "\n", __func__, ##__VA_ARGS__)
#define AOT_RECALL_ERR(X, ...)            fprintf(stderr, "[AOT_RECALL] %s> Err: " X "\n", __func__, ##__VA_ARGS__)

/****************************
 * Fuzz log (FL) file implementation
 *  This section implements some generic functions to create
 *  and parse files containing detailed input format log
 ****************************/
#define FL_HEADER_MAGIC 0xCAFECAFE

// Global handler to opened file
static FILE* file;

// File structure
struct FL_file_header {
    long long magic;
};

enum FL_file_fieldType {
    FL_FIELD_DATA,
    FL_FIELD_ARG,
    FL_FIELD_OTHER,
};
struct FL_file_data {
    void* dst;
    void* src;
    size_t size;
    char data[16];
} __attribute__((packed));
struct FL_file_arg {
    void* ptr;
    char name[32];
} __attribute__((packed));
struct FL_file_other {
    int type;
    char value[36];
} __attribute__((packed));

struct FL_file_field {
    enum FL_file_fieldType type;
    union {
        struct FL_file_data data;
        struct FL_file_arg arg;
        struct FL_file_other other;
    };
};

// User interface
struct FL_data {
    void* dst;
    void* src;
    size_t size;
    char* data;
};
struct FL_args {
    void* ptr;
    char name[32];
};
struct FL_other {
    int type;
    char value[36];
};
struct FL_content {
    struct FL_data* data;
    struct FL_args* args;
    struct FL_other* others;

    size_t dataLen;
    size_t argsLen;
    size_t othersLen;
};

static void fl_close_atexit(void);
static void fl_close(int);

static int fl_file_open(const char* filename, const char* mode) {
    int ret;
    
    if(file != NULL) {
        AOT_RECALL_ERR("cannot open new file before closing the previous one");
        return -1;
    }

    file = fopen(filename, mode);
    if(file == NULL) {
        AOT_RECALL_ERR("failed to open FL file (%d)%s", errno, strerror(errno));
        return -1;
    }

    return 0;
}

int fl_create(const char* filename) {
    int ret;
    struct FL_file_header hdr = {
        .magic = FL_HEADER_MAGIC
    };

    ret = fl_file_open(filename, "wb");
    if(ret) return ret;

    ret = fwrite(&hdr, sizeof(hdr), 1, file);
    if(!ret) {
        AOT_RECALL_ERR("failed to write file header (%d)%s", errno, strerror(errno));
        return -1;
    }

    // Register close callback
    ret = atexit(fl_close_atexit);
    if(ret) {
        AOT_RECALL_ERR("failed to register at_exit handler (%d)%s", errno, strerror(errno));
        return -1;
    }

    // Register signals callback
    struct sigaction sig = {
        .sa_handler = fl_close,
        .sa_flags = SA_ONSTACK,     // Try to use the alternate stack - we have no idea what OT could have done with his stack
    };
    for(int i = 0; i < SIGUSR2; i++)
        sigaction(i, &sig, NULL);

    return 0;
}

static int fl_open(const char* filename) {
    int ret;
    struct FL_file_header hdr;

    ret = fl_file_open(filename, "rb");
    if(ret)
        return -1;

    ret = fread(&hdr, sizeof(hdr), 1, file);
    if(!ret) {
        AOT_RECALL_ERR("failed to read FL file (%d)%s", errno, strerror(errno));
        return -1;
    }

    if(hdr.magic != FL_HEADER_MAGIC) {
        AOT_RECALL_ERR("input isn't a correct FL file (magic mismatch)");
        return -1;
    }

    return 0;
}

static int fl_load(struct FL_content* content) {
    int ret = 1;
    int dataLen = 0, argsLen = 0, othersLen = 0;
    struct FL_file_field field;

    // Count number of elements
    while(ret) {
        ret = fread(&field, sizeof(field), 1, file);
        if(!ret) continue;

        if(field.type == FL_FIELD_ARG)
            argsLen++;
        else if(field.type == FL_FIELD_OTHER)
            othersLen++;
        else if(field.type == FL_FIELD_DATA) {
            int remSize = field.data.size - sizeof(field.data.data);
            if(remSize > 0)
                fseek(file, remSize, SEEK_CUR);
            dataLen++;
        } else {
            AOT_RECALL_ERR("input isn't a correct FL file (unknown field type %d)", field.type);
            return -1;
        }
    }
    fseek(file, sizeof(struct FL_file_header), SEEK_SET);

    // Read elements to user memory
    int argCnt = 0, dataCnt = 0, otherCnt = 0;
    ret = 1;
    content->argsLen = argsLen;
    content->dataLen = dataLen;
    content->othersLen = othersLen;
    content->args = malloc(sizeof(struct FL_args) * argsLen);
    content->data = malloc(sizeof(struct FL_data) * dataLen);
    content->others = malloc(sizeof(struct FL_other) * othersLen);

    while(ret) {
        ret = fread(&field, sizeof(field), 1, file);
        if(!ret) continue;

        if(field.type == FL_FIELD_ARG) {
            content->args[argCnt].ptr = field.arg.ptr;
            strncpy(content->args[argCnt].name, field.arg.name, sizeof(field.arg.name));
            argCnt++;
        } else if(field.type == FL_FIELD_OTHER) {
            content->others[otherCnt].type = field.other.type;
            memcpy(content->others[otherCnt].value, field.other.value, sizeof(field.other.value));
            otherCnt++;
        } else if(field.type == FL_FIELD_DATA) {
            struct FL_data* data = &content->data[dataCnt];
            data->dst = field.data.dst;
            data->src = field.data.src;
            data->size = field.data.size;
            data->data = malloc(field.data.size);

            if(field.data.size <= 16) {
                memcpy(data->data, field.data.data, field.data.size);
            } else {
                memcpy(data->data, field.data.data, 16);
                ret = fread(data->data + 16, field.data.size - 16, 1, file);
                if(!ret) {
                    AOT_RECALL_ERR("input isn't a correct FL file (truncated file)");
                    return -1;
                }
            }
            dataCnt++;
        }
    }

    return 0;
}

int fl_add(void* dst, void* src, unsigned long long size, void* data) {
    int ret;
    struct FL_file_data fd = {
        .dst = dst,
        .src = src,
        .size = size
    };
    struct FL_file_field field = {
        .type = FL_FIELD_DATA,
        .data = fd
    };

    if(file == NULL)
        return 0;   // Exit gracefully when file is not opened

    AOT_RECALL_INFO("dst = %p, src=%p, size = %llu", dst, src, size);

    if(size <= 16)
        memcpy(field.data.data, data, size);
    else 
        memcpy(field.data.data, data, 16);
    
    ret = fwrite(&field, sizeof(field), 1, file);
    if(!ret) goto failed_write;

    if(size > 16) {
        ret = fwrite(data + 16, size - 16, 1, file);
        if(!ret) goto failed_write;
    }

    fflush(file);

    return 0;

failed_write:
    AOT_RECALL_ERR("failed to write FL file (%d)%s", errno, strerror(errno));
    return -1;
}

int fl_save_arg(void* ptr, const char* name) {
    int ret;
    struct FL_file_arg arg = {
        .ptr = ptr
    };
    struct FL_file_field field = {
        .type = FL_FIELD_ARG,
        .arg = arg
    };

    if(file == NULL)
        return 0;   // Exit gracefully when file is not opened

    strncpy(field.arg.name, name, sizeof(field.arg.name));

    AOT_RECALL_INFO("ptr = %p, name=%s", ptr, name);
    ret = fwrite(&field, sizeof(field), 1, file);
    if(!ret) {
        AOT_RECALL_ERR("failed to write arg to FL file (%d)%s", errno, strerror(errno));
    }

    fflush(file);

    return 0;
}

int fl_save_other(int type, const char* value) {
    int ret;
    struct FL_file_other other = {
        .type = type,
    };
    strncpy(other.value, value, sizeof(other.value));
    struct FL_file_field field = {
        .type = FL_FIELD_OTHER,
        .other = other,
    };

    if(file == NULL)
        return 0;

    AOT_RECALL_INFO("type = %d, value=%p", type, value);
    ret = fwrite(&field, sizeof(field), 1, file);
    if(!ret) {
        AOT_RECALL_ERR("failed to write param to FL file (%d)%s", errno, strerror(errno));
    }

    fflush(file);

    return 0;
}

static void fl_print(struct FL_content* content) {
    // Print others
    for(int i = 0; i < content->othersLen; i++) {
        struct FL_other* other = &content->others[i];
        printf("[FuzzLog] OTHER(%02d) #%02d == \"%s\"\n", i, other->type, other->value);
    }

    // Print args
    for(int i = 0; i < content->argsLen; i++) {
        struct FL_args* args = &content->args[i];
        printf("[FuzzLog] ARG(%02d) \"%s\" @ %p\n", i, args->name, args->ptr);
    }

    // Print fuzzing data
    for(int i = 0; i < content->dataLen; i++) {
        struct FL_data* log = &content->data[i];

        printf("[FuzzLog]  %p ==> %p (%zu bytes): \n\t\"", log->src, log->dst, log->size);
        for(int j = 0; j < log->size; j++) {
            unsigned int byte = log->data[j] & 0xff;
            printf("%02x", byte);
        }
        printf("\"\n");
    }
}

// Used for intercepting ASAN reports
static void _fl_close_file() {
    // Make sure this handler is invoked only once
    FILE* fcopy = file;
    file = NULL;
    if(fcopy == NULL)
        return;

    fclose(fcopy);
    AOT_RECALL_INFO("closed recall file");
}

// Override ASAN report callback
void __asan_on_error(void) {
    _fl_close_file();
}

static void fl_close(int) {
    _fl_close_file();
    _exit(0);
}
static void fl_close_atexit(void) {
    fl_close(0);
}

#ifdef AOT_RECALL_BINARY

/****************************
 * AoT Recall simple data types
 ****************************/
struct stupid_hashmap {
    void* key;
    void* value;
};
static const size_t max_ptrs = 1000000;
static struct stupid_hashmap ptrs[max_ptrs];
static size_t ptrsCnt;

static void* getPtr(void* orig) {
    for(int i = 0; i < ptrsCnt; i++)
        if(ptrs[i].key == orig)
            return ptrs[i].value;
    return NULL;
}
static void addPtr(void* orig, void* ptr) {
    if(ptrsCnt >= max_ptrs) {
        AOT_RECALL_ERR("failed to load recall image - too many memory fragments");
        exit(1);
    }
    ptrs[ptrsCnt].key = orig;
    ptrs[ptrsCnt].value = ptr;
    ptrsCnt++;
}

/****************************
 * AoT Recall interfaces
 *  In here, wrappers for invoking all support kernel interfaces
 *  is implemented
 ****************************/
#define PRINT_SYSCALL_RESULT(RET)       \
        do {                            \
            if(RET < 0) AOT_RECALL_INFO("\t... ret = %d(%s)", ret, strerror(ret));  \
            else AOT_RECALL_INFO("\t... ret = %d", ret);    \
        } while(0)
#define CHECK_INPUT_ARGS(MIN)           \
        do {                            \
            if(content->argsLen < MIN) {    \
                AOT_RECALL_ERR("failed to execute read syscall - to few arguments in recall file (min=%d, got=%zu)", \
                     MIN, content->argsLen);    \
                return -1;  \
            }   \
        } while(0)

static char* poc_buffers_names[2][6] = {
    {"b", "buf", "buffer", "page", NULL},
    {"b", "buf", "buffer", "page", "input", NULL},
};

#define POC_SHOW_BUFFER_NAMES      poc_buffers_names[0]
#define POC_STORE_BUFFER_NAMES     poc_buffers_names[1]

static struct FL_args* poc_arg_by_names(struct FL_content* content, char** names) {
    int matches_count = 0;
    struct FL_args* match = NULL;

    for(int i = 0; i < content->argsLen; i++) {
        struct FL_args* args = &content->args[i];
        
        for(char** p = names; *p && **p; p++)
            if(!strcmp(*p, args->name)) {
                match = args;
                matches_count++;
            }
    }

    if(matches_count > 1) {
        AOT_RECALL_ERR("while searching for syscall argments multiple matches were found");
        AOT_RECALL_ERR("using the last found one - '%s'", match->name);
    }

    return match;
}

static int poc_call_read(struct FL_content* content, int fd) {
    int ret;
    CHECK_INPUT_ARGS(3);

    struct FL_args* arg_buf = &content->args[content->argsLen - 3];
    struct FL_args* arg_count = &content->args[content->argsLen - 2];
    void* buf = getPtr(arg_buf->ptr);
    size_t* count_ptr = (size_t*) getPtr(arg_count->ptr);

    if(count_ptr == NULL) {
        AOT_RECALL_ERR("failed to extract count parameter");
        return -1;
    }
    size_t count = *count_ptr;

    AOT_RECALL_INFO("executing: read(fd=%d, buf=%p, cnt=%ld) ...", fd, buf, count);
    fflush(stdout); fflush(stderr);

    // Let's roll it!
    ret = read(fd, buf, count);
    PRINT_SYSCALL_RESULT(ret);
    return 0;
}

static int poc_call_write(struct FL_content* content, int fd) {
    int ret;
    CHECK_INPUT_ARGS(3);

    struct FL_args* arg_buf = &content->args[content->argsLen - 3];
    struct FL_args* arg_count = &content->args[content->argsLen - 2];
    void* buf = getPtr(arg_buf->ptr);
    size_t* count_ptr = (size_t*) getPtr(arg_count->ptr);

    if(count_ptr == NULL) {
        AOT_RECALL_ERR("failed to extract count parameter");
        return -1;
    }
    size_t count = *count_ptr;

    AOT_RECALL_INFO("executing: write(fd=%d, buf=%p, cnt=%ld) ...", fd, buf, count);
    fflush(stdout); fflush(stderr);

    // Let's roll it!
    ret = write(fd, buf, count);
    PRINT_SYSCALL_RESULT(ret);
    return 0;
}

static int poc_call_store(struct FL_content* content, int fd) {
    int ret;
    CHECK_INPUT_ARGS(2);

    struct FL_args* arg_buf = poc_arg_by_names(content, POC_STORE_BUFFER_NAMES);
    void* buf = getPtr(arg_buf->ptr);
    
    struct FL_args* arg_count = &content->args[content->argsLen - 1];
    size_t* count_ptr = (size_t*) getPtr(arg_count->ptr);

    if(count_ptr == NULL) {
        AOT_RECALL_ERR("failed to extract count parameter");
        return -1;
    }
    size_t count = *count_ptr;

    if(count < 1)
        count = 1;
    else if(count > 4096)
        count = 4096;

    AOT_RECALL_INFO("executing: store(fd=%d, buf=%p, cnt=%ld) ...", fd, buf, count);
    fflush(stdout); fflush(stderr);

    // Let's roll it!
    ret = write(fd, buf, count);
    PRINT_SYSCALL_RESULT(ret);
    return 0;
}

static int poc_call_show(struct FL_content* content, int fd) {
    int ret;
    CHECK_INPUT_ARGS(2);
    
    struct FL_args* arg_buf = poc_arg_by_names(content, POC_SHOW_BUFFER_NAMES);
    void* buf = getPtr(arg_buf->ptr);

    struct FL_args* arg_count = &content->args[content->argsLen - 1];
    size_t* count_ptr = (size_t*) getPtr(arg_count->ptr);

    if(count_ptr == NULL) {
        AOT_RECALL_ERR("failed to extract count parameter");
        return -1;
    }
    size_t count = *count_ptr;

    if(count < 1)
        count = 1;
    else if(count > 4096)
        count = 4096;

    AOT_RECALL_INFO("executing: show(fd=%d, buf=%p, cnt=%ld) ...", fd, buf, count);
    fflush(stdout); fflush(stderr);

    // Let's roll it!
    ret = read(fd, buf, count);
    PRINT_SYSCALL_RESULT(ret);
    return 0;
}

static int poc_call_ioctl(struct FL_content* content, int fd) {
    int ret;
    CHECK_INPUT_ARGS(2);

    struct FL_args* arg_cmd = &content->args[content->argsLen - 2];
    struct FL_args* arg_arg = &content->args[content->argsLen - 1];
    int cmd = *(int*) getPtr(arg_cmd->ptr);
    void* arg = (void*) getPtr(arg_arg->ptr);

    AOT_RECALL_INFO("executing: ioctl(fd=%d, cmd=%x, arg=%p) ...", fd, cmd, arg);
    fflush(stdout); fflush(stderr);

    // Let's roll it!
    ret = ioctl(fd, cmd, arg);
    PRINT_SYSCALL_RESULT(ret);
    return 0;
}


/****************************
 * Store all supported interfaces in a handy structure
 *  Its much easier to operate on such structure rather than
 *  creating a huge collection of IFs
 ****************************/
struct FL_interface_type {
    const char* name;
    int (*handler)(struct FL_content* content, int fd);
    int open_mode;
};

#define FL_DEFINE_INTERFACE(NAME, MODE)     {.name = #NAME, .handler = poc_call_##NAME, .open_mode = MODE}
#define ARRAY_SIZE(ARR) (sizeof(ARR) / sizeof(ARR[0]))

struct FL_interface_type interfaceTypes[] = {
    FL_DEFINE_INTERFACE(read, O_RDONLY),
    FL_DEFINE_INTERFACE(show, O_RDONLY),
    FL_DEFINE_INTERFACE(write, O_WRONLY),
    FL_DEFINE_INTERFACE(store, O_WRONLY),
    FL_DEFINE_INTERFACE(ioctl, O_RDONLY),
};


/****************************
 * AoT Recall Entry Point
 *  In here, the entry point for AoT Recall is implemented.
 *  This sections is only accessible from binary aot_poc_run
 ****************************/

static struct FL_interface_type* get_interface(struct FL_content* content) {
    for(int i = 0; i < content->othersLen; i++) {
        struct FL_other* other = &content->others[i];
        if(other->type == RECALL_FL_OTHER_TYPES_INTERFACE) {

            for(int j = 0; j < ARRAY_SIZE(interfaceTypes); j++)
                if(!strcmp(interfaceTypes[j].name, other->value))
                    return &interfaceTypes[j];

            AOT_RECALL_ERR("unknown kernel interface requested \"%s\"", other->value);
            break;
        }
    }
    return NULL;
}

static int recreate_memory(struct FL_content* content) {
    for(int i = 0; i < content->dataLen; i++) {
        struct FL_data* data = &content->data[i];

        // 1. Allocate and fill the memory
        void* ptr = malloc(data->size);
        if(ptr == NULL) {
            AOT_RECALL_ERR("failed to allocate memory (%d)%s", errno, strerror(errno));
            return -1;
        }
        memcpy(ptr, data->data, data->size);
        addPtr(data->dst, ptr);

        // 2. Check taints and update memories
        void* other = getPtr(data->src);
        while(other != NULL) {
            memcpy(other, ptr, data->size);

            other = getPtr(other);
        }

        // 3. Fix pointers (TODO)
    }

    return 0;
}

static int call_kernel(struct FL_content* content, struct FL_interface_type* interface, char* node) {
    int ret;

    int fd = open(node, interface->open_mode);
    if(fd < 0) {
        AOT_RECALL_ERR("failed to open node \"%s\" (%d)%s", node, errno, strerror(errno));
        return -1;
    }

    ret = interface->handler(content, fd);

    close(fd);
    return ret;
}

static int aot_total_recall_entry(int argc, char** argv) {
    struct FL_content content;
    char* input_file, *node;
    struct FL_interface_type* interface;

    AOT_RECALL_INFO("started");

    if(argc != 3) {
        AOT_RECALL_ERR("incorrect arguments were provided");
        fprintf(stderr, "Usage: %s <recall file> <node path>\n", argv[0]);
        return 1;
    }

    input_file = argv[1];
    node = argv[2];

    if(fl_open(input_file)) {
        AOT_RECALL_ERR("failed to open recall file \"%s\"", input_file);
        return 1;
    }

    if(fl_load(&content)) {
        AOT_RECALL_ERR("failed to load recall file \"%s\"", input_file);
        return 1;
    }

    // fl_print(&content);

    if((interface = get_interface(&content)) == NULL) {
        AOT_RECALL_ERR("failed to extract interface from recall file");
        return 1;
    }

    if(recreate_memory(&content)) {
        AOT_RECALL_ERR("failed to recreate memory from recall file");
        return 1;
    }

    if(call_kernel(&content, interface, node)) {
        AOT_RECALL_ERR("failed to invoke kernel syscall");
        return 1;
    }

    AOT_RECALL_INFO("finished");
    return 0;
}

__attribute__ ((constructor)) int aot_total_recall_entry_raw(int argc, char** argv) {
    int ret = aot_total_recall_entry(argc, argv);

    // Remember to do exit! Otherwise we would jump to the real main
    exit(ret);
}

#endif
