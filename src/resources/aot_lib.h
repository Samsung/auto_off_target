/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#include "aot_log.h"

#ifdef AOT_GET_CURRENT
__attribute__((gnu_inline)) __attribute__((unused)) __attribute__((no_instrument_function)) __attribute__((always_inline)) static inline struct task_struct* get_current() {
    static unsigned char buffer[4096] = { 0 };
    return buffer;
}
#endif

#ifdef AOT_CAPABLE
typedef _Bool bool;
static inline bool capable(int cap) {
    return 1;
}
#endif

#ifdef AOT___RANGE_OK
__attribute__((gnu_inline)) __attribute__((unused)) __attribute__((no_instrument_function)) static inline unsigned long __range_ok(const void* addr, unsigned long size) {
    aot_log_msg("__range_ok -> assuming success\n");
    return 1;
}
#endif

#ifdef  AOT_ACCESS_OK
static inline int access_ok(const void* addr, unsigned long size) {
    aot_log_msg("access_ok -> assuming success\n");
    return 1;
}
#endif

void* malloc(typeof(sizeof(int)) size);
void free(void* ptr);

#ifdef AOT_MEMDUP_USER
void *memdup_user(const void * _src, typeof(sizeof(int)) len);
#endif

#ifdef AOT_COPY_FROM_USER
unsigned long copy_from_user(void *to, const void *from , unsigned long n);
#endif

#ifdef AOT___COPY_FROM_USER
unsigned long __copy_from_user(void *to, const void *from , unsigned long n);
#endif

#ifdef AOT_COPY_TO_USER
unsigned long copy_to_user(void *to, const void *from, unsigned long n);
#endif

#ifdef AOT___COPY_TO_USER
unsigned long __copy_to_user(void *to, const void *from, unsigned long n);
#endif

#ifdef AOT_KMALLOC
void* kmalloc(unsigned long size, unsigned flags);
#endif

#ifdef AOT___KMALLOC
void* __kmalloc(unsigned long size, unsigned flags);
#endif

#ifdef AOT_KZALLOC
void* kzalloc(unsigned long size, unsigned flags);
#endif

#ifdef AOT_KFREE
void kfree(const void* ptr);
#endif

#ifdef AOT_PRINTK
int printk(const char *fmt, ...);
#endif

#ifdef AOT__PRINTK
int _printk(const char *fmt, ...);
#endif

#ifdef AOT_MUTEX_LOCK
void mutex_lock(void* m);
#endif

#ifdef AOT_MUTEX_UNLOCK
void mutex_unlock(void *m);
#endif

#ifdef AOT_SPIN_LOCK
void spin_lock(void* l);
#endif

#ifdef AOT_SPIN_LOCK_BH
void spin_lock_bh(void* l);
#endif

#ifdef AOT_SPIN_UNLOCK
void spin_unlock(void* l);
#endif

#ifdef AOT_SPIN_UNLOCK_BH
void spin_unlock_bh(void* l);
#endif

#ifdef AOT_KSTRDUP
char* kstrdup(const char* s, unsigned flags);
#endif

#ifdef AOT_KSTRNDUP
char* kstrndup(const char* s, unsigned long max, unsigned flags);
#endif

#ifdef AOT_STRLCPY
typeof(sizeof(int)) strlcpy(char *dst, const char *src, typeof(sizeof(int)) siz);
#endif
