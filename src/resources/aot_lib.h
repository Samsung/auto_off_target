/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#include "aot_log.h"

#ifdef AOT_GET_CURRENT
__attribute__((gnu_inline)) __attribute__((unused)) __attribute__((no_instrument_function)) __attribute__((always_inline)) static inline struct task_struct* get_current() {
    static unsigned char buffer[8192] = { 0 };
    return (struct task_struct*) buffer;
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

#ifdef AOT_FLS
static inline int fls(unsigned int x) {
    if(x == 0)
        return 0;
    return 32 - __builtin_clz(x);
}
#endif

void* malloc(typeof(sizeof(int)) size);
void free(void* ptr);

#ifdef AOT_MEMDUP_USER
void *memdup_user(const void * _src, typeof(sizeof(int)) len);
#endif

#ifdef AOT_MEMDUP_USER_NUL
void *memdup_user_nul(const void * _src, unsigned long len);
#endif

#ifdef AOT_KMEMDUP
void* kmemdup(const void* src, unsigned long long len, unsigned long flags) ;
#endif

#ifdef AOT_VMEMDUP_USER
void *vmemdup_user(const void * _src, unsigned long len);
#endif

#ifdef AOT_KREALLOC
void* krealloc(const void* p, unsigned long new_size, unsigned long flags);
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

#ifdef AOT_KVMALLOC_NODE
void* kvmalloc_node(unsigned long long size, unsigned long flags, int node);
#endif

#ifdef AOT_KMALLOC_NODE
void* kmalloc_node(unsigned long long size, unsigned long flags, int node);
#endif

#ifdef AOT_DEVM_KMALLOC
void* devm_kmalloc(void* dev, unsigned long size, unsigned long flags);
#endif

#ifdef AOT_PCPU_ALLOC
void* pcpu_alloc(unsigned long size, unsigned long align, int reserved, unsigned long flags);
#endif

#ifdef AOT_FREE_PERCPU
void free_percpu(void* ptr);
#endif

#ifdef AOT_KFREE
void kfree(const void* ptr);
#endif

#ifdef AOT_KVFREE
void kvfree(const void* addr);
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

#ifdef AOT_MUTEX_LOCK_NESTED
void mutex_lock_nested(void* m, unsigned int subclass);
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

#ifdef AOT_VMALLOC
void* vmalloc(unsigned long size);
#endif

#ifdef AOT_VZALLOC
void* vzalloc(unsigned long size);
#endif

#ifdef AOT_VFREE
void vfree(void* mem);
#endif

#ifdef AOT_SCHED_CLOCK
unsigned long long sched_clock(void);
#endif

#ifdef AOT_KTIME_GET_MONO_FAST_NS
unsigned long long ktime_get_mono_fast_ns(void);
#endif

#ifdef AOT_KTIME_GET
unsigned long long ktime_get(void);
#endif

#ifdef AOT_USLEEP_RANGE_STATE
void usleep_range_state(unsigned long min, unsigned long max, unsigned int state);
#endif

#ifdef AOT_MSLEEP
void msleep(unsigned int msecs);
#endif

#ifdef AOT_CLEAR_PAGE
void clear_page(void* to);
#endif

#ifdef AOT_PANIC
void panic(const char* fmt, ...);
#endif

#ifdef AOT____KMALLOC_NODE_TRACK_CALLER
void* __kmalloc_node_track_caller(unsigned long size, unsigned int flags, 
                                int node, unsigned long caller);
#endif

#ifdef AOT_MEMCHR_INV
void* memchr_inv(const void* start, int c, unsigned long bytes);
#endif

#ifdef AOT___KERN_MY_CPU_OFFSET
unsigned long __kern_my_cpu_offset(void);
#endif

#ifdef AOT_ARCH_ATOMIC64_ADD
void arch_atomic64_add(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_ADD_RETURN
long long arch_atomic64_add_return(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_ANDNOT
void arch_atomic64_andnot(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_DEC
void arch_atomic64_dec(long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_INC
void arch_atomic64_inc(long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_INC_RETURN
long long arch_atomic64_inc_return(long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_OR
void arch_atomic64_or(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_SUB
void arch_atomic64_sub(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_SUB_RETURN
long long arch_atomic64_sub_return(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_ANDNOT
long long arch_atomic64_fetch_andnot(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_ANDNOT_RELEASE
long long arch_atomic64_fetch_andnot_release(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_OR
long long arch_atomic64_fetch_or(long i, long long* v);
#endif

#ifdef AOT_ARCH_ATOMIC64_TRY_CMPXCHG
int arch_atomic64_try_cmpxchg(long long* v, int64_t* oldp, int64_t new);
#endif


#ifdef AOT_ARCH_ATOMIC_ADD_RETURN
int arch_atomic_add_return(int i, int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_ADD
void arch_atomic_add(int i, int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_ADD_UNLESS
int arch_atomic_add_unless(int* v, int a, int u);
#endif

#ifdef AOT_ARCH_ATOMIC_INC
void arch_atomic_inc(int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_INC_RETURN
int arch_atomic_inc_return(int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_SUB
void arch_atomic_sub(int i, int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_SUB_RETURN
int arch_atomic_sub_return(int i, int* val);
#endif

#ifdef AOT_ARCH_ATOMIC_DEC
void arch_atomic_dec(int* v);
#endif

#ifdef AOT_ARCH_ATOMIC_DEC_RETURN
int arch_atomic_dec_return(int* v);
#endif

#ifdef AOT_ARCH_ATOMIC_DEC_AND_TEST
int arch_atomic_dec_and_test(int* v);
#endif

#ifdef AOT_ARCH_ATOMIC_FETCH_ADD_UNLESS
int arch_atomic_fetch_add_unless(int* v, int a, int u);
#endif

#ifdef AOT_ARCH_ATOMIC_FETCH_ADD_RELAXED
int arch_atomic_fetch_add_relaxed(int i, int* v);
#endif

#ifdef AOT_ARCH_ATOMIC_TRY_CMPXCHG
int arch_atomic_try_cmpxchg(int* v, int* old, int new);
#endif

#ifdef AOT_ARCH_ATOMIC_TRY_CMPXCHG_RELAXED
int arch_atomic_try_cmpxchg_relaxed(int* v, int* old, int new);
#endif

#ifdef AOT_KMEM_CACHE_ALLOC
void* kmem_cache_alloc(void* cache, unsigned long flags);
#endif

#ifdef AOT_KMEM_CACHE_FREE
void kmem_cache_free(void* s, void* x);
#endif
