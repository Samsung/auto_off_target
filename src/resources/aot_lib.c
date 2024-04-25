/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

// This file contains stubs for generic functions used in many off-targets.
// Name of each function added here should be listed in src/lib_functions.
// When generating off-target only declarations for these will be emited.

#define AOT_LIB_EX

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include "aot_lib.h"
#include "aot_fuzz_lib.h"

void* malloc(size_t size);
void free(void* ptr);

#define AOT_MEMDUP_USER_MAX_SIZE (128 * 1024 * 1024) // 128 MB

#ifdef AOT_MEMDUP_USER
void *memdup_user(const void * _src, size_t len) {
    if (len > AOT_MEMDUP_USER_MAX_SIZE) 
        return (void *)(-12);
    void* p = malloc(len);
    // See a comment in copy_from_user implementation
    fuzz_that_data(p, _src, len, 0);
    aot_tag_memory(p, len, 0);
    return p;
}
#endif

#ifdef AOT_MEMDUP_USER_NUL
void *memdup_user_nul(const void * _src, unsigned long len) {
    if (len > AOT_MEMDUP_USER_MAX_SIZE) 
        return (void *)(-12);
    char* p = malloc(len + 1);
    if(p) {
        fuzz_that_data(p, _src, len, 0);
        p[len] = '\0';
        aot_tag_memory(p, len + 1, 0);
    }
    return p;
}
#endif

#ifdef AOT_KMEMDUP
void* kmemdup(const void* src, unsigned long long len, unsigned long flags) {
    if(len > AOT_MEMDUP_USER_MAX_SIZE)
        return (void *)(-12);
    char* p = malloc(len);
    if(p)
        memcpy(p, src, len);
    return p;
}
#endif

#ifdef AOT_VMEMDUP_USER
void *vmemdup_user(const void * _src, unsigned long len) {
    if (len > AOT_MEMDUP_USER_MAX_SIZE) 
        return (void *)(-12);
    char* p = malloc(len);
    if(!p)
        return (void *)(-12);
    fuzz_that_data(p, _src, len, 0);
    aot_tag_memory(p, len, 0);
    return p;
}
#endif

#ifdef AOT_KREALLOC
void* krealloc(const void* p, unsigned long new_size, unsigned long flags) {
    if(new_size == 0){
        free(p);
        return (void*)0x10;
    }
    if (new_size > AOT_MEMDUP_USER_MAX_SIZE) 
        return (void *)(-12);

    return realloc(p, new_size);
}
#endif

unsigned long aot_copy_from_user(void* to, const void* from, unsigned long n) {
    // in copy from user we will just return a fuzzer-generated data 
    // if we're not fuzzing, that will be just zero-initialized memory
    // "from" is not important from the security standpoint as an incorrect pointer
    // would have been filtered out by the real copy_from_user anyways
    // "to" should be able to store the data copied from the user
    fuzz_that_data(to, (void*)from, n, 0);
    aot_tag_memory(to, n, 0);
    return 0;
}

#ifdef AOT_COPY_FROM_USER
unsigned long copy_from_user(void *to, const void *from , unsigned long n){
    return aot_copy_from_user(to, from, n);
}
#endif

#ifdef AOT___COPY_FROM_USER
unsigned long __copy_from_user(void *to, const void *from , unsigned long n){
    return aot_copy_from_user(to, from, n);
}
#endif

static char largebuffer[0xFFFF];
unsigned long aot_copy_to_user(void* to, const void* from, unsigned long n) {
    // It might be better to ignore memcpy destination in copy_to_user -> it doesn't change much 
    // from the security standpoint and could introduce FPs: e.g. there is a pattern
    // in which unsigned long args are casted to pointers which might be hard
    // to detect and initialize automatically

    // one thing to consider - depending on what's the current test case - is to try
    // catching info leaks in copy_to_user
    
    // in order to find out if we are not oveflowing the "from" buffer, we will
    // copy the data to local buffer
    unsigned long offset = 0;

    while(n > 0) {
        unsigned long copy_size = n < sizeof(largebuffer) ? n : sizeof(largebuffer);
        memcpy(largebuffer, (char*)from + offset, copy_size);
        n -= copy_size;
        offset += copy_size;
    }
    return 0;
}

#ifdef AOT_COPY_TO_USER
unsigned long copy_to_user(void *to, const void *from, unsigned long n){
    return aot_copy_to_user(to, from, n);
}
#endif

#ifdef AOT___COPY_TO_USER
unsigned long __copy_to_user(void *to, const void *from, unsigned long n){
    return aot_copy_to_user(to, from, n);
}
#endif

#ifdef AOT_KMALLOC
void* kmalloc(unsigned long size, unsigned flags) {
    return malloc(size);    
}
#endif

#ifdef AOT___KMALLOC
void* __kmalloc(unsigned long size, unsigned flags) {
    return malloc(size);    
}
#endif

#ifdef AOT_KZALLOC
void* kzalloc(unsigned long size, unsigned flags) {
    void* ptr = malloc(size);
    memset(ptr, 0, size);
    return ptr;
}
#endif

#ifdef AOT_KVMALLOC_NODE
void* kvmalloc_node(unsigned long long size, unsigned long flags, int node) {
    return malloc(size);
}
#endif

#ifdef AOT_KMALLOC_NODE
void* kmalloc_node(unsigned long long size, unsigned long flags, int node) {
    return malloc(size);
}
#endif

#ifdef AOT_DEVM_KMALLOC
void* devm_kmalloc(void* dev, unsigned long size, unsigned long flags) {
    return malloc(size);
}
#endif

#ifdef AOT_PCPU_ALLOC
void* pcpu_alloc(unsigned long size, unsigned long align, int reserved, unsigned long flags) {
    return malloc(size);
}
#endif

#ifdef AOT_FREE_PERCPU
void free_percpu(void* ptr) {
    free(ptr);
}
#endif

#ifdef AOT_KFREE
void kfree(const void* ptr) {
    if ((unsigned long)(ptr) <= ((unsigned long)(void*)16))
        return;

    free(ptr);
}
#endif

#ifdef AOT_KVFREE
void kvfree(const void *addr) {
    if ((unsigned long)(addr) <= ((unsigned long)(void*)16))
        return;
        
    free(addr);
}
#endif

#ifdef AOT_PRINTK
int printk(const char *fmt, ...) {
    va_list args;
    int ret = 0;

    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);

    return ret;
}
#endif

#ifdef AOT__PRINTK
int _printk(const char *fmt, ...) {
    va_list args;
    int ret = 0;

    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);

    return ret;
}
#endif



#ifdef AOT_MUTEX_LOCK
void mutex_lock(void* m) {
    // no locking 
}
#endif

#ifdef AOT_MUTEX_UNLOCK
void mutex_unlock(void *m) {
    // no unlocking
}
#endif

#ifdef AOT_MUTEX_LOCK_NESTED
void mutex_lock_nested(void* m, unsigned int subclass) {
    // no unlocking
}
#endif

#ifdef AOT_SPIN_LOCK
void spin_lock(void* l) {
    // no locking
}
#endif

#ifdef AOT_SPIN_LOCK_BH
void spin_lock_bh(void* l) {
    // no locking
}
#endif

#ifdef AOT_SPIN_UNLOCK
void spin_unlock(void* l) {
    // no unlocking
}
#endif

#ifdef AOT_SPIN_UNLOCK_BH
void spin_unlock_bh(void* l) {
    // no unlocking
}
#endif

#ifdef AOT_SPIN_UNLOCK_IRQRESTORE
void spin_unlock_irqrestore(void* l, unsigned long flags) {
    // no unlocking
}
#endif

#ifdef AOT__RAW_SPIN_LOCK_IRQSAVE
unsigned long _raw_spin_lock_irqsave(void* l) {
    // no locking
    return 0;
}
#endif

#ifdef AOT__RAW_SPIN_UNLOCK_IRQRESTORE
void _raw_spin_unlock_irqrestore(void *lock, unsigned long flags) {
    // no unlocking
}
#endif

#ifdef AOT___MIGHT_SLEEP
void __might_sleep(const char *file, int line) {

}
#endif

#ifdef AOT_KSTRDUP
char* kstrdup(const char* s, unsigned flags) {
    unsigned long long len;
    char* buf;

    if (!s)
        return 0;

    len = strlen(s) + 1;
    buf = malloc(len);
    if (buf)
        memcpy(buf, s, len);
    return buf;
}
#endif

#ifdef AOT_KSTRNDUP
char* kstrndup(const char* s, unsigned long max, unsigned flags) {
    unsigned long long len;
    char* buf;

    if (!s)
        return 0;

    len = strnlen(s, max);
    buf = malloc(len + 1);
    if (buf) {
        memcpy(buf, s, len);
        buf[len] = '\0';
    }
    return buf;
}
#endif

#ifdef AOT_STRLCPY
// source: https://android.googlesource.com/platform/system/core.git/+/master/libcutils/strlcpy.c
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Implementation of strlcpy() for platforms that don't already have it. */
/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;
    /* Copy as many bytes as will fit */
    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
  }
    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';		/* NUL-terminate dst */
        while (*s++)
            ;
    }
    return(s - src - 1);	/* count does not include NUL */
}

#endif

#ifdef AOT_VMALLOC
void* vmalloc(unsigned long size) {
    return malloc(size);
}
#endif

#ifdef AOT_VZALLOC
void* vzalloc(unsigned long size) {
    void* mem = malloc(size);
    if(mem)
        memset(mem, 0, size);
    return mem;
}
#endif

#ifdef AOT_VFREE
void vfree(void* mem) {
    free(mem);
}
#endif

#ifdef AOT_SCHED_CLOCK
unsigned long long sched_clock(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return tp.tv_sec + tp.tv_nsec * 1000000000ULL; /* 10e9 */
}
#endif

#ifdef AOT_KTIME_GET_MONO_FAST_NS
unsigned long long ktime_get_mono_fast_ns(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return tp.tv_sec + tp.tv_nsec * 1000000000ULL; /* 10e9 */
}
#endif

#ifdef AOT_KTIME_GET
unsigned long long ktime_get(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return tp.tv_sec + tp.tv_nsec * 1000000000ULL; /* 10e9 */
}
#endif

#ifdef AOT_USLEEP_RANGE_STATE
void usleep_range_state(unsigned long min, unsigned long max, unsigned int state) {
    return;
}
#endif

#ifdef AOT_CLEAR_PAGE
void clear_page(void* to) {
    memset(to, 0, 4096 /* PAGE_SIZE */);
}
#endif

#ifdef AOT_PANIC
void panic(const char* fmt, ...) {
    /* Crash application */
    volatile int* ptr = 0; 
    *ptr = 0;
}
#endif

#ifdef AOT___KMALLOC_NODE_TRACK_CALLER
void* __kmalloc_node_track_caller(unsigned long size, unsigned int flags, 
                                int node, unsigned long caller) {
    return malloc(size);
}
#endif 

#ifdef AOT_MEMCHR_INV
/* Returns pointer to the first byte other than 'c' or NULL if there're only 'c' */
void* memchr_inv(const void* start, int c, unsigned long bytes) {
    const char* ptr = (const char*) start;

    for(unsigned long i = 0; i < bytes; i++) {
        if(ptr[i] != c)
            return &ptr[i]; 
    }
    return NULL;
}
#endif

#ifdef AOT___KERN_MY_CPU_OFFSET
unsigned long __kern_my_cpu_offset(void) {
    return 0;   /* off-targets always assume that per_cpu vars offset is 0 */
}
#endif

/*
 * Atomic variables support: for now we implement atomic operations using their
 *  plain C equivalent. If in future we'd like to test for race conditions in OTs,
 *  these will need to be updated to proper atomics.
 */
#ifdef AOT_ARCH_ATOMIC64_ADD
void arch_atomic64_add(long i, long long* v) {
    *v += i;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_ADD_RETURN
long long arch_atomic64_add_return(long i, long long* v) {
    *v += i;
    return *v;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_ANDNOT
void arch_atomic64_andnot(long i, long long* v) {
    *v &= ~i;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_DEC
void arch_atomic64_dec(long long* v) {
    *v -= 1;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_INC
void arch_atomic64_inc(long long* v) {
    *v += 1;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_INC_RETURN
long long arch_atomic64_inc_return(long long* v) {
    *v += 1;
    return *v;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_OR
void arch_atomic64_or(long i, long long* v) {
    *v |= i;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_SUB
void arch_atomic64_sub(long i, long long* v) {
    *v -= i;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_SUB_RETURN
long long arch_atomic64_sub_return(long i, long long* v) {
    *v -= i;
    return *v;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_ANDNOT
long long arch_atomic64_fetch_andnot(long i, long long* v) {
    long long old = *v;
    *v &= ~i;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_ANDNOT_RELEASE
long long arch_atomic64_fetch_andnot_release(long i, long long* v) {
    long long old = *v;
    *v &= ~i;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_FETCH_OR
long long arch_atomic64_fetch_or(long i, long long* v) {
    long long old = *v;
    *v |= i;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC64_TRY_CMPXCHG
int arch_atomic64_try_cmpxchg(long long* v, long long* oldp, long long new) {
    long long ret = *v, old = *oldp;
    
    if(ret == old)
        *v = new;
    if(ret != old)
        *oldp = ret;
    return ret == old;
}
#endif


#ifdef AOT_ARCH_ATOMIC_ADD_RETURN
int arch_atomic_add_return(int i, int* val) {
    *val += i;
    return *val;
}
#endif

#ifdef AOT_ARCH_ATOMIC_ADD
void arch_atomic_add(int i, int* val) {
    *val += i;
}
#endif

#ifdef AOT_ARCH_ATOMIC_ADD_UNLESS
int arch_atomic_add_unless(int* v, int a, int u) {
    int old = *v;
    if(*v != u)
        *v += a;
    return old != *v;
}
#endif

#ifdef AOT_ARCH_ATOMIC_INC
void arch_atomic_inc(int* val) {
    *val += 1;
}
#endif

#ifdef AOT_ARCH_ATOMIC_INC_RETURN
int arch_atomic_inc_return(int* val) {
    *val += 1;
    return *val;
}
#endif

#ifdef AOT_ARCH_ATOMIC_SUB
void arch_atomic_sub(int i, int* val) {
    *val -= i;
}
#endif

#ifdef AOT_ARCH_ATOMIC_SUB_RETURN
int arch_atomic_sub_return(int i, int* val) {
    *val -= i;
    return *val;
}
#endif

#ifdef AOT_ARCH_ATOMIC_DEC
void arch_atomic_dec(int* v) {
    *v -= 1;
}
#endif

#ifdef AOT_ARCH_ATOMIC_DEC_RETURN
int arch_atomic_dec_return(int* v) {
    *v -= 1;
    return *v;
}
#endif

#ifdef AOT_ARCH_ATOMIC_DEC_AND_TEST
int arch_atomic_dec_and_test(int* v) {
    *v -= 1;
    return *v == 0;
}
#endif

#ifdef AOT_ARCH_ATOMIC_FETCH_ADD_UNLESS
int arch_atomic_fetch_add_unless(int* v, int a, int u) {
    int old = *v;
    if(*v != u)
        *v += a;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC_FETCH_ADD_RELAXED
int arch_atomic_fetch_add_relaxed(int i, int* v) {
    int old = *v;
    *v += i;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC_FETCH_SUB_RELEASE
int arch_atomic_fetch_sub_release(int i, int* v) {
    int old = *v;
    *v -= i;
    return old;
}
#endif

#ifdef AOT_ARCH_ATOMIC_TRY_CMPXCHG
int arch_atomic_try_cmpxchg(int* v, int* oldp, int new) {
    int ret = *v, old = *oldp;
    
    if(ret == old)
        *v = new;
    if(ret != old)
        *oldp = ret;
    return ret == old;
}
#endif

#ifdef AOT_ARCH_ATOMIC_TRY_CMPXCHG_RELAXED
int arch_atomic_try_cmpxchg_relaxed(int* v, int* oldp, int new) {
    int ret = *v, old = *oldp;
    
    if(ret == old)
        *v = new;
    if(ret != old)
        *oldp = ret;
    return ret == old;
}
#endif

#ifdef AOT_DUMP_STACK
void dump_stack(void) {
    return;
}
#endif

#ifdef AOT___PRINTK_RATELIMIT
int __printk_ratelimit(const char* func) {
    return 0;    
}
#endif

#ifdef AOT_VPRINTK_DEFERRED
int vprintk_deferred(const char* fmt, va_list args) {
    int ret = vprintk(fmt, args);
    return ret;
}
#endif

#ifdef AOT_VPRINTK_DEFAULT
int vprintk_default(const char* fmt, va_list args) {
    int ret = vprintk(fmt, args);
    return ret;
}
#endif

#ifdef AOT_VPRINTK
int vprintk(const char* fmt, va_list args) {
    int ret = vprintk(fmt, args);
    return ret;
}
#endif

#ifdef AOT_SCHEDULE
void schedule(void) {
    return;
}
#endif

#ifdef AOT_SCHEDULE_TIMEOUT
signed long schedule_timeout(signed long timeout) {
    return 0;
}
#endif

#ifdef AOT_PREEMPT_SCHEDULE
void preempt_schedule(void) {
    return;
}
#endif

#ifdef AOT_PREEMPT_SCHEDULE_NOTRACE
void preempt_schedule_notrace(void) {
    return;
}
#endif

#ifdef AOT_SCHED_DYNAMIC_UPDATE
void sched_dynamic_update(int mode) {
    return;    
}
#endif

#ifdef AOT_MSLEEP
void msleep(unsigned int msecs) {
    return;    
}
#endif

#ifdef AOT_TRACE_HARDIRQS_ON
void trace_hardirqs_on(void) {
    return;    
}
#endif

#ifdef AOT_TRACE_HARDIRQS_OFF
void trace_hardirqs_off(void) {
    return;    
}
#endif

#ifdef AOT_CT_IRQ_ENTER
void ct_irq_enter(void) {
    return;    
}
#endif

#ifdef AOT_CT_IRQ_EXIT
void ct_irq_exit(void) {
    return;    
}
#endif

#ifdef AOT_CT_IRQ_ENTER_IRQSON
void ct_irq_enter_irqson(void) {
    return;    
}
#endif

#ifdef AOT_CT_IRQ_EXIT_IRQSON
void ct_irq_exit_irqson(void) {
    return;    
}
#endif

#ifdef AOT_CT_NMI_ENTER
void ct_nmi_enter(void) {
    return;    
}
#endif

#ifdef AOT_CT_NMI_EXIT
void ct_nmi_exit(void) {
    return;    
}
#endif