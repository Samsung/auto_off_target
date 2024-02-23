/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

// This file contains stubs for generic functions used in many off-targets.
// Name of each function added here should be listed in src/lib_functions.
// When generating off-target only declarations for these will be emited.

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include "aot_lib.h"
#include "aot_fuzz_lib.h"

void* malloc(size_t size);
void free(void* ptr);

#ifdef AOT_MEMDUP_USER
#define AOT_MEMDUP_USER_MAX_SIZE (128 * 1024 * 1024) // 128 MB

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
    // copy the data to an arbitrary large buffer (should be large enough in most cases)
    memcpy(largebuffer, from, n);
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

#ifdef AOT_KFREE
void kfree(const void* ptr) {
    if ((unsigned long)(ptr) <= ((unsigned long)(void*)16))
        return;

    free(ptr);
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
    return tp.tv_sec + tp.tv_nsec * 1'000'000'000ULL;
}
#endif
