/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
 */

// This file contains stubs for generic functions that require types defined in
//  "aot.h". We cannot simply include "aot.h" in main "aot_lib.c" as it would
//  cause type clashes with standard C library included in there.

#define AOT_LIB_EX

#include "aot.h"
#include "aot_lib.h"

#ifdef AOT_KMEM_CACHE_ALLOC
void* kmem_cache_alloc(void* cache, unsigned long flags) {
    struct kmem_cache *s = (struct kmem_cache*) cache;
    return malloc(s->object_size);
}
#endif

#ifdef AOT_KMEM_CACHE_FREE
void kmem_cache_free(void* s, void* x) {
    free(x);
}
#endif

#ifdef AOT_LOCK_ACQUIRE
void lock_acquire(struct lockdep_map* lock, unsigned int subclass, int trylock,
                int read, int check, struct lockdep_map* nest_lock, unsigned long ip) {
    return;
}
#endif

#ifdef AOT_LOCK_RELEASE
void lock_release(struct lockdep_map* lock, unsigned long ip) {
    return;
}
#endif

#ifdef AOT_CALL_RCU
#ifndef AOT_LIB_EX
void call_rcu(struct rcu_head* head, rcu_callback_t func) {
    func(head);
}
#endif
#endif

#ifdef AOT_DO_RAW_SPIN_LOCK
void do_raw_spin_lock(raw_spinlock_t* lock) {
    return;    
}
#endif

#ifdef AOT_DO_RAW_SPIN_UNLOCK
void do_raw_spin_unlock(raw_spinlock_t* lock) {
    return;    
}
#endif

#ifdef AOT___KFREE_SKB
void __kfree_skb(struct sk_buff* skb) {
    free(skb);
}
#endif

#ifdef AOT___ALLOC_SKB
struct sk_buff* __alloc_skb(unsigned int size, unsigned int mask, int flags, int node) {
    return (struct sk_buff*)malloc(size + sizeof(struct sk_buff));
};
#endif

#ifdef AOT_DEVICE_INITIALIZE
void device_initialize(struct device* dev) {
    return;
}
#endif