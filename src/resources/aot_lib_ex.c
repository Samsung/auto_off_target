/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
 */

// This file contains stubs for generic functions that require types defined in
//  "aot.h". We cannot simply include "aot.h" in main "aot_lib.c" as it would
//  cause type clashes with standard C library included in there.

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
void call_rcu(struct callback_head* head, rcu_callback_t func) {
    func(head);
}
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

#ifdef AOT_SKB_CLONE
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask) {
    struct sk_buff *n;
    
    n = malloc(sizeof(struct sk_buff));
    if (!n)
        return NULL;

    memcpy(n, skb, sizeof(struct sk_buff));
    n->fclone = SKB_FCLONE_UNAVAILABLE;
    n->next = n->prev = NULL;
    n->sk = NULL;
    n->slow_gro = 0;
    n->slow_gro |= !!(skb->_skb_refdst);
    if (skb->active_extensions) {
        skb->extensions->refcnt += 1;
        n->extensions = skb->extensions;
    }
    n->hdr_len = skb->nohdr ? (skb->data-skb->head) : skb->hdr_len;
    n->cloned = 1;
  	n->nohdr = 0;
  	n->peeked = 0;
    n->destuctor = NULL;
    n->users += 1
    (skb->((struct skb_shared_info *)(skb->head + skb->end)))->dataref += 1;
    skb->cloned = 1;

    return n;
}
#endif