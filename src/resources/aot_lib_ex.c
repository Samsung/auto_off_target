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
static inline unsigned char *aot_skb_end_pointer(const struct sk_buff *skb)
{
	return skb->head + skb->end;
}
static void aot_refcount_inc(refcount_t *t) {
    t->refs.counter++;
}
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask) {
    struct sk_buff *n;
    
    n = malloc(sizeof(struct sk_buff));
    if (!n)
        return 0;

    memcpy(n, skb, sizeof(struct sk_buff));
    n->fclone = SKB_FCLONE_UNAVAILABLE;
    n->next = n->prev = 0;
    n->sk = 0;
    n->slow_gro = 0;
    n->slow_gro |= !!(skb->_skb_refdst);
    if (skb->active_extensions) {
        aot_refcount_inc(&skb->extensions->refcnt);
        n->extensions = skb->extensions;
    }
    n->hdr_len = skb->nohdr ? (skb->data-skb->head) : skb->hdr_len;
    n->cloned = 1;
  	n->nohdr = 0;
  	n->peeked = 0;
    n->destructor = 0;
    aot_refcount_inc(&n->users);
    (((struct skb_shared_info*)aot_skb_end_pointer(skb))->dataref).counter++;
    skb->cloned = 1;

    return n;
}
#endif

#ifdef AOT_DOWN_READ
void down_read(struct rw_semaphore *sem) {
    return;
}
#endif

#ifdef AOT_UP_READ
void up_read(struct rw_semaphore *sem) {
    return;
}
#endif

#ifdef AOT_NETLINK_RCV_SKB
int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *, struct nlmsghdr *, struct netlink_ext_ack *)) {
    struct netlink_ext_ack extack;
    struct nlmsghdr *nlh;
    int err;

    while (skb->len >= 16) {
        int msglen;

        memset(&extack, 0, sizeof(extack));
        nlh = (struct nlmsghdr *)skb->data;
        
        if (nlh->nlmsg_len < 16 || skb->len < nlh->nlmsg_len)
  			return 0;

        if (!(nlh->nlmsg_flags & 0x01) || nlh->nlmsg_type < 0x10)
            return 0;

        err = cb(skb, nlh, &extack);

        msglen = (nlh->nlmsg_len + 3) & ~(3);
        if (msglen > skb->len)
            msglen = skb->len;
        
        skb->len -= msglen;
        skb->data += msglen;
    }
}
#endif
