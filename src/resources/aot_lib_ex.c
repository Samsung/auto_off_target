/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
 */

// This file contains stubs for generic functions that require types defined in
//  "aot.h". We cannot simply include "aot.h" in main "aot_lib.c" as it would
//  cause type clashes with standard C library included in there.

#include "aot_lib.h"
#include "aot.h"

#ifdef AOT_KMEM_CACHE_ALLOC
void* kmem_cache_alloc(void* cache, unsigned long flags) {
    struct kmem_cache *s = (struct kmem_cache*) cache
    return malloc(s->object_size);
}
#endif

#ifdef AOT_KMEM_CACHE_FREE
void kmem_cache_free(void* s, void* x) {
    free(x);
}
#endif
