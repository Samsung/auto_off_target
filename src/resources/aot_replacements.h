/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/


#ifndef AOT_REPLACEMENTS_H
#define AOT_REPLACEMENTS_H

#include "aot_fuzz_lib.h"

int printf(const char* fmt, ...);

#define __replacement____put_user__(x,ptr) ({ typeof(*ptr) val; typeof(*ptr) __x = x; memcpy(&val, &__x, sizeof(__x)); 0; })
#define __replacement____get_user__(x,ptr)  ({ fuzz_that_data(&x, ptr, sizeof(x), 0); aot_tag_memory(&x, sizeof(x), 0); 0; })
#define __replacement____BUG_ON__(condition)({ int _c = !!(condition); if (_c) { int* ptr = 0; *ptr = 0; } })
#define __replacement__WARN_ON__(condition) ({ int _c = !!(condition); if (_c) { printf("WARN_ON\n"); } _c; })
#define __replacement__WARN__(condition, format...)({ int _c = !!(condition); if (_c) { printf("WARN\n"); } _c; })
#define __replacement__WARN_TAINT__(condition, taint, format...)({ int _c = !!(condition); if (_c) { printf("WARN_TAINT\n"); } _c; })
#define __replacement__WARN_ON_ONCE__(condition)({ int _c = !!(condition); if (_c) { printf("WARN_ON_ONCE\n"); } _c; })
#define __replacement__WARN_ONCE__(condition, format...)({ int _c = !!(condition); if (_c) { printf("WARN_ONCE\n"); } _c; })
#define __replacement__WARN_TAINT_ONCE__(condition, taint, format...)({ int _c = !!(condition); if (_c) { printf("WARN_TAINT_ONCE\n"); } _c; })
#define __replacement__BUG__()({ int* ptr = 0; *ptr = 0; })
#define __replacement__wait_event_interruptible__(wq_head, condition) ({ int ret = 0; ret; })
#define __replacement__wait_event_interruptible_timeout__(wq_head, condition, timeout) ({ long ret = timeout; ret; })
#define __user
#define __replacement__barrier__() ({;})

static inline void __macrocall__list_for_each__(struct list_head* pos, struct list_head* head) { (void)pos; (void)head; }
static inline void __macrocall__list_for_each_continue__(struct list_head* pos, struct list_head* head) { (void)pos; (void)head; }
static inline void __macrocall__list_for_each_prev__(struct list_head* pos, struct list_head* head) { (void)pos; (void)head; }
static inline void __macrocall__list_for_each_safe__(struct list_head* pos, struct list_head* n, struct list_head* head) { (void)pos; (void)n; (void)head; }
static inline void __macrocall__list_for_each_prev_safe__(struct list_head* pos, struct list_head* n, struct list_head* head) { (void)pos; (void)n; (void)head; }
static inline void __macrocall__list_for_each_entry__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_reverse__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_continue__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_continue_reverse__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_from__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_from_reverse__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_safe__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_safe_continue__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_safe_from__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__list_for_each_entry_safe_reverse__(struct list_head* head, unsigned long offset) { (void)head; (void)offset; }
static inline void __macrocall__container_of__(void* ptr, unsigned long offset) { (void)ptr; (void)offset; }

#endif
