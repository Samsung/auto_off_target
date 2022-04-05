/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#ifndef AOT_REPLACEMENTS_H
#define AOT_REPLACEMENTS_H

#include "aot_fuzz_lib.h"

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

#endif
