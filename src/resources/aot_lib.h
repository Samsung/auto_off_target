/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 

#include aot_log.h

#ifdef AOT_GET_CURRENT
static inline struct task_struct* get_current() {
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
static inline unsigned long __range_ok(const void* addr, unsigned long size) {
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