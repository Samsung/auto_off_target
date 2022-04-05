/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


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

