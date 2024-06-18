/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#ifndef __DYN_INIT_H__
#define __DYN_INIT_H__

void aot_kflat_init(const char* imgpath);
void aot_kflat_fini(void);
void* aot_kflat_root_by_name(const char* name, unsigned long* size);
long aot_kflat_replace_variable(void* old_mem, void* new_mem, unsigned long size);
void aot_kflat_mark_freed(void* mptr);
#endif /* __DYN_INIT_H__ */
