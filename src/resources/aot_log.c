/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#include "aot_log.h"
#include <stdio.h>
#include <stdarg.h>

#define LOG_FILE_NAME "off_target.log"

FILE* aot_log_file = 0;


void aot_log_init() {
    // no need for logging stubs while fuzzing
    #if defined(AFL) || defined(KLEE)
        return;
    #endif
    
    aot_log_file = fopen(LOG_FILE_NAME, "w");
}

// File gets the log, screen gets the log, everyone gets the log
void aot_log_msg(char* fmt, ...) {
    // no need for logging stubs while fuzzing
    #if defined(AFL) || defined(KLEE)
        return;
    #endif

    if (!aot_log_file) 
        return;

    va_list args;
    va_start(args, fmt);
    fprintf(aot_log_file, fmt, args);
    printf(fmt, args);
    va_end(args);

    fflush(aot_log_file);
}