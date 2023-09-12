#!/bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
function log {
    local msg=$1
    echo "$msg"
}
function compile_fail {
    local target=$1
    local logfile="$target""_build.log"
    log "Command 'make $target' failed. Please check $logfile for details."
    log "The off-target code needs to compile first before we can proceed to testing."
    log "==== Build errors: ===="
    local errors=`grep "error:" $logfile`
    log "$errors"
    exit 1
}

make clean &>/dev/null && make asan   &>asan_build.log   || compile_fail "asan"
make clean &>/dev/null && make ubsan  &>ubsan_build.log  || compile_fail "ubsan"
make clean &>/dev/null && make dfsan  &>dfsan_build.log  || compile_fail "dfsan"
make clean &>/dev/null && make gcov   &>gcov_build.log   || compile_fail "gcov"
make clean &>/dev/null && make afl    &>afl_build.log    || compile_fail "afl"
make clean &>/dev/null && make klee   &>klee_build.log   || compile_fail "klee"
make clean &>/dev/null && make symcc  &>symcc.log 	 || compile_fail "symcc"
make clean &>/dev/null && make debug  &>debug_build.log  || compile_fail "debug" 
make clean &>/dev/null && make native &>native_build.log || compile_fail "native"
make clean &>/dev/null && make native-gcc &>gcc_build.log || compile_fail "native-gcc"

