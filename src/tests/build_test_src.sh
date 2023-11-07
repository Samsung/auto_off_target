#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

if [ -z $CAS_DIR ]
then
    echo "Make sure CAS_DIR is set correctly"
    exit 1
fi

(cd test_data/src/csmith_test && etrace -w etrace_data make) &&
(cd test_data/src/tinycc && ./configure && etrace -w etrace_data make)
