#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

(cd test_data/src/csmith_test && etrace -w etrace_data make) ||
    { echo "csmith_test build failed" ; exit 2; }
(cd test_data/src/tinycc && ./configure && etrace -w etrace_data make) ||
    { echo "tinycc build failed" ; exit 2; }
