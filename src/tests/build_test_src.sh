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

(cd test_data/src/csmith_test && make clean && etrace make) &&
(cd test_data/src/csmith_test && cas parse && cas postprocess && cas cache) &&

(cd test_data/src/tinycc && ./configure && etrace make) &&
(cd test_data/src/tinycc && cas parse && cas postprocess && cas cache)
