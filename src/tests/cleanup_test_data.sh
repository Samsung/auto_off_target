#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

set -u

rm -f test_data/csmith_test/db.img &&
rm -f test_data/tinycc/db.img &&

(cd test_data/src/csmith_test && rm -Rf etrace_data && make clean) &&
(cd test_data/src/tinycc      && rm -Rf etrace_data && make clean)
