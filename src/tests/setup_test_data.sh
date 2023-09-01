#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

echo "Pulling test project sources" &&
./pull_test_src.sh &&

echo "Tracing test project builds" &&
./build_test_src.sh &&

echo "Processing tracer data" &&
./generate_test_data.sh test_data/tinycc test_data/csmith_test
