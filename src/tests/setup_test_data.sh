#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

export PATH=${CAS_DIR}:$PATH

echo "Pulling test project and tree-sitter-c sources"
git submodule update --init --recursive ||
    { echo "Pulling test project and tree-sitter-c sources failed"; exit 2; }

echo "Building tree-sitter language"
python3 tree_sitter_c.py ||
    { echo "Building tree-sitter language failed" ; exit 2; }

echo "Tracing test project builds"
./cleanup_test_data.sh
./build_test_src.sh \ ||
    { echo "Tracing test project builds failed" ; exit 2; }

echo "Generating FTDB database for tinycc"
./generate_test_data.sh tinycc ||
    { echo "Generating FTDB database for tinycc failed" ; exit 2; }

echo "Generating FTDB database for csmith_test"
./generate_test_data.sh csmith_test ||
    { echo "Generating FTDB database for csmith_test failed" ; exit 2; }
