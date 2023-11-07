#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

export PATH=${CAS_DIR}:$PATH

echo "Pulling test project and tree-sitter-c sources" &&
git submodule update --init --recursive &&

echo "Building tree-sitter language" &&
python3 tree_sitter_c.py &&

echo "Tracing test project builds and creating BAS database" &&
./cleanup_test_data.sh &&
./build_test_src.sh &&

echo "Generating FTDB database for the project"
./generate_test_data.sh test_data/src/tinycc test_data/src/csmith_test
