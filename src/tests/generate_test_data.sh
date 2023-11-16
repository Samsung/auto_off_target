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

AOT_ROOT="$PWD/.."
AOT_ARGS="--product test_product 
        --version test_version 
        --build-type userdebug 
        --db-type ftdb 
        --rdm-file rdm.json 
        --known-funcs-file $AOT_ROOT/known_functions 
        --import-json db.json 
        --fptr-analysis"

CAS_OPTIONS='--verbos --debug'

(
    cd test_data/src/$1/etrace_data ||
        { echo "No etrace data for $1" ; exit 2; }
    cas $CAS_OPTIONS parse ||
        { echo "parse fail" ; exit 2; }
    cas $CAS_OPTIONS postprocess ||
        { echo "postprocess fail" ; exit 2; }
    cas $CAS_OPTIONS cache ||
        { echo "cache fail" ; exit 2; }
    cas $CAS_OPTIONS lm deps --cached ||
        { echo "lm deps fail" ; exit 2; }
    PYTHONPATH=$CAS_DIR python3 $AOT_ROOT/tests/extract_ftdb_info.py ||
        { echo "extract_ftdb_info.py fail" ; exit 2; }
    $CAS_DIR/clang-proc/create_json_db --macro-expansion -P $CAS_DIR/clang-proc/clang-proc ||
        { echo "create_json_db fail" ; exit 2; }
    PYTHONPATH=$CAS_DIR $AOT_ROOT/aot.py $AOT_ARGS ||
        { echo "AoT fail" ; exit 2; }
    rm -Rf off-target
) || exit 2

mkdir -p test_data/$1
cp -f test_data/src/$1/etrace_data/db.img test_data/$1 ||
    { echo "test_data/src/$1/etrace_data/db.img not found" ; exit 2; }
cp -f test_data/src/$1/etrace_data/rdm.json test_data/$1 ||
    { echo "test_data/src/$1/etrace_data/rdm.json not found" ; exit 2; }
