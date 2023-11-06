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

generate_data () {
    cas parse && cas postprocess && cas cache &&
    cas lm deps --cached &&
    PYTHONPATH=$CAS_DIR python3 $AOT_ROOT/tests/extract_ftdb_info.py &&
    $CAS_DIR/clang-proc/create_json_db -P $CAS_DIR/clang-proc/clang-proc &&
    PYTHONPATH=$CAS_DIR $AOT_ROOT/aot.py $AOT_ARGS &&
    rm -Rf off-target
}

for build in $@ ; do
    cd $build/etrace_data &&
    generate_data &&
    cd - &&
    mkdir -p test_data/$(basename $build) &&
    cp -f $build/etrace_data/db.img test_data/$(basename $build) &&
    cp -f $build/etrace_data/rdm.json test_data/$(basename $build)
done
