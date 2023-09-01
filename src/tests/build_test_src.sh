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

cd test_data &&

cd src/csmith_test &&

# build csmith
$CAS_DIR/etrace make &&

cd - &&
mkdir -p csmith_test &&
cp src/csmith_test/.nfsdb csmith_test &&

cd src/tinycc &&

# build tinycc
./configure &&
$CAS_DIR/etrace make &&

cd - &&
mkdir -p tinycc &&
cp src/tinycc/.nfsdb tinycc &&

cd ..
