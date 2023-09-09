#! /bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
set -u

cd test_data/src &&
rm -rf tinycc &&
git clone https://github.com/TinyCC/tinycc.git &&
cd tinycc &&
git checkout ff2a372a9af5a7eb16548940f779a24c20767d4f &&
cd ../../..
