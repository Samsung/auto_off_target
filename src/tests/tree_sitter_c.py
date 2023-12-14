#! /bin/python3

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from tree_sitter import Language
import os

src_path = os.path.join(os.path.dirname(__file__), 'tree-sitter-c')
lib_path = os.path.join(src_path, 'lang.so')

if __name__ == '__main__':
    Language.build_library(lib_path, [src_path])
