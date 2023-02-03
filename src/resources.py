#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland


#
# Resources module
#

import shutil
import os
import sys


class ResourceMgr:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.predefined_files = ["aot_replacements.h", "Makefile", "aot_lib.h", "aot_lib.c", "aot_mem_init_lib.h",
                                 "aot_mem_init_lib.c", "aot_fuzz_lib.h", "aot_fuzz_lib.c", "aot_log.h", "aot_log.c",
                                 "build.sh",
                                 "vlayout.c.template", "fptr_stub.c.template", "fptr_stub_known_funcs.c.template", "dfsan_ignore_list.txt",
                                 "aot_recall.h", "aot_recall.c", "aot_dfsan.c.lib"]

    def copy_resources(self):
        # copy the predefined files
        for f in self.predefined_files:
            # https://www.blog.pythonlibrary.org/2013/10/29/python-101-how-to-find-the-path-of-a-running-script/
            shutil.copyfile(
                f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{f}", f"{self.out_dir}/{f}")
            shutil.copymode(
                f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{f}", f"{self.out_dir}/{f}")



def resourcemgr_factory(out_dir) -> ResourceMgr:
    return ResourceMgr(out_dir)
