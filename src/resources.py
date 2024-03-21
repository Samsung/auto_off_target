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


class ResourceMgr:
    def __init__(self, resources_dir, out_dir):
        self.out_dir = out_dir
        self.resources_dir = resources_dir
        self.predefined_files = ["aot_replacements.h", "Makefile", "aot_lib.h", "aot_lib.c", "aot_lib_ex.c", "aot_mem_init_lib.h",
                                 "aot_mem_init_lib.c", "aot_fuzz_lib.h", "aot_fuzz_lib.c", "aot_log.h", "aot_log.c",
                                 "build.sh",
                                 "vlayout.c.template", "fptr_stub.c.template", "fptr_stub_known_funcs.c.template", "dfsan_ignore_list.txt",
                                 "aot_recall.h", "aot_recall.c", "aot_dfsan.c.lib"]

    def copy_resources(self):
        # copy the predefined files
        for f in self.predefined_files:
            from_path = os.path.join(self.resources_dir, f)
            to_path = os.path.join(self.out_dir, f)

            shutil.copyfile(from_path, to_path)
            shutil.copymode(from_path, to_path)



def resourcemgr_factory(resources_dir, out_dir) -> ResourceMgr:
    return ResourceMgr(resources_dir, out_dir)
