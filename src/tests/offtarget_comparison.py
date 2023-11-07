#! /bin/python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import filecmp
import os
import subprocess
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
import file_comparison


class OfftargetComparator:

    def __init__(self):
        self.special_files = {
            'aot_literals': file_comparison.compare_aot_literals,
            'aot.h': file_comparison.CComparator.compare_C_simple,
            'fptr_stub.c': file_comparison.FptrStubCComparator.compare_fptr_stub_c,
        }
        self.exclude_from_diff = ['aot.log']
        self.differences = []

    def _assert_differences(self, comparison_output, dir1, dir2):
        for file in comparison_output.left_only:
            file_path = os.path.join(dir1, file)
            self.differences.append(f'Unexpected file: {file_path}')

        for file in comparison_output.right_only:
            file_path = os.path.join(dir2, file)
            self.differences.append(f'Missing file: {file_path}')

        for file in comparison_output.diff_files:
            if file in self.exclude_from_diff:
                continue

            file_path1 = os.path.join(dir1, file)
            file_path2 = os.path.join(dir2, file)

            if file in self.special_files:
                result, difference = self.special_files[file](file_path1, file_path2)
                if not result:
                    self.differences.append(
                        f'Files {file_path1} and {file_path2} differ:\n'
                        f'{difference}'
                    )
                continue

            try:
                subprocess.check_output(['diff', file_path1, file_path2])
            except subprocess.CalledProcessError as e:
                self.differences.append(
                    f'Files {file_path1} and {file_path2} differ:\n'
                    f'{e.output.decode()}'
                )

        for subdir, comparison in comparison_output.subdirs.items():
            if not self._assert_differences(comparison,
                                            os.path.join(dir1, subdir),
                                            os.path.join(dir2, subdir)):
                return False
        return True

    def compare_offtarget(self, dir1, dir2):
        comparison = filecmp.dircmp(dir1, dir2, ignore=self.exclude_from_diff)
        self._assert_differences(comparison, dir1, dir2)
        return self.differences


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {os.path.basename(sys.argv[0])} dir1 dir2')
        exit(1)

    for difference in OfftargetComparator().compare_offtarget(sys.argv[1], sys.argv[2]):
        print(difference)
