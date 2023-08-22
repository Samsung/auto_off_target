import filecmp
from tests import aot_execution
import subprocess
import os


class RegressionTester:
    def __init__(self, test_case, regression_aot_path):
        self.test_case = test_case
        self.regression_aot_path = regression_aot_path
        self.exclude_from_diff = ['aot.log']

        # some files con't be simply compared
        self.special_files = {
            'aot_literals': RegressionTester.aot_literals_comparison
        }

    def aot_literals_comparison(file1, file2):
        def read_set(file):
            ret = set()
            with open(file) as f:
                line = f.readline()
                while line:
                    ret.add(line.split('=')[-1])
                    line = f.readline()
            return ret

        set1 = read_set(file1)
        set2 = read_set(file2)
        return set1 == set2

    def assert_differences(self, comparison_output, dir):
        files = []
        for file in comparison_output.left_only:
            file_path = os.path.join('test_output_dir', dir, file)
            files.append(file_path)
        if files:
            self.test_case.fail(f'Unexpected files: {files}')

        files = []
        for file in comparison_output.right_only:
            file_path = os.path.join('regression_test_output_dir', dir, file)
            files.append(file_path)
        if files:
            self.test_case.fail(f'Missing files: {files}')

        files = []
        for file in comparison_output.diff_files:
            file_path = os.path.join(dir, file)
            if file in self.exclude_from_diff:
                continue

            if file in self.special_files \
                and self.special_files[file_path](os.path.join('test_output_dir', file_path),
                                                  os.path.join('regression_test_output_dir', file_path)):
                # self.special_files[file] is a function returning True if files match
                continue

            files.append(file_path)

            print('-' * 50 + f'\nDiff {os.path.join(dir, file)}')
            subprocess.run(['diff', os.path.join('test_output_dir', file_path),
                            os.path.join('regression_test_output_dir', file_path)])
            print('-' * 50)
        if files:
            self.test_case.fail(f'Files differ: {files}')

        for subdir in comparison_output.subdirs.values():
            if not self.assert_differences(subdir, os.path.join(dir, subdir)):
                return False
        return True

    def compare_output(self, dir1, dir2):
        comparison = filecmp.dircmp('test_output_dir', 'regression_test_output_dir', ignore=self.exclude_from_diff)
        return self.assert_differences(comparison, '')

    def run_regression(self, options):
        options['output-dir'] = 'test_output_dir'
        aot_status = aot_execution.run_aot(options)

        options['output-dir'] = 'regression_test_output_dir'
        regression_aot_status = aot_execution.run_shell_aot(self.regression_aot_path, options)

        self.test_case.assertEqual(aot_status, 0, "Unexpected AoT failure")
        self.test_case.assertEqual(regression_aot_status, 0, "Unexpected regression AoT failure")

        self.compare_output('test_output_dir', 'regression_test_output_dir')
