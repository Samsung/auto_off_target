# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import filecmp
from tests import aot_execution
from tests import file_comparison
import subprocess
import os


class RegressionTester:

    def __init__(self, test_case, regression_aot_path, timeout, generate_run_scripts=False):
        self.test_case = test_case
        self.regression_aot_path = regression_aot_path
        self.exclude_from_diff = ['aot.log']
        self.timeout = timeout
        self.generate_run_scripts = generate_run_scripts

        # some files con't be simply compared
        self.special_files = {
            'aot_literals': file_comparison.compare_aot_literals,
            'aot.h': file_comparison.compare_C_simple,
            'fptr_stub.c': file_comparison.FptrStubCComparator.compare_fptr_stub_c,
        }

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

            file_path1 = os.path.join('test_output_dir', file_path)
            file_path2 = os.path.join('regression_test_output_dir', file_path)
            if file_path in self.special_files:
                result, msg = self.special_files[file_path](file_path1, file_path2)
                if not result:
                    files.append(file_path)
                    print('-' * 50 + f'\nDiff {file_path}:')
                    print(msg)
                    print('-' * 50)
                continue

            files.append(file_path)

            print('-' * 50 + f'\nDiff {file_path}')
            subprocess.run(['diff', file_path1, file_path2])
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

    def _generate_run_script(filename, command):
        with open(filename, 'w+') as f:
            f.write('#! /bin/bash\n')
            f.write('rm -Rf off-target\n')
            f.write(command)
        os.chmod(filename, 0o777)

    def generate_scripts(self, options):
        aot_path = os.path.join(os.path.dirname(__file__), '..', 'aot.py')
        args = ' '.join(aot_execution.prepare_args(options))
        RegressionTester._generate_run_script('run.sh',
                                              f'{aot_path} {args}')
        RegressionTester._generate_run_script('run_debug.sh',
                                              f'python3 -m pdb {aot_path} {args}')
        RegressionTester._generate_run_script('run_regression.sh',
                                              f'{self.regression_aot_path} {args}')

    def run_regression(self, options):
        if self.generate_run_scripts:
            self.generate_scripts(options)

        options['output-dir'] = 'test_output_dir'
        aot_status = aot_execution.run_aot(options, timeout=self.timeout)

        options['output-dir'] = 'regression_test_output_dir'
        regression_aot_status = aot_execution.run_shell_aot(self.regression_aot_path, options, timeout=self.timeout)

        self.test_case.assertEqual(regression_aot_status, 0, "Unexpected regression AoT failure")
        self.test_case.assertEqual(aot_status, 0, "Unexpected AoT failure")

        self.compare_output('test_output_dir', 'regression_test_output_dir')

        os.chdir('test_output_dir')
        print('Running make')
        status = subprocess.run(['make'])

        self.test_case.assertEqual(status.returncode, 0, 'Off-target build failed')

        print('Running off-target executable')
        status = subprocess.run(['./native'])

        self.test_case.assertEqual(status.returncode, 0, 'Off-target execution failed')
