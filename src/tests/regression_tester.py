# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from tests import aot_execution
from tests import offtarget_comparison
import subprocess
import os


class RegressionTester:

    def __init__(self, test, regression_aot_path, timeout,
                 generate_run_scripts=False):
        self.test = test
        self.regression_aot_path = regression_aot_path
        self.timeout = timeout
        self.generate_run_scripts = generate_run_scripts

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

    def run_regression(self, test_case):
        options = test_case.options.copy()

        if self.generate_run_scripts:
            self.generate_scripts(options)

        options['output-dir'] = 'test_output_dir'
        aot_status = aot_execution.run_aot(options, timeout=self.timeout)

        options['output-dir'] = 'regression_test_output_dir'
        regression_aot_status = aot_execution.run_shell_aot(self.regression_aot_path, options, timeout=self.timeout)

        self.test.assertEqual(regression_aot_status, 0, "Unexpected regression AoT failure")
        self.test.assertEqual(aot_status, 0, "Unexpected AoT failure")

        ot_comparator = offtarget_comparison.OfftargetComparator()
        diffs = ot_comparator.compare_offtarget('test_output_dir', 'regression_test_output_dir')
        if len(diffs) != 0:
            self.test.fail('\n'.join(diffs))

        if not test_case.build_offtarget:
            return

        os.chdir('test_output_dir')
        print('Running make')
        status = subprocess.run(['make'])

        self.test.assertEqual(status.returncode, 0, 'Off-target build failed')
