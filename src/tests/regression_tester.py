# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from tests import aot_execution
from tests import offtarget_comparison
import subprocess
import os


class RegressionTester:

    def __init__(self, regression_aot_path, timeout,
                 generate_run_scripts=False):
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
        args = ''
        for part in aot_execution.prepare_args(options):
            args += f' "{part}"'
        RegressionTester._generate_run_script('run.sh',
                                              f'{aot_path} {args}')
        RegressionTester._generate_run_script('run_debug.sh',
                                              f'python3 -m pdb {aot_path} {args}')
        RegressionTester._generate_run_script('run_regression.sh',
                                              f'{self.regression_aot_path} {args}')

    def run_regression(self, options, build_offtarget):
        success, msg = True, ''

        if self.generate_run_scripts:
            self.generate_scripts(options)

        log = ''

        if self.regression_aot_path:
            options['output-dir'] = 'regression_test_output_dir'
            status, run_log = aot_execution.run_shell_aot(self.regression_aot_path, options,
                                                          timeout=self.timeout, capture_output=True)
            if status != 0:
                log += run_log + '\n'
                success = False
                msg += 'Unexpected regression AoT failure\n'

        options['output-dir'] = 'test_output_dir'
        status, run_log = aot_execution.run_aot(options, timeout=self.timeout, capture_output=True)
        if status != 0:
            log += run_log + '\n'
            success = False
            msg += 'Unexpected AoT failure\n'
            return success, msg, log

        if self.regression_aot_path:
            ot_comparator = offtarget_comparison.OfftargetComparator()
            diffs = ot_comparator.compare_offtarget('test_output_dir', 'regression_test_output_dir')
            if len(diffs) != 0:
                success = False
                msg += '\n'.join(diffs)

        build_all = False
        if 'TEST_BUILD_ALL' in os.environ:
            build_all = os.environ['TEST_BUILD_ALL'].lower() == 'true'

        if not build_offtarget and not build_all:
            return success, msg, log

        os.chdir('test_output_dir')
        status = subprocess.run(['make'], capture_output=True)

        if status.returncode != 0:
            success = False
            log += 'Running make\n'
            log += status.stdout.decode()
            log += status.stderr.decode()
            msg += 'Off-target build failed\n'
        return success, msg, log
