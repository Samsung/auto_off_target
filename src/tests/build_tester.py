from tests import aot_execution
import os
import subprocess


class BuildTester:

    def __init__(self, test_case):
        self.test_case = test_case

    def run_build(self, options):
        options['output-dir'] = 'output_dir'
        aot_execution.run_aot(options)

        os.chdir('output_dir')
        print('Running make')
        status = subprocess.run(['make'])

        self.test_case.assertEqual(status.returncode, 0, 'Invalid make status code')

        print('Running off-target executable')
        status = subprocess.run(['./native'])

        self.test_case.assertEqual(status.returncode, 0, 'Invalid off-target execution status code')
