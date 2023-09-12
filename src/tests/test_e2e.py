# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import unittest
import tempfile
import os
import json
import shutil
import uuid
from tests import regression_tester


class TestE2E(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.cwd_path = os.getcwd()

        self.test_data_dir = 'test_data'
        if 'DATA_DIR' in os.environ:
            self.test_data_dir = os.environ['DATA_DIR']
        self.test_data_dir = os.path.join(os.path.dirname(__file__), self.test_data_dir)
        self.ignore_test_data_dirs = ['src']

        self.keep_test_env = 'KEEP_TEST_ENV' in os.environ and os.environ['KEEP_TEST_ENV'] == 'True'

        test_cases_path = os.path.join(self.test_data_dir, 'test_cases.json')

        self.test_cases = []
        with open(test_cases_path) as test_cases_file:
            data = json.load(test_cases_file)
            for case in data:
                options = {}
                for k, v in case.items():
                    options[k] = v
                self.test_cases.append(options)

    @classmethod
    def tearDownClass(self):
        os.chdir(self.cwd_path)

    def set_up_test_case(self, i):
        execution_dir_name = None
        if self.keep_test_env:
            execution_dir_name = os.path.join(os.path.dirname(__file__),
                                              'test_env',
                                              f'test{i}_{uuid.uuid4()}')
            try:
                os.makedirs(execution_dir_name)
            except OSError:
                pass
        else:
            self.temp_dir = tempfile.TemporaryDirectory()
            execution_dir_name = self.temp_dir.name

        os.chdir(execution_dir_name)
        print(f'Working in directory: {execution_dir_name}')

        shutil.copytree(self.test_data_dir, execution_dir_name, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*self.ignore_test_data_dirs))
        return execution_dir_name

    def clean_up_test_case(self):
        if not self.keep_test_env:
            self.temp_dir.cleanup()

    def test_regression(self):
        if 'AOT_REGRESSION_PATH' not in os.environ:
            self.fail('Make sure AOT_REGRESSION_PATH is set')
        regression_aot_path = os.environ['AOT_REGRESSION_PATH']

        timeout = None
        if 'AOT_TIMEOUT' in os.environ:
            timeout = int(os.environ['AOT_TIMEOUT'])

        tester = regression_tester.RegressionTester(self, regression_aot_path, timeout, self.keep_test_env)
        for i, options in enumerate(self.test_cases):
            execution_dir_name = self.set_up_test_case(i)
            with self.subTest(f'Test {i} at {execution_dir_name}'):
                tester.run_regression(options.copy())
            self.clean_up_test_case()
