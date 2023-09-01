# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import unittest
import tempfile
import os
import json
import shutil
from tests import regression_tester
from tests import build_tester


class TestE2E(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.cwd_path = os.getcwd()

        self.test_data_dir = 'test_data'
        if 'DATA_DIR' in os.environ:
            self.test_data_dir = os.environ['DATA_DIR']
        self.test_data_dir = os.path.join(os.path.dirname(__file__), self.test_data_dir)

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

    def set_up_test_case(self):
        temp_dir = tempfile.TemporaryDirectory()
        os.chdir(temp_dir.name)
        print(f'Working in temporary directory: {temp_dir}')

        shutil.copytree(self.test_data_dir, temp_dir.name, dirs_exist_ok=True)

        return temp_dir

    def test_regression(self):
        if 'AOT_REGRESSION_PATH' not in os.environ:
            self.fail('Make sure AOT_REGRESSION_PATH is set')
        regression_aot_path = os.environ['AOT_REGRESSION_PATH']

        tester = regression_tester.RegressionTester(self, regression_aot_path)
        for options in self.test_cases:
            with self.subTest(f'options={options}'):
                temp_dir = self.set_up_test_case()
                tester.run_regression(options.copy())
                temp_dir.cleanup()

    def test_build(self):
        tester = build_tester.BuildTester(self)
        for options in self.test_cases:
            with self.subTest(f'options={options}'):
                temp_dir = self.set_up_test_case()
                tester.run_build(options.copy())
                temp_dir.cleanup()
