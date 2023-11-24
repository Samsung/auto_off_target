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
from tests.regression_tester import RegressionTester


class TestE2E(unittest.TestCase):

    class Config:

        def __init__(self, source, data_dir, cases):
            self.source = TestE2E.Source(**source)
            self.data_dir = data_dir
            self.cases = [TestE2E.Case(**case) for case in cases]
            self.name = ''

    class Source:

        def __init__(self, db_type, db, config, functions):
            self.db_type = db_type
            self.db = db
            self.cfg = config
            if not isinstance(functions, list):
                functions = [functions]
            self.functions = functions

    class Case:

        def __init__(self, options, build_offtarget=True):
            self.options = options
            self.build_offtarget = build_offtarget

    @classmethod
    def setUpClass(self):
        self.keep_test_env = False
        if 'KEEP_TEST_ENV' in os.environ:
            self.keep_test_env = os.environ['KEEP_TEST_ENV'].lower() == 'true'

        test_data_path = os.path.join(os.path.dirname(__file__), 'test_data')
        tinycc_config = os.path.join(test_data_path, 'test_config_tinycc.json')
        csmith_config = os.path.join(test_data_path, 'test_config_csmith_test.json')
        test_configs = f'{tinycc_config} {csmith_config}'
        if 'TEST_CONFIGS' in os.environ:
            test_configs = os.environ['TEST_CONFIGS']

        if 'AOT_REGRESSION_PATH' not in os.environ:
            self.fail('Make sure AOT_REGRESSION_PATH is set')
        self.regression_aot_path = os.environ['AOT_REGRESSION_PATH']

        self.timeout = None
        if 'AOT_TIMEOUT' in os.environ:
            self.timeout = int(os.environ['AOT_TIMEOUT'])

        self.test_configs = []
        for test_config in test_configs.split():
            with open(test_config) as f:
                data = json.load(f)
                config = TestE2E.Config(**data)
                config.name = test_config
                self.test_configs.append(config)

    def _prepare_options(test_config, function, case):
        options = {
            'product': 'test_product',
            'version': 'test_version',
            'build-type': 'userdebug',
            'db-type': test_config.source.db_type,
            'db': test_config.source.db,
            'config': test_config.source.cfg,
            'functions': function,
        }
        for k, v in case.options.items():
            options[k] = v
        return options

    def _run_test_case(self, test_config, function, i, case):
        # setup test env
        temp_dir = None
        if self.keep_test_env:
            execution_dir_name = os.path.join(os.path.dirname(__file__),
                                              'test_env',
                                              f'test{i}_{uuid.uuid4()}')
            os.makedirs(execution_dir_name, exist_ok=True)
        else:
            temp_dir = tempfile.TemporaryDirectory()
            execution_dir_name = temp_dir.name

        original_cwd = os.getcwd()
        os.chdir(execution_dir_name)
        print(f'Working in directory: {execution_dir_name}')

        data_dir = os.path.join(os.path.dirname(__file__), 'test_data', test_config.data_dir)
        shutil.copytree(data_dir, execution_dir_name, dirs_exist_ok=True)

        # test
        with self.subTest(f'Test {test_config.name} ({function}) [{i}] at {execution_dir_name}'):
            tester = RegressionTester(self.regression_aot_path, self.timeout,
                                      generate_run_scripts=self.keep_test_env)
            options = TestE2E._prepare_options(test_config, function, case)
            tester.run_regression(self, options, case.build_offtarget)

        # cleanup test env
        os.chdir(original_cwd)
        if not self.keep_test_env:
            temp_dir.cleanup()

    def test_regression(self):
        for test_config in self.test_configs:
            for function in test_config.source.functions:
                for i, case in enumerate(test_config.cases):
                    self._run_test_case(test_config, function, i, case)