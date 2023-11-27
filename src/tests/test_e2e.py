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
import multiprocessing.pool
import progressbar
from tests.regression_tester import RegressionTester


class TestE2E(unittest.TestCase):

    class Config:

        def __init__(self, source, data_dir, cases):
            self.source = TestE2E.Source(**source)
            self.data_dir = data_dir
            self.cases = [TestE2E.Case(**case) for case in cases]
            self.name = ''

    class Source:

        def __init__(self, db_type, config, db=None, functions=None, functions_file=None,
                    product=None, version=None, build_type=None):
            self.db_type = db_type
            self.db = db
            self.cfg = config
            self.product = product
            self.version = version
            self.build_type = build_type
            if functions_file is not None:
                test_data_path = os.path.join(os.path.dirname(__file__), 'test_data')
                with open(os.path.join(test_data_path, functions_file), 'r') as f:
                    self.functions = []
                    for function in f.readlines():
                        self.functions.append(function.strip())
                return
            if not isinstance(functions, list):
                functions = [functions]
            self.functions = functions
        
        def options(self):
            options = {
                'db-type': self.db_type,
                'config': self.cfg,
            }
            if self.db_type == 'mongo':
                options['mongo-direct'] = ''
                options['product'] = self.product
                options['version'] = self.version
                options['build-type'] = self.build_type
            elif self.db_type == 'ftdb':
                options['db'] = self.db
                options['product'] = 'test_product'
                options['version'] = 'test_version'
                options['build-type'] = 'userdebug'
            return options

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
                config.name = os.path.basename(test_config)
                self.test_configs.append(config)

    def _prepare_options(test_config, function, case):
        options = test_config.source.options()
        options['functions'] = function
        for k, v in case.options.items():
            options[k] = v
        return options

    def _run_test_case(test_config, function, i, case,
                       keep_test_env, regression_aot_path, timeout):
        # setup test env
        temp_dir = None
        if keep_test_env:
            execution_dir_name = os.path.join(os.path.dirname(__file__),
                                              'test_env',
                                              f'{test_config.name}_{i}_{uuid.uuid4()}')
            os.makedirs(execution_dir_name, exist_ok=True)
        else:
            temp_dir = tempfile.TemporaryDirectory()
            execution_dir_name = temp_dir.name

        original_cwd = os.getcwd()
        os.chdir(execution_dir_name)

        data_dir = os.path.join(os.path.dirname(__file__), 'test_data', test_config.data_dir)
        shutil.copytree(data_dir, execution_dir_name, dirs_exist_ok=True)

        # test
        tester = RegressionTester(regression_aot_path, timeout,
                                    generate_run_scripts=keep_test_env)
        options = TestE2E._prepare_options(test_config, function, case)
        success, msg, log = tester.run_regression(options, case.build_offtarget)

        # cleanup test env
        os.chdir(original_cwd)
        if not keep_test_env:
            temp_dir.cleanup()
        
        return success, msg, log, execution_dir_name

    def _progress_bar(max_value):
        timer = progressbar.Timer(format='elapsed time: %(elapsed)s')
        bar = progressbar.Bar('#')
        eta = progressbar.AdaptiveETA()
        progress = progressbar.SimpleProgress()

        widgets = [' [', timer, '] ', bar, progress, ' (', eta, ') ']
        return progressbar.ProgressBar(max_value=max_value, widgets=widgets)

    def test_regression(self):
        test_args = []
        for test_config in self.test_configs:
            for function in test_config.source.functions:
                for i, case in enumerate(test_config.cases):
                    test_args.append((test_config, function, i, case, self.keep_test_env,
                                       self.regression_aot_path, self.timeout))
        
        process_pool = multiprocessing.pool.Pool()
        progress_bar = TestE2E._progress_bar(len(test_args))

        def callback(_):
            progress_bar.increment()

        results = []
        for test_case in test_args:
            results.append(process_pool.apply_async(TestE2E._run_test_case, test_case, 
                                                    callback=callback))

        process_pool.close()
        process_pool.join()
        progress_bar.finish()

        for test_case, result in zip(test_args, results):
            test_config, function, i, case, _, _, _ = test_case
            success, msg, log, exec_dir = result.get()
            exec_dir_postfix =  f' at {exec_dir}' if self.keep_test_env else ''
            test_title = f'Test {test_config.name} ({function}) [{i}]{exec_dir_postfix}'
            with self.subTest(test_title):
                if not success:
                    print(f'\n\033[31m=== {test_title} failed ===\033[0m\n\n'
                          f'{log}\n\n'
                          'Messages:\n'
                          f'{msg}', end='')
                    self.fail(msg)