# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import unittest
import pytest
import tempfile
import os
import json
import shutil
import uuid
import multiprocessing.pool
import progressbar
from tests.regression_tester import RegressionTester


TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')


def _get_funcs_from_file(path):
    with open(path, 'r') as f:
        functions = []
        for function in f.readlines():
            function = function.strip()
            if len(function) == 0:
                continue
            functions.append(function)
        return functions


class Config:

    def __init__(self, source, data_dir, cases):
        self.source = Source(**source)
        self.data_dir = data_dir
        self.cases = [Case(**case) for case in cases]
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
            funcs_path = os.path.join(TEST_DATA_DIR, functions_file)
            self.functions = _get_funcs_from_file(funcs_path)
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

    def __init__(self, options, build_offtarget=True, always_build_funcs=None,
                 success_dump=None):
        self.options = options
        self.build_offtarget = build_offtarget

        self.always_build_funcs = set()
        if always_build_funcs is not None:
            always_build_funcs_path = os.path.join(TEST_DATA_DIR, always_build_funcs)
            if os.path.exists(always_build_funcs_path):
                funcs = _get_funcs_from_file(always_build_funcs_path)
                self.always_build_funcs = set(funcs)

        self.success_dump = None
        if success_dump is not None:
            self.success_dump = os.path.join(TEST_DATA_DIR, success_dump)


class TestE2E(unittest.TestCase):

    @pytest.fixture(autouse=True)
    def _set_keep_test_env(self, keep_test_env):
        self.keep_test_env = keep_test_env

    @pytest.fixture(autouse=True)
    def _set_build_all(self, build_all):
        self.build_all = build_all

    @pytest.fixture(autouse=True)
    def _set_test_configs(self, test_configs):
        self.test_configs = []
        for test_config in test_configs:
            with open(test_config) as f:
                data = json.load(f)
                config = Config(**data)
                config.name = os.path.basename(test_config)
                self.test_configs.append(config)

    @pytest.fixture(autouse=True)
    def _set_regression_aot_path(self, regression_aot):
        if regression_aot is None:
            print('--regression-aot not set, regression tests will not run')
        self.regression_aot_path = regression_aot

    @pytest.fixture(autouse=True)
    def _set_aot_timeout(self, aot_timeout):
        self.timeout = aot_timeout

    def _prepare_options(test_config, function, case):
        options = test_config.source.options()
        options['functions'] = function
        for k, v in case.options.items():
            options[k] = v
        return options

    def _run_test_case(test_config, function, i, case,
                       keep_test_env, build_all,
                       regression_aot_path, timeout):
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

        data_dir = os.path.join(TEST_DATA_DIR, test_config.data_dir)
        shutil.copytree(data_dir, execution_dir_name, dirs_exist_ok=True)

        build_offtarget = case.build_offtarget or build_all or function in case.always_build_funcs

        # test
        tester = RegressionTester(regression_aot_path, timeout, keep_test_env)
        options = TestE2E._prepare_options(test_config, function, case)
        success, msg, log = tester.run_regression(options, build_offtarget)

        if build_offtarget and success and case.success_dump is not None:
            with open(case.success_dump, 'a+') as f:
                if function not in _get_funcs_from_file(case.success_dump):
                    f.write(f'{function}\n')

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
                    test_args.append((test_config, function, i, case,
                                      self.keep_test_env, self.build_all,
                                      self.regression_aot_path, self.timeout))

        process_pool = multiprocessing.pool.Pool(int(os.cpu_count() / 2))
        progress_bar = TestE2E._progress_bar(len(test_args))
        progress_bar.start()

        def callback(_):
            progress_bar.increment()

        results = []
        for test_case in test_args:
            result = process_pool.apply_async(TestE2E._run_test_case,
                                              test_case, callback=callback)
            results.append(result)

        process_pool.close()
        process_pool.join()
        progress_bar.finish()

        for test_case, result in zip(test_args, results):
            test_config, function, i, case, _, _, _, _ = test_case
            success, msg, log, exec_dir = result.get()
            exec_dir_postfix = f' at {exec_dir}' if self.keep_test_env else ''
            test_title = f'Test {test_config.name} ({function}) [{i}]{exec_dir_postfix}'
            with self.subTest(test_title):
                if not success:
                    print(f'\n\033[31m=== {test_title} failed ===\033[0m\n\n'
                          f'{log}\n\n'
                          'Messages:\n'
                          f'{msg}', end='')
                    self.fail(msg)
