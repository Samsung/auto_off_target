# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import pytest_subtests
import tempfile
import os
import shutil
import uuid
import multiprocessing.pool
import progressbar
from typing import Optional, Any
import aotdb
from tests.regression_tester import RegressionTester


def _get_funcs_from_file(path: str) -> list[str]:
    with open(path, 'r') as f:
        functions = []
        for function in f.readlines():
            function = function.strip()
            if len(function) == 0:
                continue
            functions.append(function)
        return functions


class Config:
    source: 'Source'
    data_dir: str
    cases: list['Case']
    name: str

    def __init__(
        self,
        source: dict[str, Any],
        data_dir: str,
        cases: list[dict[str, Any]],
        base_dir: str,
        name: str
    ) -> None:
        self.source = Source(**source, base_dir=base_dir)
        self.data_dir = os.path.join(base_dir, data_dir)
        self.cases = [Case(**case, base_dir=base_dir) for case in cases]
        self.name = name


class Source:
    db_type: aotdb.DbType
    cfg: str
    db: Optional[str]
    product: Optional[str]
    version: Optional[str]
    build_type: Optional[str]
    functions: list[str]

    def __init__(
        self,
        db_type: str,
        config: str,
        base_dir: str,
        db: Optional[str] = None,
        functions: Optional[list[str] | str] = None,
        functions_file: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        build_type: Optional[str] = None
    ) -> None:
        self.db_type = aotdb.DbType(db_type)
        self.db = db
        self.cfg = config
        self.product = product
        self.version = version
        self.build_type = build_type
        if functions_file is not None:
            funcs_path = os.path.join(base_dir, functions_file)
            self.functions = _get_funcs_from_file(funcs_path)
            return
        if not isinstance(functions, list):
            functions = [] if functions is None else [functions]
        self.functions = functions

    def options(self) -> dict[str, str]:
        options = {
            'db-type': self.db_type,
            'config': self.cfg,
        }
        if self.db_type == 'mongo':
            options['mongo-direct'] = ''

            assert self.product, '"product" field is None'
            options['product'] = self.product

            assert self.version, '"version" field is None'
            options['version'] = self.version

            assert self.build_type, '"build-type" field is None'
            options['build-type'] = self.build_type
        elif self.db_type == 'ftdb':
            assert self.db, '"db" field is None'
            options['db'] = self.db

            options['product'] = 'test_product'
            options['version'] = 'test_version'
            options['build-type'] = 'userdebug'
        return options


class Case:
    options: dict[str, str]
    build_offtarget: bool
    always_build_funcs: set[str]
    success_dump: Optional[str]

    def __init__(
        self,
        options: dict[str, str],
        base_dir: str,
        build_offtarget: bool = True,
        always_build_funcs: Optional[str] = None,
        success_dump: Optional[str] = None
    ) -> None:
        self.options = options
        self.build_offtarget = build_offtarget

        self.always_build_funcs = set()
        if always_build_funcs is not None:
            always_build_funcs_path = os.path.join(
                base_dir, always_build_funcs
            )
            if os.path.exists(always_build_funcs_path):
                funcs = _get_funcs_from_file(always_build_funcs_path)
                self.always_build_funcs = set(funcs)

        self.success_dump = None
        if success_dump is not None:
            self.success_dump = os.path.join(
                os.path.abspath(base_dir), success_dump
            )


def _prepare_options(
    test_config: Config,
    function: str,
    case: Case
) -> dict[str, str]:
    options = test_config.source.options()
    options['functions'] = function
    for k, v in case.options.items():
        options[k] = v
    return options


def _run_test_case(
    test_config: Config,
    function: str,
    i: int,
    case: Case,
    keep_test_env: bool,
    build_all: bool,
    regression_aot_path: Optional[str],
    timeout: int
) -> tuple[RegressionTester, str]:
    # setup test env
    temp_dir = None
    if keep_test_env:
        execution_dir_name = os.path.join(
            os.path.dirname(__file__),
            'test_env',
            f'{test_config.name}_{i}_{uuid.uuid4()}'
        )
        os.makedirs(execution_dir_name, exist_ok=True)
    else:
        temp_dir = tempfile.TemporaryDirectory()
        execution_dir_name = temp_dir.name

    shutil.copytree(
        test_config.data_dir,
        execution_dir_name,
        dirs_exist_ok=True
    )

    original_cwd = os.getcwd()
    os.chdir(execution_dir_name)

    # test
    build_offtarget = (
        case.build_offtarget
        or build_all
        or (function in case.always_build_funcs)
    )

    tester = RegressionTester(regression_aot_path, timeout, keep_test_env)

    options = _prepare_options(test_config, function, case)
    tester.run_regression(options, build_offtarget)

    if (
        build_offtarget
        and tester.success
        and (case.success_dump is not None)
    ):
        with open(case.success_dump, 'a+') as f:
            if function not in _get_funcs_from_file(case.success_dump):
                f.write(f'{function}\n')

    # cleanup test env
    os.chdir(original_cwd)
    if temp_dir:
        temp_dir.cleanup()

    return tester, execution_dir_name


def _progress_bar(max_value: int) -> progressbar.ProgressBar:
    timer = progressbar.Timer(format='elapsed time: %(elapsed)s')
    bar = progressbar.Bar('#')
    eta = progressbar.AdaptiveETA()
    progress = progressbar.SimpleProgress()

    widgets = [' [', timer, '] ', bar, progress, ' (', eta, ') ']
    return progressbar.ProgressBar(max_value=max_value, widgets=widgets)


def test_regression(
    subtests: pytest_subtests.SubTests,
    keep_test_env: bool,
    build_all: bool,
    test_configs: list[Config],
    regression_aot: str,
    aot_timeout: int,
    aot_threads: int
) -> None:
    test_args = []
    for test_config in test_configs:
        for function in test_config.source.functions:
            for i, case in enumerate(test_config.cases):
                test_args.append((
                    test_config,
                    function,
                    i,
                    case,
                    keep_test_env,
                    build_all,
                    regression_aot,
                    aot_timeout
                ))

    process_pool = multiprocessing.pool.Pool(aot_threads)
    progress_bar = _progress_bar(len(test_args))
    progress_bar.start()

    def callback(_: Any) -> None:
        progress_bar.increment()

    results = []
    for test_case in test_args:
        result = process_pool.apply_async(
            _run_test_case, test_case, callback=callback
        )
        results.append(result)

    process_pool.close()
    process_pool.join()
    progress_bar.finish()

    total_aot_time = 0
    aot_time_loss = 0
    total_regression_time = 0
    regression_time_loss = 0

    for test_case, result in zip(test_args, results):
        test_config, function, i, case, _, _, _, _ = test_case
        tester, exec_dir = result.get()

        if tester.aot_time is not None:
            total_aot_time += tester.aot_time
        else:
            aot_time_loss += 1

        if tester.regression_time is not None:
            total_regression_time += tester.regression_time
        else:
            regression_time_loss += 1

        exec_dir_postfix = f' at {exec_dir}' if keep_test_env else ''
        test_title = f'Test {test_config.name} ({function})' \
                     f'[{i}]{exec_dir_postfix}'
        with subtests.test(test_title):
            if not tester.success:
                print(f'\n\033[31m=== {test_title} failed ===\033[0m\n\n'
                      f'{tester.log}\n\n'
                      'Messages:\n'
                      f'{tester.msg}', end='')
                assert False, tester.msg

    print()
    print('===============================================')
    if total_aot_time:
        postfix = ''
        if aot_time_loss > 0:
            postfix = f' (loss: {100 * aot_time_loss / len(results)}%)'
        print(f'Total AoT time: {total_aot_time}{postfix}')
    if total_regression_time:
        postfix = ''
        if regression_time_loss > 0:
            postfix = f' (loss: {100 * regression_time_loss / len(results)}%)'
        print(f'Total regression AoT time: {total_regression_time}')
