# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import pytest
import os
import json
from .test_e2e import Config


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption('--keep-test-env', action='store_true')
    parser.addoption('--build-all', action='store_true')

    data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
    tinycc_path = os.path.join(data_dir, 'test_config_tinycc.json')
    csmith_path = os.path.join(data_dir, 'test_config_csmith_test.json')
    parser.addoption(
        '--test-configs',
        nargs='+',
        default=[tinycc_path, csmith_path]
    )

    parser.addoption('--regression-aot', default=None)
    parser.addoption('--aot-timeout', type=int, default=600)

    cpu_count = os.cpu_count()
    thread_count = 1 if cpu_count is None else cpu_count - 1
    parser.addoption('--aot-threads', type=int, default=thread_count)


@pytest.fixture
def keep_test_env(pytestconfig: pytest.Config) -> bool:
    return pytestconfig.getoption('keep_test_env')


@pytest.fixture
def build_all(pytestconfig: pytest.Config) -> bool:
    return pytestconfig.getoption('build_all')


@pytest.fixture
def test_configs(pytestconfig: pytest.Config) -> list[Config]:
    test_configs = []
    for test_config in pytestconfig.getoption('test_configs'):
        with open(test_config) as f:
            data = json.load(f)
            base_dir = os.path.dirname(test_config)
            name = os.path.basename(test_config)
            test_configs.append(Config(
                **data,
                base_dir=base_dir,
                name=name
            ))
    return test_configs


@pytest.fixture
def regression_aot(pytestconfig: pytest.Config) -> str:
    regression_aot = pytestconfig.getoption('regression_aot')
    if regression_aot is None:
        print('--regression-aot not set, regression tests will not run')
    return regression_aot


@pytest.fixture
def aot_timeout(pytestconfig: pytest.Config) -> int:
    return pytestconfig.getoption('aot_timeout')


@pytest.fixture
def aot_threads(pytestconfig: pytest.Config) -> int:
    return pytestconfig.getoption('aot_threads')
