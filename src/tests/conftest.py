# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import pytest
import os


def pytest_addoption(parser):
    parser.addoption('--keep-test-env', action='store_true')
    parser.addoption('--build-all', action='store_true')

    data_dir = os.path.join(os.path.dirname(__file__), 'test_data')

    parser.addoption('--test-configs', nargs='+',
                     default=[os.path.join(data_dir, 'test_config_tinycc.json'),
                              os.path.join(data_dir, 'test_config_csmith_test.json')])
    parser.addoption('--regression-aot', default=None)
    parser.addoption('--aot-timeout', type=int, default=600)


@pytest.fixture
def keep_test_env(pytestconfig):
    return pytestconfig.getoption('keep_test_env')


@pytest.fixture
def build_all(pytestconfig):
    return pytestconfig.getoption('build_all')


@pytest.fixture
def test_configs(pytestconfig):
    return pytestconfig.getoption('test_configs')


@pytest.fixture
def regression_aot(pytestconfig):
    return pytestconfig.getoption('regression_aot')


@pytest.fixture
def aot_timeout(pytestconfig):
    return pytestconfig.getoption('aot_timeout')
