# E2E Test Suite Guide

E2E Test Suite runs test cases located in one of the `test_data` directories
(specific directory depends on the `DATA_DIR` env variable, `test_data` by
default). 

## test_cases.json

`test_cases.json` contains a list of test cases, each one having key-value
pairs corresponding to options with which AoT is run. (`"config": "cfg.json"`
corresponds to running `./aot.py` with `--config cfg.json`, `"init": ""`
corresponds to `--init`).

For each test case all files in the folder are copied to a temporary directory
and AoT tests are run.

Before running tests for directory `test_data` make sure you generate `db.json`
for a test project located in `test_data/src/`.

## Regression tests

Regression tests need a path to `aot.py` in the version of AoT which we want
to compare the results to. You have to provide it in `AOT_REGRESSION_PATH` env
variable.

The tests first import the `db.img` database file, then generate an off-target
using both the current AoT version and the version from `AOT_REGRESSION_PATH`.
Generated files are then compared to see if anything changed between versions.

File comparison is performed directly using `filecmp` module unless a file is
specified in `special_files` map in `RegressionTester` class, which maps the
file name to a function that returns `True` if files are the same according to
some custom criterion.

## Test data

Data required for tests has to be generated using CAS (information on CAS
setup can be found in [CAS repository](https://github.com/Samsung/CAS)). 

Make sure the following env variables are set:
- `CAS_DIR` points to CAS root directory
- `PYTHONPATH` includes `CAS_DIR` (this is needed for libftdb)

To generate all required files run `setup_test_data.sh`. Make sure you run it
from `tests` directory.

## Running tests

First setup python virtual environment.
```
cd <AOT_ROOT>/src
source setup_venv.sh
```
Then generate the test data.
```
cd <AOT_ROOT>/src/tests
./setup_test_data.sh
```
Then run tests using `pytest` (see `pytest` documentation for additional options).
```
AOT_REGRESSION_PATH=<REGRESSION_AOT_ROOT>/src/aot.py pytest -s
```

If you would like to keep the test environment data, please set the `KEEP_TEST_ENV=True` env variable.

If you want the tests to check if the off-target build is successful, you can set
the `AOT_TEST_BUILD=True` env variable.
