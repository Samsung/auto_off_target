# E2E Test Suite Guide

E2E Test Suite runs test cases located in one of the `test_data` directories
(specific directory depends on the `DATA_DIR` env variable, `test_data` by
default). 

## test_cases.json

`test_cases.json` contains a list of test cases, each one having key-value
pairs corresponding to options with which AoT is run. (`"config": "cfg.json"
corresponds to running `./aot.py` with `--config cfg.json`, `"init": ""`
corresponds to `--init`).

For each test case all files in the folder are copied to a temporary directory
and AoT tests are run.

Before running tests for directory `test_data` make sure you generate `db.json`
for a test project located in `test_data/src/`.

## Regression tests

Regression tests need a path to the `aot.py` in version of AoT which we want
to compare the results to. You have to provide it in `AOT_REGRESSION_PATH` env
variable.

Generated files are compared directly unless they are specified in
`special_files` map in `RegressionTester` class, which maps the file name to a
function that returns `True` if files are the same according to some criterion.

## Test data

Data required for tests has to be generated using CAS (information on CAS
setup can be found in [CAS repository](https://github.com/Samsung/CAS)). Make
sure `CAS_DIR` env variable is set to CAS root directory.

To generate all required files run `setup_test_data.sh`. Make sure you run it
from `tests` directory.
