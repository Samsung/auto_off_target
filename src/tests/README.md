# E2E Test Suite Guide

E2E Test Suite runs test cases which are configured by `test_config.json` files.
Test config files to be used are defined by `TEST_CONFIGS` env variable, which
is a list of space separated file paths (default points to
`test_data/test_config_csmith_test.json` and `test_data/test_config_tinycc.json`).

## `test_config.json`

One `test_config.json` file contains a test config for one test project.

```js
{
    "source": {
        "db_type": "ftdb", // Type of database
        "db": "db.img", // Required when db_type == ftdb
        "config": "cfg.json",

        // All three required when db_type == mongo
        "product": "test_product",
        "version": "test_version",
        "build_type": "userdebug",

        // Values for --functions option in aot.py
        // This can be a list, in which case test cases are run for each
        // of the values
        "functions": "main@tcc.c tccgen_compile@tccgen.c decl",

        // A path to a file from which function names are read
        // Each line in the file is a --functions option value
        // Overrides "functions" field
        "functions_file": "functions_file.dat"
    },

    // Files from this directory are copied to a temporary test directory
    // where tests are run
    "data_dir": "tinycc",

    // List of test cases
    "cases": [
        {
            // aot.py options with which the test is run
            "options": {
                "init": "", // This corresponds to --init
                "dynamic-init": "",
                "func-stats": "basic", // This corresponds to --func-stats basic
                "include-std-headers": "<stdint.h> <stdio.h>",
                "external-inclusion-margin": "1",
                "cut-off": "functions",
                "co-funcs": "tcc_run",
                "fptr-analysis": "",
                "ignore-recursion-errors": "",
                "unroll-macro-defs": "",
                "verify-struct-layout": "",
                "dump-smart-init": ""
            },

            // This determines if the build of the generated off-target
            // should be tested
            // Default value is true
            "build_offtarget": false
        }
    ]
}
```

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

Data required for default tests has to be generated using CAS (information on CAS
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
AOT_REGRESSION_PATH=<REGRESSION_AOT_ROOT>/src/aot.py pytest --tb=line -sv test_e2e.y
```

If you would like to keep the test environment data, please set the `KEEP_TEST_ENV=True` env variable.

To test off-target build for all test cases you can set `TEST_BUILD_ALL=True` env variable.
