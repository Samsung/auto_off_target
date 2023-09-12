# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import subprocess
import aot
import sys
import contextlib
import tempfile
import os
import shutil
import func_timeout


class ExecutionContext:

    def __init__(self, data_dir=None, ignore=[]):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cwd_path = os.getcwd()

        if data_dir:
            shutil.copytree(data_dir, self.temp_dir.name,
                            ignore=shutil.ignore_patterns(*ignore), dirs_exist_ok=True)
        os.chdir(self.temp_dir.name)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.cleanup()

    def cleanup(self):
        self.temp_dir.cleanup()
        os.chdir(self.cwd_path)


def prepare_args(options):
    args = []
    for k, v in options.items():
        args.append(f'--{k}')
        if v:
            args += v.split()
    return args


def run_shell_aot(aot_path, options, timeout=None, show_output=True):
    command = [aot_path] + prepare_args(options)
    joined_command = ' '.join(command)
    print(f'Running shell AoT with {joined_command}')
    status = subprocess.run(command, capture_output=not show_output, timeout=timeout)
    return status.returncode


TIMEOUT_EXIT_CODE = 123


def _run_with_timeout(timeout, func):
    try:
        func_timeout.func_timeout(timeout, aot.main)
    except func_timeout.FunctionTimedOut:
        return TIMEOUT_EXIT_CODE
    except SystemExit as e:
        return e.code
    return 0


# TODO: in the future we should probably return some more execution information
def run_aot(options, timeout=None, show_output=True):
    sys.argv = ['./aot.py'] + prepare_args(options)
    joined_argv = ' '.join(sys.argv)

    if show_output:
        print(f'Running AoT with {joined_argv}')
        return _run_with_timeout(timeout, aot.main)
    else:
        with contextlib.redirect_stdout(None), contextlib.redirect_stderr(None):
            return _run_with_timeout(timeout, aot.main)
