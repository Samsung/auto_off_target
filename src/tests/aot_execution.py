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
import io


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


def run_shell_aot(aot_path, options, timeout=None, capture_output=False):
    command = [aot_path] + prepare_args(options)
    joined_command = ' '.join(command)

    log = ''
    if capture_output:
        log += f'Running shell AoT with {joined_command}\n'
    else:
        print(f'Running shell AoT with {joined_command}')

    status = subprocess.run(command, capture_output=capture_output, timeout=timeout)

    if capture_output:
        log += status.stdout.decode()
        log += status.stderr.decode()

    return status.returncode, log


TIMEOUT_EXIT_CODE = 100
EXCEPTION_EXIT_CODE = 101


def _run_with_timeout(timeout, func):
    def wrapper():
        try:
            aot.main()
        except SystemExit as e:
            return e.code
        except Exception:
            return EXCEPTION_EXIT_CODE
    try:
        return func_timeout.func_timeout(timeout, wrapper)
    except func_timeout.FunctionTimedOut:
        return TIMEOUT_EXIT_CODE


# TODO: in the future we should probably return some more execution information
def run_aot(options, timeout=None, capture_output=True):
    sys.argv = ['./aot.py'] + prepare_args(options)
    joined_argv = ' '.join(sys.argv)

    log = ''
    if not capture_output:
        print(f'Running AoT with {joined_argv}')
        return _run_with_timeout(timeout, aot.main), log
    else:
        log += f'Running AoT with {joined_argv}\n'
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            exit_code = _run_with_timeout(timeout, aot.main)
            log += out.getvalue()
            return exit_code, log
