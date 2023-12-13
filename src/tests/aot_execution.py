# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import subprocess
import aot
import sys
import contextlib
import func_timeout
import io
from typing import Optional, Callable, Any


def prepare_args(options: dict[str, str]) -> list[str]:
    args = []
    for k, v in options.items():
        args.append(f'--{k}')
        if v:
            args += v.split()
    return args


def run_shell_aot(
    aot_path: str,
    options: dict[str, str],
    timeout: Optional[int] = None,
    capture_output: bool = False
) -> tuple[int, str]:
    command = [aot_path] + prepare_args(options)
    joined_command = ' '.join(command)

    log = ''
    if capture_output:
        log += f'Running shell AoT with {joined_command}\n'
    else:
        print(f'Running shell AoT with {joined_command}')

    try:
        status = subprocess.run(command, capture_output=capture_output,
                                timeout=timeout)
        exit_code = status.returncode
        if capture_output:
            log += status.stdout.decode()
            log += status.stderr.decode()
    except subprocess.TimeoutExpired:
        exit_code = TIMEOUT_EXIT_CODE

    return exit_code, log


TIMEOUT_EXIT_CODE = 100
EXCEPTION_EXIT_CODE = 101


def _run_with_timeout(timeout: Optional[int], func: Callable[[], Any]) -> int:
    def wrapper() -> int:
        try:
            func()
        except SystemExit as e:
            return e.code  # type: ignore
        except Exception:
            return EXCEPTION_EXIT_CODE
        return 0
    try:
        return func_timeout.func_timeout(timeout, wrapper)  # type: ignore
    except func_timeout.FunctionTimedOut:
        return TIMEOUT_EXIT_CODE


# TODO: in the future we should probably return some more execution information
def run_aot(
    options: dict[str, str],
    timeout: Optional[int] = None,
    capture_output: bool = True
) -> tuple[int, str]:
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
