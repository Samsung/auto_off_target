import subprocess
import aot
import sys


def prepare_args(options):
    args = []
    for k, v in options.items():
        args.append(f'--{k}')
        if v:
            args.append(v)
    return args


def run_shell_aot(aot_path, options):
    command = [aot_path] + prepare_args(options)
    print(f'Running shell AoT with {command}')
    status = subprocess.run(command)
    return status.returncode


def run_aot(options):
    sys.argv = ['./aot.py'] + prepare_args(options)
    try:
        print(f'Running AoT with {sys.argv}')
        aot.main()
    except SystemExit as e:
        return e.code
