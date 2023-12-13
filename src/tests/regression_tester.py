# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from tests import aot_execution
from tests import offtarget_comparison
import subprocess
import os
import re
import random
from typing import Optional


class RegressionTester:
    regression_aot_path: Optional[str]
    timeout: Optional[int]
    generate_run_scripts: bool
    regression_out_dir: str
    out_dir: str
    success: Optional[bool]
    msg: str
    log: str
    aot_time: Optional[float]
    regression_time: Optional[float]

    def __init__(
        self,
        regression_aot_path: Optional[str],
        timeout: Optional[int],
        generate_run_scripts: bool = False
    ) -> None:
        self.regression_aot_path = regression_aot_path
        self.timeout = timeout
        self.generate_run_scripts = generate_run_scripts

        self.regression_out_dir = 'regression_test_output_dir'
        self.out_dir = 'test_output_dir'

        self.success = None
        self.msg = ''
        self.log = ''
        self.aot_time = None
        self.regression_time = None

    @staticmethod
    def _generate_run_script(filename: str, command: str) -> None:
        with open(filename, 'w+') as f:
            f.write('#! /bin/bash\n')
            f.write('rm -Rf off-target\n')
            f.write(command)
        os.chmod(filename, 0o777)

    def generate_scripts(self, options: dict[str, str]) -> None:
        aot_path = os.path.join(os.path.dirname(__file__), '..', 'aot.py')
        args = ''
        for part in aot_execution.prepare_args(options):
            args += f' "{part}"'
        RegressionTester._generate_run_script('run.sh', f'{aot_path} {args}')
        RegressionTester._generate_run_script(
            'run_debug.sh', f'python3 -m pdb {aot_path} {args}'
        )
        RegressionTester._generate_run_script(
            'run_regression.sh', f'{self.regression_aot_path} {args}'
        )

    def _get_execution_time(self, status: int, log: str) -> Optional[float]:
        if status == aot_execution.TIMEOUT_EXIT_CODE:
            return self.timeout

        match = re.search(r'AOT_RUN_TIME_SECONDS: \|(\d+?(?:\.\d+))\|', log)
        if match is None:
            return None

        try:
            time = float(match.group(1))
        except ValueError:
            return None

        return time

    def _run_regression_aot(self, options: dict[str, str]) -> None:
        if self.regression_aot_path is None:
            return

        options['output-dir'] = self.regression_out_dir

        status, run_log = aot_execution.run_shell_aot(
            self.regression_aot_path,
            options,
            timeout=self.timeout,
            capture_output=True
        )

        self.regression_time = self._get_execution_time(status, run_log)

        if status == 0:
            return

        self.success = False
        self.log += run_log + '\n'
        if status == aot_execution.TIMEOUT_EXIT_CODE:
            self.msg += 'Regression AoT timeout\n'
        else:
            self.msg += 'Regression AoT execution failed\n'

    def _run_aot(self, options: dict[str, str]) -> None:
        options['output-dir'] = self.out_dir

        status, run_log = aot_execution.run_aot(
            options, timeout=self.timeout, capture_output=True
        )

        self.aot_time = self._get_execution_time(status, run_log)

        if status == 0:
            return

        self.success = False
        self.log += run_log + '\n'
        if status == aot_execution.TIMEOUT_EXIT_CODE:
            self.msg += 'AoT timeout\n'
        else:
            self.msg += 'AoT execution failed\n'

    def _compare_offtarget(self) -> None:
        ot_comparator = offtarget_comparison.OfftargetComparator()
        diffs = ot_comparator.compare_offtarget(
            self.out_dir, self.regression_out_dir
        )
        if len(diffs) == 0:
            return

        self.success = False
        self.log += '\n'.join(diffs) + '\n'
        self.msg += 'Off-target comparison failed\n'

    def _build_offtarget(self) -> None:
        os.chdir(self.out_dir)
        status = subprocess.run(['make'], capture_output=True)

        if status.returncode == 0:
            return

        log = 'Running make\n'
        log += status.stdout.decode()
        log += status.stderr.decode()

        self.success = False
        self.log += log
        self.msg += 'Off-target build failed\n'

    def run_regression(
        self,
        options: dict[str, str],
        build_offtarget: bool
    ) -> None:
        self.success, self.msg, self.log = True, '', ''

        if self.generate_run_scripts:
            self.generate_scripts(options)

        if random.random() < 0.5:
            if self.regression_aot_path:
                self._run_regression_aot(options)
            self._run_aot(options)
        else:
            self._run_aot(options)
            if self.regression_aot_path:
                self._run_regression_aot(options)

        if not self.success:
            return

        if self.regression_aot_path:
            self._compare_offtarget()

        if build_offtarget:
            self._build_offtarget()
