import os
import tempfile
from codesentinel.sandbox.docker_runner import SandboxRunner


def test_sandbox_executes_successful_command():
    sandbox = SandboxRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        res = sandbox.run_tests(tmpdir, test_command="python3 -c 'print(\"hello sandbox\")'")
        assert res.passed is True
        assert res.exit_code == 0
        assert "hello sandbox" in res.stdout


def test_sandbox_captures_failure_and_exit_code():
    sandbox = SandboxRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        res = sandbox.run_tests(tmpdir, test_command="python3 -c 'import sys; sys.exit(42)'")
        assert res.passed is False
        assert res.exit_code == 42


def test_sandbox_enforces_timeout():
    sandbox = SandboxRunner(timeout=2)
    with tempfile.TemporaryDirectory() as tmpdir:
        res = sandbox.run_tests(tmpdir, test_command="python3 -c 'import time; time.sleep(5)'")
        assert res.passed is False
        assert res.exit_code == 124
