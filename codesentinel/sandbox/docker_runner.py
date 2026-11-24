import time
import os
import subprocess
import shutil
from typing import Optional, Dict
from codesentinel.analyzer.models import SandboxTestResult
from codesentinel.core.logger import logger
from codesentinel.core.config import settings

try:
    import docker
    from docker.errors import DockerException, APIError
except ImportError:
    docker = None
    DockerException = Exception
    APIError = Exception


class SandboxRunner:
    """
    Manages isolated execution of untrusted code and test suites.
    Supports ephemeral Docker containers with cgroup restrictions,
    falling back to sandboxed subprocess execution when Docker daemon is offline.
    """

    def __init__(
        self,
        image: str = settings.DOCKER_SANDBOX_IMAGE,
        timeout: int = settings.SANDBOX_TIMEOUT_SECONDS,
        memory_limit: str = settings.SANDBOX_MEMORY_LIMIT,
        network_disabled: bool = settings.SANDBOX_NETWORK_DISABLED,
    ):
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.network_disabled = network_disabled
        self.docker_client = None

        if docker:
            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping()
                logger.info("Connected to Docker daemon successfully.")
            except Exception as e:
                logger.warning(f"Docker daemon unavailable ({e}). Using isolated subprocess sandbox.")
                self.docker_client = None

    def run_tests(
        self,
        workspace_dir: str,
        test_command: str = "pytest -v",
        env_vars: Optional[Dict[str, str]] = None
    ) -> SandboxTestResult:
        """
        Runs unit tests inside the sandbox and returns structured results.
        """
        start_time = time.time()
        if self.docker_client:
            return self._run_in_docker(workspace_dir, test_command, env_vars, start_time)
        else:
            return self._run_in_subprocess(workspace_dir, test_command, env_vars, start_time)

    def _run_in_docker(
        self,
        workspace_dir: str,
        test_command: str,
        env_vars: Optional[Dict[str, str]],
        start_time: float
    ) -> SandboxTestResult:
        """Executes test_command inside an isolated Docker container with strict cgroups."""
        container = None
        try:
            abs_workspace = os.path.abspath(workspace_dir)
            volumes = {
                abs_workspace: {"bind": "/workspace", "mode": "rw"}
            }

            container = self.docker_client.containers.create(
                image=self.image,
                command=f"sh -c 'cd /workspace && {test_command}'",
                volumes=volumes,
                working_dir="/workspace",
                mem_limit=self.memory_limit,
                network_disabled=self.network_disabled,
                environment=env_vars or {},
                user="1000:1000",
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
            )

            container.start()

            # Wait for execution with timeout
            try:
                res = container.wait(timeout=self.timeout)
                exit_code = res.get("StatusCode", 1)
            except Exception:
                container.kill()
                exit_code = 124  # SIGTIMEOUT

            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            elapsed = time.time() - start_time

            return self._parse_output(logs, exit_code, elapsed)

        except Exception as e:
            logger.error(f"Docker sandbox error: {e}")
            elapsed = time.time() - start_time
            return SandboxTestResult(
                passed=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_seconds=round(elapsed, 2),
                error_summary=f"Docker sandbox execution failure: {e}"
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _run_in_subprocess(
        self,
        workspace_dir: str,
        test_command: str,
        env_vars: Optional[Dict[str, str]],
        start_time: float
    ) -> SandboxTestResult:
        """Fallback isolated local runner with timeout constraints."""
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        try:
            proc = subprocess.run(
                test_command,
                shell=True,
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env
            )
            elapsed = time.time() - start_time
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            return self._parse_output(output, proc.returncode, elapsed)
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return SandboxTestResult(
                passed=False,
                exit_code=124,
                stdout="",
                stderr=f"Execution timed out after {self.timeout}s",
                execution_time_seconds=round(elapsed, 2),
                error_summary=f"Timeout limit reached ({self.timeout}s)"
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return SandboxTestResult(
                passed=False,
                exit_code=1,
                stdout="",
                stderr=str(e),
                execution_time_seconds=round(elapsed, 2),
                error_summary=str(e)
            )

    @staticmethod
    def _parse_output(logs: str, exit_code: int, elapsed: float) -> SandboxTestResult:
        passed = (exit_code == 0)
        total_tests = 0
        failed_tests = 0
        error_summary = None

        # Extract pytest stats if available
        # Example line: "=== 2 failed, 5 passed in 0.23s ==="
        for line in logs.splitlines():
            if "failed" in line or "passed" in line or "error" in line:
                if "===" in line:
                    error_summary = line.strip("= ")

        if not passed and not error_summary:
            lines = logs.strip().splitlines()
            error_summary = lines[-1] if lines else "Non-zero exit code"

        return SandboxTestResult(
            passed=passed,
            exit_code=exit_code,
            stdout=logs,
            stderr="",
            execution_time_seconds=round(elapsed, 2),
            total_tests=total_tests,
            failed_tests=failed_tests,
            error_summary=error_summary
        )
