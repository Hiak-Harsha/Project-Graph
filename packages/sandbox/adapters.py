"""
Runtime Execution Adapters for Ephemeral Docker Sandboxes (spec Milestone 2 §12-14)

Provides structured, safe adapters to execute runtime obligations against a running container:
1. HTTPRuntimeAdapter: Sends live HTTP requests against the container target with latency & status code tracking.
2. TestRunnerAdapter: Executes test commands inside the container sandbox, capturing stdout, stderr, and exit codes.
3. BrowserTargetAdapter: Provides verified target URLs and environment parameters for Playwright browser workers.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from packages.sandbox.container_runtime import CommandExecutor, CommandResult, DockerSandboxSupervisor, execute_command
from packages.sandbox.execution_target import ExecutionTarget


@dataclass
class HTTPResponsePayload:
    status_code: int
    headers: dict[str, str]
    body: str
    latency_ms: float
    is_error: bool = False
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_preview": self.body[:500] if self.body else "",
            "latency_ms": self.latency_ms,
            "is_error": self.is_error,
            "error_message": self.error_message,
        }


class HTTPRuntimeAdapter:
    """Dispatches HTTP requests strictly to an active, validated ExecutionTarget."""

    def __init__(self, target: ExecutionTarget, timeout_seconds: float = 10.0) -> None:
        if not target.is_healthy or not target.base_url:
            raise ValueError("HTTPRuntimeAdapter requires a healthy ExecutionTarget with a base_url.")
        self.target = target
        self.timeout_seconds = timeout_seconds

    def send_request(
        self,
        method: str,
        path: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[Union[str, bytes, dict]] = None,
    ) -> HTTPResponsePayload:
        clean_path = "/" + path.lstrip("/")
        full_url = urllib.parse.urljoin(self.target.base_url, clean_path)

        req_headers = {"User-Agent": "ProjectGraph-Audit-Sandbox/1.0", **(headers or {})}
        encoded_body = None
        if body is not None:
            if isinstance(body, dict):
                encoded_body = json.dumps(body).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                encoded_body = body.encode("utf-8")
            else:
                encoded_body = body

        req = urllib.request.Request(
            url=full_url,
            data=encoded_body,
            headers=req_headers,
            method=method.upper(),
        )

        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                raw_body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
                return HTTPResponsePayload(
                    status_code=int(resp.status),
                    headers=resp_headers,
                    body=raw_body,
                    latency_ms=elapsed_ms,
                    is_error=False,
                )
        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            raw_body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
            resp_headers = {str(k): str(v) for k, v in e.headers.items()} if hasattr(e, "headers") else {}
            return HTTPResponsePayload(
                status_code=int(e.code),
                headers=resp_headers,
                body=raw_body,
                latency_ms=elapsed_ms,
                is_error=True,
                error_message=f"HTTP {e.code}: {e.reason}",
            )
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return HTTPResponsePayload(
                status_code=0,
                headers={},
                body="",
                latency_ms=elapsed_ms,
                is_error=True,
                error_message=f"Network error: {str(e)}",
            )


@dataclass
class ContainerTestResult:
    exit_code: int
    passed: bool
    stdout: str
    stderr: str
    duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "passed": self.passed,
            "stdout_tail": self.stdout[-2000:] if self.stdout else "",
            "stderr_tail": self.stderr[-2000:] if self.stderr else "",
            "duration_seconds": self.duration_seconds,
        }


class ContainerTestRunnerAdapter:
    """Executes test commands inside a running container via docker exec."""

    def __init__(self, target: ExecutionTarget, executor: CommandExecutor = execute_command) -> None:
        self.target = target
        self._executor = executor

    def run_test_suite(self, test_cmd: list[str], timeout_seconds: int = 60) -> ContainerTestResult:
        if not self.target.container_id:
            return ContainerTestResult(
                exit_code=-1,
                passed=False,
                stdout="",
                stderr="Container ID not available on target.",
                duration_seconds=0.0,
            )

        cmd = ["docker", "exec", self.target.container_id, *test_cmd]
        t0 = time.perf_counter()
        res: CommandResult = self._executor(cmd, Path("."), timeout_seconds)
        elapsed = round(time.perf_counter() - t0, 3)

        return ContainerTestResult(
            exit_code=res.returncode,
            passed=(res.returncode == 0),
            stdout=res.stdout,
            stderr=res.stderr,
            duration_seconds=elapsed,
        )
