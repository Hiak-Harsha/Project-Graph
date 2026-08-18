"""
Unit & Integration Tests for Ephemeral Docker Sandbox Supervisor and Runtime Adapters.

Validates that:
1. DockerSandboxSupervisor rejects uncontracted repos and redacts environment secrets in logged commands.
2. RuntimePlanner validates candidate contracts against strict runtime policy limits.
3. HTTPRuntimeAdapter safely constructs and executes requests against healthy ExecutionTargets.
4. ContainerTestRunnerAdapter dispatches sandboxed test executions and captures exit codes.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from packages.sandbox import (
    CommandResult,
    ContainerTestResult,
    ContainerTestRunnerAdapter,
    DockerSandboxSupervisor,
    ExecutionTarget,
    HTTPResponsePayload,
    HTTPRuntimeAdapter,
    RuntimeBootstrapEngine,
    RuntimeContract,
    RuntimePlanner,
    RuntimePolicy,
    SandboxExecution,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"
CAREER_APP_PATH = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"


class TestSandboxSupervisorAndAdapters(unittest.TestCase):
    def test_supervisor_command_and_text_redaction(self):
        """Verify Docker flags and text logs redact API keys, tokens, and secrets."""
        supervisor = DockerSandboxSupervisor()

        # Test command argument redaction
        cmd = ["docker", "run", "--env", "DATABASE_URL=postgres://user:pass@db:5432/app", "--env", "JWT_SECRET=supersecret123", "image:tag"]
        redacted_cmd = supervisor._redact_command(cmd)

        self.assertIn("DATABASE_URL=[REDACTED]", redacted_cmd)
        self.assertIn("JWT_SECRET=[REDACTED]", redacted_cmd)
        self.assertNotIn("supersecret123", str(redacted_cmd))

        # Test log text redaction
        raw_log = "Server started with API_KEY: 9876543210abcdef and JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5..."
        redacted_log = supervisor._redact_text(raw_log)
        self.assertNotIn("9876543210abcdef", redacted_log)
        self.assertIn("API_KEY=[REDACTED]", redacted_log)

    def test_runtime_policy_validation(self):
        """Verify RuntimePolicy enforces port ranges, approved frameworks, and absolute healthcheck paths."""
        policy = RuntimePolicy()
        bootstrap = RuntimeBootstrapEngine(ACME_NOTES_PATH)
        candidate = bootstrap.detect_candidate()

        self.assertIsNotNone(candidate)
        is_valid, msg = policy.validate_candidate(candidate)
        self.assertTrue(is_valid, f"Policy validation failed: {msg}")

        # Test invalid port
        candidate.port = 99999
        is_valid, msg = policy.validate_candidate(candidate)
        self.assertFalse(is_valid)
        self.assertIn("out of allowed range", msg)

        # Test invalid relative healthcheck path
        candidate.port = 8000
        candidate.healthcheck_path = "health"
        is_valid, msg = policy.validate_candidate(candidate)
        self.assertFalse(is_valid)
        self.assertIn("absolute path", msg)

    def test_http_runtime_adapter_error_handling(self):
        """Verify HTTPRuntimeAdapter gracefully handles network connection errors without crashing."""
        target = ExecutionTarget(
            execution_id="SANDBOX-TEST-001",
            container_id="pg-audit-test",
            base_url="http://127.0.0.1:54321",
            health_status="HEALTHY",
            environment_id="DOCKER_SANDBOX_ISOLATED",
            container_image="project-graph/audit-sandbox:latest",
            internal_port=8000,
            host_port=54321,
            is_healthy=True,
        )

        adapter = HTTPRuntimeAdapter(target, timeout_seconds=1.0)
        resp: HTTPResponsePayload = adapter.send_request("GET", "/api/notes")

        self.assertTrue(resp.is_error)
        self.assertEqual(resp.status_code, 0)
        self.assertIn("Network error", resp.error_message)

    def test_container_test_runner_adapter_execution(self):
        """Verify ContainerTestRunnerAdapter formats docker exec command and captures result."""
        target = ExecutionTarget(
            execution_id="SANDBOX-TEST-002",
            container_id="pg-audit-test-container",
            base_url="http://127.0.0.1:8000",
            health_status="HEALTHY",
            environment_id="DOCKER_SANDBOX_ISOLATED",
            container_image="project-graph/audit-sandbox:latest",
            internal_port=8000,
            host_port=8000,
            is_healthy=True,
        )

        recorded_commands: list[list[str]] = []

        def mock_executor(cmd: list[str], cwd: Path, timeout: int) -> CommandResult:
            recorded_commands.append(cmd)
            return CommandResult(returncode=0, stdout="=== 5 passed in 0.42s ===", stderr="")

        test_runner = ContainerTestRunnerAdapter(target, executor=mock_executor)
        res: ContainerTestResult = test_runner.run_test_suite(["pytest", "tests/"])

        self.assertTrue(res.passed)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("5 passed", res.stdout)
        self.assertEqual(recorded_commands[0], ["docker", "exec", "pg-audit-test-container", "pytest", "tests/"])


if __name__ == "__main__":
    unittest.main()
