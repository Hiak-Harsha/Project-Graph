"""Ephemeral, evidence-producing Docker sandbox for audited repositories.

The control plane must not run a target repository on the host.  This module
accepts only an explicit runtime contract, builds an isolated image, starts it
with restrictive Docker flags, probes a declared health endpoint, and returns
structured execution provenance.  It intentionally does not guess a start
command, ports, credentials, or network permissions.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class RuntimeContract:
    start_command: tuple[str, ...]
    internal_port: int
    healthcheck_path: str = "/health"
    healthcheck_statuses: tuple[int, ...] = (200,)
    startup_timeout_seconds: int = 45
    cpu_limit: float = 1.0
    memory_limit_mb: int = 1024
    pids_limit: int = 256
    environment: dict[str, str] = field(default_factory=dict)
    allow_outbound_network: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RuntimeContract":
        command = raw.get("start_command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
            raise ValueError("start_command must be a non-empty JSON string array; shell strings are forbidden.")
        port = raw.get("internal_port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("internal_port must be an integer in the range 1..65535.")
        path = raw.get("healthcheck_path", "/health")
        if not isinstance(path, str) or not path.startswith("/") or "://" in path:
            raise ValueError("healthcheck_path must be an absolute local URL path.")
        env = raw.get("environment", {})
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise ValueError("environment must map string names to string values.")
        statuses = raw.get("healthcheck_statuses", [200])
        if not isinstance(statuses, list) or not statuses or not all(isinstance(s, int) and 100 <= s <= 599 for s in statuses):
            raise ValueError("healthcheck_statuses must be a non-empty status-code array.")
        contract = cls(
            start_command=tuple(command), internal_port=port, healthcheck_path=path,
            healthcheck_statuses=tuple(statuses), startup_timeout_seconds=int(raw.get("startup_timeout_seconds", 45)),
            cpu_limit=float(raw.get("cpu_limit", 1.0)), memory_limit_mb=int(raw.get("memory_limit_mb", 1024)),
            pids_limit=int(raw.get("pids_limit", 256)), environment=dict(env),
            allow_outbound_network=bool(raw.get("allow_outbound_network", False)),
        )
        contract.validate()
        return contract

    def validate(self) -> None:
        if not 1 <= self.startup_timeout_seconds <= 300:
            raise ValueError("startup_timeout_seconds must be between 1 and 300.")
        if not 0.1 <= self.cpu_limit <= 8:
            raise ValueError("cpu_limit must be between 0.1 and 8.")
        if not 64 <= self.memory_limit_mb <= 8192:
            raise ValueError("memory_limit_mb must be between 64 and 8192.")
        if not 16 <= self.pids_limit <= 1024:
            raise ValueError("pids_limit must be between 16 and 1024.")

    def redacted(self) -> dict[str, Any]:
        data = asdict(self)
        data["start_command"] = list(self.start_command)
        data["healthcheck_statuses"] = list(self.healthcheck_statuses)
        data["environment"] = {key: "[REDACTED]" for key in self.environment}
        return data


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandExecutor(Protocol):
    def __call__(self, command: list[str], cwd: Path, timeout_seconds: int) -> CommandResult: ...


def execute_command(command: list[str], cwd: Path, timeout_seconds: int) -> CommandResult:
    try:
        result = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, timeout=timeout_seconds)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(-1, "", f"{type(exc).__name__}: {exc}")


@dataclass
class SandboxExecution:
    execution_id: str
    status: str  # HEALTHY | BLOCKED | ERROR
    reason: str = ""
    image_tag: str | None = None
    container_name: str | None = None
    network_name: str | None = None
    health_url: str | None = None
    base_url: str | None = None
    health_status: int | None = None
    commands: list[list[str]] = field(default_factory=list)
    logs: str = ""
    contract: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


HealthProbe = Callable[[str, float], int]


def http_health_probe(url: str, timeout_seconds: float) -> int:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


class DockerSandboxSupervisor:
    """Create one short-lived internal network and one hardened target container."""

    def __init__(self, executor: CommandExecutor = execute_command, health_probe: HealthProbe = http_health_probe) -> None:
        self._executor = executor
        self._health_probe = health_probe

    @staticmethod
    def load_contract(root: Path) -> RuntimeContract | None:
        path = root / ".project-graph" / "runtime-contract.json"
        if not path.exists():
            return None
        try:
            return RuntimeContract.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def start(self, root: Path, contract: RuntimeContract | None = None) -> SandboxExecution:
        execution_id = f"SANDBOX-{secrets.token_hex(6)}"
        contract = contract or self.load_contract(root)
        if contract is None:
            return SandboxExecution(execution_id, "BLOCKED", "No valid .project-graph/runtime-contract.json; target commands are never guessed.")
        if not (root / "Dockerfile").exists():
            return SandboxExecution(execution_id, "BLOCKED", "No Dockerfile found; sandbox cannot execute a target without an explicit image build recipe.", contract=contract.redacted())
        if not shutil.which("docker"):
            return SandboxExecution(execution_id, "BLOCKED", "Docker CLI unavailable in this execution environment.", contract=contract.redacted())

        suffix = secrets.token_hex(5)
        image, container, network = f"pg-audit:{suffix}", f"pg-audit-{suffix}", f"pg-audit-net-{suffix}"
        execution = SandboxExecution(execution_id, "ERROR", image_tag=image, container_name=container, network_name=network, contract=contract.redacted())

        # Build has networking disabled by default: a package cache/base image must
        # be available. This intentionally fails closed rather than downloading
        # arbitrary dependencies during an audit.
        build = ["docker", "build", "--network", "none", "--tag", image, "."]
        if not self._run(execution, build, root, 180):
            execution.reason = "Sandbox image build failed."
            return execution

        network_cmd = ["docker", "network", "create", "--internal", network]
        if contract.allow_outbound_network:
            # Outbound access is explicitly opted in and still confined to a
            # dedicated network. A policy proxy is the future enforcement point.
            network_cmd = ["docker", "network", "create", network]
        if not self._run(execution, network_cmd, root, 20):
            execution.reason = "Could not create isolated Docker network."
            return execution

        run = [
            "docker", "run", "--detach", "--name", container, "--network", network,
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(contract.pids_limit), "--memory", f"{contract.memory_limit_mb}m",
            "--cpus", str(contract.cpu_limit), "--publish", f"127.0.0.1::${contract.internal_port}",
        ]
        # Docker accepts host:container; the expression above is corrected below
        # to a random host port without requiring the caller to select one.
        run[-1] = f"127.0.0.1::{contract.internal_port}"
        for key, value in contract.environment.items():
            run.extend(["--env", f"{key}={value}"])
        run.extend([image, *contract.start_command])
        if not self._run(execution, run, root, 30):
            execution.reason = "Hardened sandbox container failed to start."
            return execution

        port_result = self._call(execution, ["docker", "port", container, str(contract.internal_port)], root, 10)
        if port_result.returncode != 0 or not port_result.stdout.strip():
            execution.reason = "Sandbox started but host port could not be resolved."
            return execution
        host_mapping = port_result.stdout.strip().splitlines()[0].strip()
        execution.health_url = f"http://{host_mapping}{contract.healthcheck_path}"
        execution.base_url = f"http://{host_mapping}"
        deadline = time.monotonic() + contract.startup_timeout_seconds
        while time.monotonic() < deadline:
            try:
                status = self._health_probe(execution.health_url, 2.0)
                execution.health_status = status
                if status in contract.healthcheck_statuses:
                    execution.status, execution.reason = "HEALTHY", "Declared health contract satisfied."
                    return execution
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        execution.reason = "Container did not satisfy declared health contract before timeout."
        return execution

    def teardown(self, execution: SandboxExecution, root: Path) -> None:
        """Best-effort cleanup; never touches containers/networks outside this execution ID."""
        if execution.container_name:
            self._call(execution, ["docker", "rm", "--force", execution.container_name], root, 20)
        if execution.network_name:
            self._call(execution, ["docker", "network", "rm", execution.network_name], root, 20)
        if execution.image_tag:
            self._call(execution, ["docker", "image", "rm", execution.image_tag], root, 20)

    def _run(self, execution: SandboxExecution, command: list[str], root: Path, timeout: int) -> bool:
        result = self._call(execution, command, root, timeout)
        return result.returncode == 0

    def _call(self, execution: SandboxExecution, command: list[str], root: Path, timeout: int) -> CommandResult:
        execution.commands.append(self._redact_command(command))
        result = self._executor(command, root, timeout)
        # A bounded tail remains useful evidence while avoiding uncontrolled log
        # growth or accidental full-secret persistence.
        execution.logs += self._redact_text((result.stdout + result.stderr)[-4000:])
        return result

    @staticmethod
    def _redact_command(command: list[str]) -> list[str]:
        out: list[str] = []
        redact_next = False
        for item in command:
            if redact_next:
                key = item.split("=", 1)[0]
                out.append(f"{key}=[REDACTED]")
                redact_next = False
            else:
                out.append(item)
                redact_next = item == "--env"
        return out

    @staticmethod
    def _redact_text(text: str) -> str:
        """Remove common key=value secrets from retained Docker output."""
        return re.sub(
            r"(?im)\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|KEY))\s*[:=]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            text,
        )
