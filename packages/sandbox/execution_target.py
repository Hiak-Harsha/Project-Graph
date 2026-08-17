"""
Execution Target & Runtime Planner Subsystem (spec Milestone 2 §14)

Connects RuntimeBootstrapEngine candidate detection to DockerSandboxSupervisor,
enforcing security policies and producing verified ExecutionTargets.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from packages.sandbox.bootstrap_engine import RuntimeBootstrapEngine, RuntimeContractCandidate
from packages.sandbox.container_runtime import DockerSandboxSupervisor, RuntimeContract, SandboxExecution


@dataclass
class ExecutionTarget:
    execution_id: str
    container_id: str
    base_url: str
    health_status: str
    environment_id: str
    container_image: str
    internal_port: int
    host_port: int
    is_healthy: bool = False
    logs_uri: str = ""
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimePolicy:
    allowed_frameworks: set[str] = field(default_factory=lambda: {"FastAPI", "Starlette", "Flask", "Django", "Node.js", "Express", "Next.js"})
    max_startup_timeout: int = 60
    require_container_isolation: bool = True
    require_healthcheck: bool = True
    allow_outbound_network: bool = False

    def validate_candidate(self, candidate: RuntimeContractCandidate) -> tuple[bool, str]:
        if not candidate.start_command:
            return False, "Candidate has empty startup command."

        frameworks = set(candidate.detected_frameworks)
        if not frameworks.intersection(self.allowed_frameworks):
            return False, f"Detected frameworks {frameworks} not approved in runtime policy."

        if not (1 <= candidate.port <= 65535):
            return False, f"Internal port {candidate.port} out of allowed range 1..65535."

        if not candidate.healthcheck_path.startswith("/"):
            return False, f"Healthcheck path '{candidate.healthcheck_path}' must be an absolute path."

        return True, "Candidate contract validated against policy."


class RuntimePlanner:
    def __init__(self, root: Path, policy: Optional[RuntimePolicy] = None) -> None:
        self.root = root
        self.policy = policy or RuntimePolicy()
        self.bootstrap = RuntimeBootstrapEngine(root)
        self.supervisor = DockerSandboxSupervisor()

    def plan_and_boot_target(self, allow_candidate_auto_approval: bool = False) -> tuple[Optional[ExecutionTarget], str]:
        """Detects, validates, and optionally provisions a container execution target."""
        # 1. Check for explicit runtime contract in repository
        contract = RuntimeContract.load_from_repo(self.root)
        if contract is None:
            # 2. Synthesize candidate contract from project manifests
            candidate = self.bootstrap.detect_candidate()
            if candidate is None:
                return None, "No runtime contract or detectable framework manifest found in repository."

            is_valid, reason = self.policy.validate_candidate(candidate)
            if not is_valid:
                return None, f"Runtime candidate rejected by policy: {reason}"

            if not allow_candidate_auto_approval:
                return None, "Runtime contract requires explicit approval; auto-approval is disabled."

            # Construct contract from approved candidate
            try:
                contract = RuntimeContract.from_dict(candidate.to_runtime_contract())
            except Exception as e:
                return None, f"Failed to instantiate contract from candidate: {e}"

        # 3. Boot container sandbox supervisor
        sandbox_exec: SandboxExecution = self.supervisor.start_repository_sandbox(self.root, contract)
        if sandbox_exec.status != "HEALTHY":
            return None, f"Sandbox container boot failed health check: {sandbox_exec.error_message or sandbox_exec.status}"

        # 4. Construct verified ExecutionTarget
        target = ExecutionTarget(
            execution_id=sandbox_exec.execution_id,
            container_id=sandbox_exec.container_id,
            base_url=sandbox_exec.base_url,
            health_status=sandbox_exec.status,
            environment_id="DOCKER_SANDBOX_ISOLATED",
            container_image="project-graph/audit-sandbox:latest",
            internal_port=sandbox_exec.internal_port,
            host_port=sandbox_exec.host_port,
            is_healthy=True,
            logs_uri=f"memory://sandbox-logs/{sandbox_exec.execution_id}",
        )
        return target, "Execution target active and healthy."
