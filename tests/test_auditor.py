"""
Unit & Integration Test Suite for AI Production Engineering Auditor.
Validates:
- Endpoint discovery & deduplication
- UI discovery & dead interaction detection
- Auth boundary & single BOLA finding generation
- Safe repository path traversal protection
- Check-obligation accounting & P1 completeness invariant
- Dynamic test execution & weak assertion detection
- Negative-space advertised feature discovery
- SQLite persistence of ProjectGraph and Evidence Vault
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.discovery import (
    build_audit_task_manifest,
    discover_api_endpoints,
    discover_files,
    discover_ui_elements,
    fingerprint_project,
)
from packages.evidence import EvidenceStore, EvidenceType, reset_evidence_counter
from packages.intelligence import CompletenessEngine, CrossCheckEngine, VerdictEngine
from packages.orchestration import AgentOutput, AgentProposal, AgentRegistry
from packages.sandbox.container_runtime import CommandResult, DockerSandboxSupervisor, RuntimeContract
from packages.project_graph.models import CheckStatus, NodeType, reset_id_counters
from packages.project_graph.store import ProjectGraph
from packages.verification import VerificationRunner
from workers.audit_orchestrator import run_full_audit
from apps.api.server import validate_safe_repo_path

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "sample_career_app"


class TestAuditorPlatform(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()

    def test_api_endpoint_discovery_deduplication(self):
        """Verify FastAPI routes are discovered without double-counting."""
        graph = ProjectGraph()
        endpoints = discover_api_endpoints(FIXTURE_PATH, graph)

        endpoint_names = [e.name for e in endpoints]
        self.assertEqual(len(endpoints), 4, f"Expected 4 endpoints, got {len(endpoints)}: {endpoint_names}")
        self.assertIn("POST /api/auth/login", endpoint_names)
        self.assertIn("POST /api/resume/generate", endpoint_names)
        self.assertIn("GET /api/resume/{id}", endpoint_names)
        self.assertIn("POST /api/resumes/upload", endpoint_names)

    def test_ui_element_discovery(self):
        """Verify UI discovery finds actionable elements and checks handlers."""
        graph = ProjectGraph()
        ui_elements = discover_ui_elements(FIXTURE_PATH, graph)

        self.assertEqual(len(ui_elements), 3)
        dead_button = next((u for u in ui_elements if "Export Resume" in u.name), None)
        self.assertIsNotNone(dead_button)
        self.assertFalse(dead_button.metadata.get("has_handler"))

        active_button = next((u for u in ui_elements if "Generate Resume" in u.name or "handleGenerate" in str(u.metadata)), None)
        self.assertIsNotNone(active_button)
        self.assertTrue(active_button.metadata.get("has_handler"))

    def test_safe_repo_path_validation(self):
        """Verify path traversal and root scanning are blocked."""
        is_valid, _, err = validate_safe_repo_path("/etc")
        self.assertFalse(is_valid)

        is_valid, _, err = validate_safe_repo_path("C:\\Windows")
        self.assertFalse(is_valid)

        is_valid, resolved, err = validate_safe_repo_path(str(FIXTURE_PATH))
        self.assertTrue(is_valid)
        self.assertIsNotNone(resolved)

    def test_check_obligations_model_and_persistence(self):
        """Verify first-class AuditCheck generation and SQLite persistence of evidence vault."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        self.assertGreaterEqual(len(graph.audit_checks), 60)

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            temp_db = Path(tf.name)

        try:
            graph.persist(temp_db, evidence_store)
            conn = sqlite3.connect(temp_db)
            try:
                check_count = conn.execute("SELECT COUNT(*) FROM audit_checks").fetchone()[0]
                evidence_count = conn.execute("SELECT COUNT(*) FROM evidence_records").fetchone()[0]
            finally:
                conn.close()
            self.assertGreaterEqual(check_count, 60)
            self.assertGreaterEqual(evidence_count, 10)
        finally:
            if temp_db.exists():
                temp_db.unlink()

    def test_negative_space_feature_discovery(self):
        """Verify advertised features without code backing are detected as missing requirements."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        missing_career_graph = next((f for f in findings if "Career Graph" in f["title"]), None)
        self.assertIsNotNone(missing_career_graph)
        self.assertEqual(missing_career_graph["category"], "MISSING_REQUIREMENT")

    def test_test_quality_detection_without_host_execution(self):
        """Verify weak assertions are found without executing untrusted tests on host."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        weak_test_finding = next((f for f in findings if "Non-Meaningful Test Assertions" in f["title"]), None)
        self.assertIsNotNone(weak_test_finding)

    def test_single_bola_finding_and_blocker_verdict(self):
        """Verify that BOLA finding is generated and acts as a hard production blocker."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        bola_findings = [f for f in findings if "BOLA" in f["title"]]
        self.assertEqual(len(bola_findings), 1, f"Expected exactly 1 BOLA finding, got {len(bola_findings)}")

        # Verify verdict is NOT PRODUCTION READY due to blocker gate
        verdict = summary["verdict"]
        self.assertEqual(verdict["verdict_status"], "NOT PRODUCTION READY")
        self.assertGreater(len(verdict["gate_failures"]), 0)

    def test_bola_runtime_never_uses_synthetic_identities(self):
        """A missing owner/attacker fixture must block, never fabricate BOLA evidence."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        endpoint = next(n for n in graph.nodes_of_type(NodeType.API_ENDPOINT) if n.name == "GET /api/resume/{id}")
        bola_runtime = next(c for c in graph.get_checks_for_target(endpoint.id) if "BOLA-RUNTIME" in c.id)

        self.assertEqual(bola_runtime.status, CheckStatus.BLOCKED)
        self.assertIn("no synthetic identities", bola_runtime.unverified_reason)
        self.assertFalse(any(e.evidence_type == EvidenceType.AUTH_BOUNDARY_TEST for e in evidence_store.find_by_target(endpoint.id)))
        self.assertGreater(summary["completeness"]["check_obligations"]["blocked"], 0)

    def test_untrusted_runtime_never_executes_on_control_plane_host(self):
        """Runtime API and test obligations wait for the container adapters."""
        graph, evidence_store, _ = run_full_audit(FIXTURE_PATH)
        runtime_checks = [
            check for check in graph.audit_checks.values()
            if check.execution_tier.value in {"RUNTIME_HTTP", "TEST_RUNNER"}
        ]
        self.assertTrue(runtime_checks)
        self.assertTrue(all(check.status in (CheckStatus.BLOCKED, CheckStatus.NOT_APPLICABLE) for check in runtime_checks))
        self.assertFalse(any(e.evidence_type == EvidenceType.TEST_EXECUTION for e in evidence_store.all()))

    def test_agent_registry_requires_evidence_for_findings(self):
        """Reasoning agents can propose findings but cannot create evidence-free truth."""
        registry = AgentRegistry()
        self.assertGreaterEqual(len(registry.all()), 14)

        unsupported = AgentProposal(
            agent_id="AGENT-SECURITY", output=AgentOutput.FINDING_PROPOSAL,
            target_ids=["API-0001"], summary="Unproven security assertion", confidence=0.8,
        )
        self.assertFalse(registry.validate_proposal(unsupported)[0])

        supported = AgentProposal(
            agent_id="AGENT-SECURITY", output=AgentOutput.FINDING_PROPOSAL,
            target_ids=["API-0001"], summary="Evidence-backed security proposal", evidence_ids=["EV-00001"], confidence=0.8,
        )
        self.assertTrue(registry.validate_proposal(supported)[0])

    def test_hardened_sandbox_requires_contract_and_redacts_secrets(self):
        """Container supervisor must require a contract and use only hardened Docker flags."""
        commands: list[list[str]] = []

        def fake_executor(command, cwd, timeout):
            commands.append(command)
            if command[:2] == ["docker", "port"]:
                return CommandResult(0, "127.0.0.1:43821\n")
            return CommandResult(0, "ok")

        contract = RuntimeContract.from_dict({
            "start_command": ["python", "-m", "uvicorn", "app:app"], "internal_port": 8123,
            "environment": {"API_TOKEN": "not-for-evidence"}, "startup_timeout_seconds": 1,
        })
        with tempfile.TemporaryDirectory() as temp_dir, patch("packages.sandbox.container_runtime.shutil.which", return_value="docker"):
            root = Path(temp_dir)
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            supervisor = DockerSandboxSupervisor(executor=fake_executor, health_probe=lambda url, timeout: 200)
            execution = supervisor.start(root, contract)

        self.assertEqual(execution.status, "HEALTHY")
        self.assertIn("--network", commands[0])
        self.assertIn("none", commands[0])
        run_command = next(command for command in commands if command[:2] == ["docker", "run"])
        self.assertIn("--read-only", run_command)
        self.assertIn("--cap-drop", run_command)
        self.assertIn("no-new-privileges", run_command)
        self.assertNotIn("not-for-evidence", str(execution.commands))
        self.assertIn("API_TOKEN=[REDACTED]", str(execution.commands))

    def test_sandbox_blocks_when_runtime_contract_is_absent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            execution = DockerSandboxSupervisor().start(root)
        self.assertEqual(execution.status, "BLOCKED")
        self.assertIn("runtime-contract", execution.reason)


if __name__ == "__main__":
    unittest.main()
