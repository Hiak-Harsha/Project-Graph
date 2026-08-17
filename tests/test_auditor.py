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
- 5-State Certification Model & 7 Production Release Gates
- Runtime Bootstrap Engine candidate contract detection
- Identity Fixture Manager multi-tenant probe matrices
- Static vs Runtime DOM Reconciliation Engine
- End-to-end User Flow & State-Machine Auditing
- Deterministic Audit Reproducibility Manifest
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
from packages.evidence import EvidenceStore, EvidenceType, ReproducibilityEngine, reset_evidence_counter
from packages.intelligence import (
    CertificationState,
    CompletenessEngine,
    CrossCheckEngine,
    VerdictEngine,
)
from packages.orchestration import AgentOutput, AgentProposal, AgentRegistry
from packages.project_graph.models import CheckStatus, NodeType, reset_id_counters
from packages.project_graph.store import ProjectGraph
from packages.sandbox import RuntimeBootstrapEngine
from packages.sandbox.container_runtime import CommandResult, DockerSandboxSupervisor, RuntimeContract
from packages.verification import (
    IdentityFixtureManager,
    ReconciliationEngine,
    UserFlowEngine,
    VerificationRunner,
)
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

    def test_single_bola_finding_and_blocker_verdict(self):
        """Verify that BOLA finding is generated and acts as a hard production blocker."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = list(graph.findings.values())

        bola_findings = [f for f in findings if "BOLA" in f.title or "IDOR" in f.title]
        self.assertEqual(len(bola_findings), 1, "Expected exactly 1 BOLA finding across entire target project")
        self.assertEqual(bola_findings[0].severity.value, "CRITICAL")
        self.assertEqual(bola_findings[0].status, "CONFIRMED")
        self.assertGreater(len(bola_findings[0].evidence_ids), 0)

        # Check verdict gate failures
        verdict = summary["verdict"]
        self.assertEqual(verdict["certification_state"], CertificationState.AUDITED_NOT_PRODUCTION_READY.value)
        self.assertEqual(verdict["verdict_status"], "NOT PRODUCTION READY")
        self.assertGreater(len(verdict["gate_failures"]), 0)

    def test_safe_repo_path_validation(self):
        """Verify path traversal and root scanning are blocked."""
        is_valid_passwd, _, err1 = validate_safe_repo_path("../../../etc/passwd")
        self.assertFalse(is_valid_passwd)

        is_valid_root, _, err2 = validate_safe_repo_path("C:\\")
        self.assertFalse(is_valid_root)
        self.assertIn("blocked for security", err2)

    def test_check_obligations_model_and_persistence(self):
        """Verify first-class AuditCheck generation and SQLite persistence of evidence vault."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        self.assertGreater(len(graph.audit_checks), 50)

        temp_db = Path(tempfile.gettempdir()) / f"test_audit_persistence_{id(graph)}.sqlite"
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

        missing_career_graph = next((f for f in findings if "Career Graph Visualization" in f["title"]), None)
        self.assertIsNotNone(missing_career_graph)
        self.assertEqual(missing_career_graph["category"], "MISSING_REQUIREMENT")

    def test_dynamic_test_execution_and_assertion_quality(self):
        """Verify test runner analyzes assertions and catches weak assert True."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        weak_assertion_finding = next((f for f in findings if "Non-Meaningful Test Assertions" in f["title"]), None)
        self.assertIsNotNone(weak_assertion_finding)
        self.assertEqual(weak_assertion_finding["category"], "TESTING_GAP")

    def test_bola_runtime_never_uses_synthetic_identities(self):
        """A missing owner/attacker fixture must block, never fabricate BOLA evidence."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        endpoint = next(n for n in graph.nodes_of_type(NodeType.API_ENDPOINT) if n.name == "GET /api/resume/{id}")
        bola_runtime = next(c for c in graph.get_checks_for_target(endpoint.id) if "BOLA-RUNTIME" in c.id)

        self.assertEqual(bola_runtime.status, CheckStatus.BLOCKED)
        self.assertIn("no synthetic identities", bola_runtime.unverified_reason)
        self.assertFalse(any(e.evidence_type == EvidenceType.AUTH_BOUNDARY_TEST for e in evidence_store.find_by_target(endpoint.id)))
        self.assertGreater(summary["completeness"]["check_obligations"]["blocked"], 0)

    def test_test_quality_detection_without_host_execution(self):
        """Verify weak assertions are found without executing untrusted tests on host."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        weak_test_finding = next((f for f in findings if "Non-Meaningful Test Assertions" in f["title"]), None)
        self.assertIsNotNone(weak_test_finding)
        self.assertEqual(weak_test_finding["category"], "TESTING_GAP")

    def test_untrusted_runtime_never_executes_on_control_plane_host(self):
        """Runtime API and test obligations wait for the container adapters."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
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

    def test_runtime_agents_require_healthy_sandbox_and_emit_provenance(self):
        """API/Browser adapters receive only a healthy Docker target, never host state."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        execution = summary["verification_stats"]["sandbox_execution"]
        self.assertEqual(execution["status"], "BLOCKED")
        self.assertEqual(summary["verification_stats"]["browser_report"]["status"], "BLOCKED")
        self.assertTrue(any(e.evidence_type == EvidenceType.SANDBOX_EXECUTION for e in evidence_store.all()))

    def test_5_state_certification_and_7_production_gates(self):
        """Verify the 5-state certification model and 7 release gates evaluation."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        verdict = summary["verdict"]

        self.assertIn("certification_state", verdict)
        self.assertEqual(verdict["certification_state"], "AUDITED_NOT_PRODUCTION_READY")
        self.assertEqual(len(verdict["production_gates"]), 7)

        # Check Gate IDs
        gate_ids = [g["gate_id"] for g in verdict["production_gates"]]
        self.assertIn("GATE-1-DISCOVERY", gate_ids)
        self.assertIn("GATE-2-CRITICAL-CHECKS", gate_ids)
        self.assertIn("GATE-3-SECURITY-INTEGRITY", gate_ids)
        self.assertIn("GATE-4-RUNTIME-EXECUTION", gate_ids)
        self.assertIn("GATE-5-EVIDENCE-PROVENANCE", gate_ids)
        self.assertIn("GATE-6-REQUIREMENT-TRACEABILITY", gate_ids)
        self.assertIn("GATE-7-REPRODUCIBILITY", gate_ids)

    def test_runtime_bootstrap_candidate_synthesis(self):
        """Verify bootstrap engine synthesizes candidate contracts from manifests."""
        bootstrap = RuntimeBootstrapEngine(FIXTURE_PATH)
        candidate = bootstrap.detect_candidate()

        self.assertIsNotNone(candidate)
        self.assertIn("FastAPI", candidate.detected_frameworks)
        self.assertEqual(candidate.port, 8000)
        self.assertTrue(candidate.requires_approval)

    def test_identity_fixture_manager_matrix(self):
        """Verify identity fixture manager generates the canonical 4-identity authorization probes."""
        manager = IdentityFixtureManager(FIXTURE_PATH)
        matrix = manager.generate_authorization_matrix("resume-001", owner="user_A")

        self.assertEqual(len(matrix), 4)
        probe_categories = [p.probe_category for p in matrix]
        self.assertIn("OWNER_ACCESS", probe_categories)
        self.assertIn("CROSS_TENANT_ACCESS", probe_categories)
        self.assertIn("UNAUTHENTICATED_ACCESS", probe_categories)
        self.assertIn("ADMIN_ACCESS", probe_categories)

    def test_reconciliation_engine(self):
        """Verify static vs runtime DOM reconciliation engine catches unrendered elements."""
        graph = ProjectGraph()
        discover_ui_elements(FIXTURE_PATH, graph)

        reconciler = ReconciliationEngine(graph)
        # Mock DOM with only 1 rendered button
        report = reconciler.reconcile_ui(["BUTTON: Generate Resume"])

        self.assertEqual(report.static_ui_count, 3)
        self.assertEqual(report.matched_count, 1)
        self.assertEqual(report.unrendered_static_count, 2)
        self.assertGreater(len(report.discrepancies), 0)

    def test_user_flow_engine_breakage_detection(self):
        """Verify user flow engine identifies multi-step journey and pinpoints dead step."""
        graph = ProjectGraph()
        discover_ui_elements(FIXTURE_PATH, graph)
        discover_api_endpoints(FIXTURE_PATH, graph)

        flow_engine = UserFlowEngine(graph)
        flows = flow_engine.discover_and_audit_flows()

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].flow_id, "FLOW-001")
        self.assertEqual(flows[0].broken_step, 4)
        self.assertEqual(flows[0].overall_status.value, "FAILED")

    def test_reproducibility_manifest_generation(self):
        """Verify tamper-evident audit manifest with SHA-256 tokens."""
        evidence_store = EvidenceStore()
        repro = ReproducibilityEngine(evidence_store)

        manifest = repro.generate_manifest(
            audit_id="AUDIT-TEST-001",
            repo_path=str(FIXTURE_PATH),
            commit_sha="abcdef123456",
            certification_state="AUDITED_NOT_PRODUCTION_READY",
        )

        self.assertEqual(manifest.audit_id, "AUDIT-TEST-001")
        self.assertEqual(manifest.commit_sha, "abcdef123456")
        self.assertGreater(len(manifest.replay_token), 32)


if __name__ == "__main__":
    unittest.main()
