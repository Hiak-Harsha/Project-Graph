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

from packages.discovery import (
    build_audit_task_manifest,
    discover_api_endpoints,
    discover_files,
    discover_ui_elements,
    fingerprint_project,
)
from packages.evidence import EvidenceStore, reset_evidence_counter
from packages.intelligence import CompletenessEngine, CrossCheckEngine, VerdictEngine
from packages.project_graph.models import NodeType, reset_id_counters
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
            check_count = conn.execute("SELECT COUNT(*) FROM audit_checks").fetchone()[0]
            evidence_count = conn.execute("SELECT COUNT(*) FROM evidence_records").fetchone()[0]
            self.assertGreaterEqual(check_count, 60)
            self.assertGreater(evidence_count, 15)
            conn.close()
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

    def test_dynamic_test_execution_and_assertion_quality(self):
        """Verify test runner executes tests and detects trivial assertions."""
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


if __name__ == "__main__":
    unittest.main()
