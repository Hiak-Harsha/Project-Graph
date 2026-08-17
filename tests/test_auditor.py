"""
Unit & Integration Test Suite for AI Production Engineering Auditor.
Compatible with standard library unittest & pytest.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from packages.discovery import (
    discover_api_endpoints,
    discover_ui_elements,
    fingerprint_project,
    discover_files,
    build_audit_task_manifest,
)
from packages.evidence import EvidenceStore, reset_evidence_counter
from packages.project_graph.models import NodeType, reset_id_counters
from packages.project_graph.store import ProjectGraph
from packages.verification import VerificationRunner
from packages.intelligence import CrossCheckEngine, CompletenessEngine, VerdictEngine
from workers.audit_orchestrator import run_full_audit
from apps.api.server import validate_safe_repo_path

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "sample_career_app"


class TestAuditorPlatform(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()

    def test_api_endpoint_discovery_deduplication(self):
        """Verify BUG-3 fix: FastAPI routes are discovered without double-counting."""
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
        """Verify BUG-1 fix: Path traversal and root scanning are blocked."""
        is_valid, _, err = validate_safe_repo_path("/etc")
        self.assertFalse(is_valid)

        is_valid, _, err = validate_safe_repo_path("C:\\Windows")
        self.assertFalse(is_valid)

        is_valid, resolved, err = validate_safe_repo_path(str(FIXTURE_PATH))
        self.assertTrue(is_valid)
        self.assertIsNotNone(resolved)

    def test_single_bola_finding_and_accurate_scoring(self):
        """Verify that de-duplicated endpoints generate exactly 1 BOLA finding."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        findings = summary["findings"]

        bola_findings = [f for f in findings if "BOLA" in f["title"]]
        self.assertEqual(len(bola_findings), 1, f"Expected exactly 1 BOLA finding, got {len(bola_findings)}")

        critical_count = summary["verdict"]["findings_summary"]["critical"]
        self.assertEqual(critical_count, 1, f"Expected 1 critical finding, got {critical_count}")

        # Verify P1 completeness invariant
        completeness = summary["completeness"]
        self.assertTrue(completeness["complete_accounting"])
        self.assertEqual(completeness["audit_coverage_pct"], 100.0)

    def test_full_orchestrator_pipeline(self):
        """Test full M1 -> M2 -> M3 audit pipeline."""
        graph, evidence_store, summary = run_full_audit(FIXTURE_PATH)
        self.assertEqual(summary["verdict"]["verdict_status"], "NOT PRODUCTION READY")
        self.assertGreater(len(summary["evidence_records"]), 0)
        self.assertEqual(summary["product_understanding"]["product_archetype"], "Career Platform & Resume Intelligence Engine")


if __name__ == "__main__":
    unittest.main()
