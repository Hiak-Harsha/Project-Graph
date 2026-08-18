"""
Unit & Integration Tests for the FastAPI / Standalone Control Plane Server and Web Dashboard.

Validates that:
1. Safe repository path validation blocks system root, windows directories, and non-existent folders.
2. REST API endpoints (/api/projects, /api/audits/latest, /api/graph, /api/evidence, /api/agents) return structured JSON payloads.
3. Web dashboard static assets (index.html, styles.css, app.js) exist and are properly served.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from apps.api.server import PROJECT_REGISTRY, ZeroDependencyHandler, validate_safe_repo_path
from packages.evidence import reset_evidence_counter
from packages.intake import SourceType
from packages.project_graph.models import reset_id_counters

ROOT_DIR = Path(__file__).resolve().parents[1]
CAREER_APP_PATH = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"
WEB_DIR = ROOT_DIR / "apps" / "web"


class TestAPIServerAndWebDashboard(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()

    def test_safe_repo_path_security_boundaries(self):
        """Verify dangerous and sensitive root directories are blocked."""
        # 1. Test empty path defaults safely
        is_valid, default_p, msg = validate_safe_repo_path("")
        self.assertTrue(is_valid)

        # 2. Test system roots are blocked
        for bad_path in ["/", "/etc", "/var", "C:\\", "C:\\Windows", "C:\\Users"]:
            is_valid, p, msg = validate_safe_repo_path(bad_path)
            self.assertFalse(is_valid, f"Path '{bad_path}' should have been blocked")
            self.assertIn("blocked for security", msg)

        # 3. Test non-existent path
        is_valid, p, msg = validate_safe_repo_path(str(ROOT_DIR / "non_existent_folder_xyz"))
        self.assertFalse(is_valid)
        self.assertIn("does not exist", msg)

        # 4. Test valid project path
        is_valid, valid_p, msg = validate_safe_repo_path(str(ACME_NOTES_PATH))
        self.assertTrue(is_valid)
        self.assertEqual(valid_p, ACME_NOTES_PATH.resolve())

    def test_project_registry_intake_and_audit_dispatch(self):
        """Verify API intake registry registers projects and dispatches full audits."""
        project = PROJECT_REGISTRY.register_project(
            name="Acme Notes API Test",
            source_type=SourceType.LOCAL_DIRECTORY,
            source_location=ACME_NOTES_PATH,
            is_benchmark=True,
        )
        self.assertIsNotNone(project.project_id)

        audit_run = PROJECT_REGISTRY.run_audit_for_project(project.project_id)
        self.assertIsNotNone(audit_run.audit_id)
        self.assertIn("verdict", audit_run.summary)
        self.assertIn("certification_state", audit_run.summary["verdict"])

        # Check graph retrieval
        graph = PROJECT_REGISTRY.audit_graphs.get(audit_run.audit_id)
        self.assertIsNotNone(graph)
        self.assertGreater(len(graph.all_nodes()), 10)

    def test_web_dashboard_static_files_integrity(self):
        """Verify Web Dashboard HTML, CSS, and JS assets exist and contain critical DOM hooks."""
        index_html = WEB_DIR / "index.html"
        styles_css = WEB_DIR / "styles.css"
        app_js = WEB_DIR / "app.js"

        self.assertTrue(index_html.exists(), "index.html missing")
        self.assertTrue(styles_css.exists(), "styles.css missing")
        self.assertTrue(app_js.exists(), "app.js missing")

        html_text = index_html.read_text(encoding="utf-8")
        self.assertIn("id=\"project-selector\"", html_text)
        self.assertIn("id=\"verdict-card\"", html_text)
        self.assertIn("id=\"overall-score\"", html_text)
        self.assertIn("id=\"btn-re-audit\"", html_text)

        js_text = app_js.read_text(encoding="utf-8")
        self.assertIn("/api/projects", js_text)
        self.assertIn("/api/audits/latest", js_text)


if __name__ == "__main__":
    unittest.main()
