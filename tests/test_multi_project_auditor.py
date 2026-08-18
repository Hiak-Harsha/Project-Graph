"""
Multi-Project & Generic Auditor Verification Suite.

Validates that:
1. An unrelated project (Acme Notes) is audited purely on its own merits without Career Graph bias:
   - Product archetype is NOT "Career Platform"
   - Zero hallucinations of "Missing AI Resume" or "Missing Career Graph"
   - Discovers notes CRUD API and UI controls
   - Missing capabilities (e.g. file upload, AI provider) are marked NOT_APPLICABLE, not FAILED
2. The benchmark (Career Graph) retains its truthful critical findings (BOLA, dead export button)
3. Multi-project intake and revision hashing maintain isolation
"""
from __future__ import annotations

import unittest
from pathlib import Path

from packages.discovery import discover_api_endpoints, discover_ui_elements
from packages.evidence import reset_evidence_counter
from packages.intake import ProjectRegistry, SourceType
from packages.intelligence import ApplicabilityEngine, CapabilityType
from packages.project_graph.models import reset_id_counters
from workers.audit_orchestrator import run_full_audit

ROOT_DIR = Path(__file__).resolve().parents[1]
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"
CAREER_APP_PATH = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"


class TestGenericMultiProjectAuditor(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()

    def test_acme_notes_no_career_graph_leakage(self):
        """Verify Acme Notes is audited without any Career Graph or Resume assumptions."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)
        
        prod_understanding = summary["product_understanding"]
        archetype = prod_understanding["product_archetype"]
        
        # 1. Assert Archetype is accurate and NOT Career Platform
        self.assertNotIn("Career", archetype)
        self.assertNotIn("Resume", archetype)
        self.assertIn("Note", archetype)

        # 2. Assert all findings are generic and none refer to Resume or Career Graph
        findings = summary["findings"]
        for f in findings:
            title_lower = f["title"].lower()
            desc_lower = f["description"].lower()
            self.assertNotIn("resume", title_lower, f"Found leaked resume keyword in finding title: {f['title']}")
            self.assertNotIn("career", title_lower, f"Found leaked career keyword in finding title: {f['title']}")
            self.assertNotIn("resume", desc_lower, f"Found leaked resume keyword in finding description: {f['description']}")

        # 3. Assert Discovered Capabilities
        applicability = summary.get("applicability", {})
        caps = applicability.get("capabilities", {})
        self.assertIn("PARAMETERIZED_RESOURCE_API", caps)
        self.assertIn("UI_INTERACTION", caps)
        self.assertNotIn("FILE_UPLOAD", caps)

        # 4. Assert P1 invariant passes
        self.assertTrue(summary["completeness"]["complete_accounting"])

    def test_career_app_benchmark_evaluation(self):
        """Verify Career App benchmark accurately detects BOLA, dead buttons, and explicit features."""
        graph, evidence_store, summary = run_full_audit(CAREER_APP_PATH)

        prod_understanding = summary["product_understanding"]
        archetype = prod_understanding["product_archetype"]
        self.assertIn("Career", archetype)

        findings = summary["findings"]
        finding_titles = [f["title"] for f in findings]
        
        # Must detect BOLA and Dead UI Interaction
        has_bola = any("BOLA" in t or "Broken Object-Level Authorization" in t for t in finding_titles)
        has_dead_ui = any("Dead UI Interaction" in t for t in finding_titles)
        self.assertTrue(has_bola, f"Expected BOLA finding in {finding_titles}")
        self.assertTrue(has_dead_ui, f"Expected Dead UI finding in {finding_titles}")

        # Verdict should block production due to Critical security finding
        self.assertEqual(summary["verdict"]["certification_state"], "AUDITED_NOT_PRODUCTION_READY")

    def test_multi_project_intake_isolation(self):
        """Verify ProjectRegistry manages multiple projects and revisions independently."""
        registry = ProjectRegistry()
        
        p1 = registry.register_project("Career App", SourceType.LOCAL_DIRECTORY, CAREER_APP_PATH, is_benchmark=True)
        p2 = registry.register_project("Acme Notes", SourceType.LOCAL_DIRECTORY, ACME_NOTES_PATH, is_benchmark=False)
        
        self.assertEqual(len(registry.projects), 2)
        
        # Run audits
        rec1 = registry.run_audit_for_project(p1.project_id)
        rec2 = registry.run_audit_for_project(p2.project_id)
        
        self.assertNotEqual(rec1.audit_id, rec2.audit_id)
        self.assertNotEqual(rec1.revision_id, rec2.revision_id)
        self.assertIn(rec1.audit_id, registry.audit_graphs)
        self.assertIn(rec2.audit_id, registry.audit_graphs)


if __name__ == "__main__":
    unittest.main()
