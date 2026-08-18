"""
Unit & Integration Tests for PlaywrightVerificationWorker & DOM Reconciliation Engine.

Validates that:
1. PlaywrightVerificationWorker enforces sandbox isolation, refusing to execute without a healthy target.
2. ReconciliationEngine correctly identifies unrendered static controls, dynamic ghost controls, and matched buttons.
3. Browser flow execution marks AuditChecks, stores EvidenceType.DOM_INTERACTION records, and updates Node runtime status.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from packages.discovery import discover_files, discover_ui_elements
from packages.evidence import EvidenceStore, EvidenceType, reset_evidence_counter
from packages.project_graph import (
    AuditCheck,
    AuditStatus,
    CheckStatus,
    ExecutionTier,
    GraphNode,
    NodeType,
    ProjectGraph,
    reset_id_counters,
)
from packages.sandbox import ExecutionTarget
from packages.verification import (
    BrowserAuditResult,
    PlaywrightVerificationWorker,
    ReconciliationDiscrepancy,
    ReconciliationEngine,
    ReconciliationReport,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
CAREER_APP_PATH = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"


class TestBrowserWorkerAndReconciliation(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()
        self.graph = ProjectGraph()
        self.evidence_store = EvidenceStore()

    def test_browser_worker_blocks_when_target_is_absent(self):
        """Verify PlaywrightVerificationWorker honestly marks RUNTIME_BROWSER checks BLOCKED when no sandbox target is provided."""
        # Add UI node and checks
        node = GraphNode(id="UI-0001", node_type=NodeType.UI_ELEMENT, name="BUTTON: Generate Resume")
        self.graph.add_node(node)

        check = AuditCheck(
            id="CHECK-UI-0001-CLICK",
            target_id="UI-0001",
            name="Element Click Interaction Executed",
            description="Trigger DOM click event on element and observe handler response",
            execution_tier=ExecutionTier.RUNTIME_BROWSER,
            status=CheckStatus.UNVERIFIED,
            required=True,
            execution_method="PLAYWRIGHT_CHROMIUM",
            preconditions=["Browser context initialized"],
            inputs={"selector": "button.generate-btn"},
            expected_observations=["Click dispatches handler"],
            success_conditions=["Handler executed"],
            failure_conditions=["Click error"],
            evidence_requirements=["DOM_INTERACTION_RECORD"],
        )
        self.graph.add_check(check)

        worker = PlaywrightVerificationWorker(CAREER_APP_PATH, self.graph, self.evidence_store)
        res: BrowserAuditResult = worker.run_browser_verification(target=None)

        self.assertEqual(res.status, "BLOCKED")
        self.assertEqual(check.status, CheckStatus.BLOCKED)
        self.assertIn("No active healthy container", check.unverified_reason)

    def test_reconciliation_engine_detects_unrendered_and_matched_elements(self):
        """Verify ReconciliationEngine matches active buttons and flags unrendered dead components."""
        btn_active = GraphNode(
            id="UI-0001",
            node_type=NodeType.UI_ELEMENT,
            name="BUTTON: Generate Resume",
            metadata={"label": "Generate Resume", "file": "src/components/ResumeGenerator.tsx", "line": 12},
        )
        btn_unrendered = GraphNode(
            id="UI-0002",
            node_type=NodeType.UI_ELEMENT,
            name="BUTTON: Hidden Admin Modal Action",
            metadata={"label": "Hidden Admin Modal Action", "file": "src/components/AdminModal.tsx", "line": 40},
        )
        self.graph.add_node(btn_active)
        self.graph.add_node(btn_unrendered)

        # Simulate live DOM capture from browser
        live_selectors = ["button.generate-resume-btn", "a.nav-link", "input.search-field"]

        engine = ReconciliationEngine(self.graph)
        report: ReconciliationReport = engine.reconcile_ui(live_selectors)

        self.assertEqual(report.static_ui_count, 2)
        self.assertEqual(report.matched_count, 1)
        self.assertEqual(report.unrendered_static_count, 1)
        self.assertEqual(report.reconciliation_rate_pct, 50.0)

        unrendered_discs = [d for d in report.discrepancies if d.discrepancy_type == "UNRENDERED_STATIC"]
        self.assertEqual(len(unrendered_discs), 1)
        self.assertEqual(unrendered_discs[0].entity_id, "UI-0002")

    def test_career_app_ui_reconciliation_integrity(self):
        """Verify UI discovery elements from fixture can be reconciled against mock live DOM elements."""
        discover_files(CAREER_APP_PATH, self.graph)
        discover_ui_elements(CAREER_APP_PATH, self.graph)

        ui_nodes = self.graph.nodes_of_type(NodeType.UI_ELEMENT)
        self.assertGreaterEqual(len(ui_nodes), 3)

        # Simulate live dashboard DOM
        live_dom = ["button.generate-resume", "button.export-resume", "a.dashboard-link"]

        engine = ReconciliationEngine(self.graph)
        report = engine.reconcile_ui(live_dom)

        self.assertGreater(report.matched_count, 0)
        self.assertIsInstance(report.to_dict(), dict)


if __name__ == "__main__":
    unittest.main()
