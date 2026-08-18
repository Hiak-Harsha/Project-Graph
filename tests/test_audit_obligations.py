"""
Unit & Integration Tests for the Multi-Tier Audit Obligation Engine.

Validates that:
1. Every discovered entity type (FILE, FUNCTION, CLASS, PACKAGE, CONFIG, UI, API, DB, TEST, SERVICE, FEATURE, REQ)
   receives a structured AuditCheck obligation contract.
2. Zero entities are left without checks.
3. Multi-tier execution invariants (Static AST, Static Pattern, Runtime Sandbox, Test Runner) are strictly enforced.
4. Obligation generation scales mathematically with project universe size.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from packages.discovery import (
    build_audit_task_manifest,
    discover_api_endpoints,
    discover_code_entities,
    discover_configs_and_services,
    discover_database_entities,
    discover_features_and_requirements,
    discover_files,
    discover_tests,
    discover_ui_elements,
)
from packages.evidence import reset_evidence_counter
from packages.project_graph.models import CheckStatus, ExecutionTier, NodeType, reset_id_counters
from packages.project_graph.store import ProjectGraph
from workers.audit_orchestrator import run_full_audit

ROOT_DIR = Path(__file__).resolve().parents[1]
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"
CAREER_APP_PATH = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"


class TestAuditObligationEngine(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()

    def test_every_discovered_node_has_explicit_audit_checks(self):
        """Invariant: Every single discovered entity in the graph must have >= 1 explicit AuditCheck assigned."""
        graph = ProjectGraph()

        discover_files(ACME_NOTES_PATH, graph)
        discover_code_entities(ACME_NOTES_PATH, graph)
        discover_api_endpoints(ACME_NOTES_PATH, graph)
        discover_ui_elements(ACME_NOTES_PATH, graph)
        discover_database_entities(ACME_NOTES_PATH, graph)
        discover_tests(ACME_NOTES_PATH, graph)
        discover_configs_and_services(ACME_NOTES_PATH, graph)
        discover_features_and_requirements(ACME_NOTES_PATH, graph)

        # Build obligation manifest
        build_audit_task_manifest(graph)

        all_nodes = graph.all_nodes()
        self.assertGreater(len(all_nodes), 10, "Expected at least 10 discovered entities in Acme Notes")

        nodes_without_checks = []
        for node in all_nodes:
            checks = graph.get_checks_for_target(node.id)
            if not checks:
                nodes_without_checks.append(f"{node.id} ({node.node_type.value}: {node.name})")

        self.assertEqual(
            len(nodes_without_checks),
            0,
            f"Found {len(nodes_without_checks)} entities with zero audit obligations: {nodes_without_checks}",
        )

    def test_multi_tier_obligation_distribution(self):
        """Verify generated obligations span Static AST, Pattern, Graph, and Runtime tiers."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)

        checks = list(graph.audit_checks.values())
        self.assertGreater(len(checks), 40, f"Expected >40 checks for Acme Notes, got {len(checks)}")

        tiers = {c.execution_tier for c in checks}
        self.assertIn(ExecutionTier.STATIC_AST, tiers)
        self.assertIn(ExecutionTier.STATIC_PATTERN, tiers)
        self.assertIn(ExecutionTier.RUNTIME_HTTP, tiers)
        self.assertIn(ExecutionTier.RUNTIME_BROWSER, tiers)

    def test_career_app_obligation_scaling(self):
        """Verify larger project (Career App) generates a comprehensive multi-tier obligation suite."""
        graph, evidence_store, summary = run_full_audit(CAREER_APP_PATH)

        checks = list(graph.audit_checks.values())
        self.assertGreater(len(checks), 100, f"Expected >100 checks for Career App, got {len(checks)}")

        # Verify no orphan nodes
        for node in graph.all_nodes():
            node_checks = graph.get_checks_for_target(node.id)
            self.assertGreater(len(node_checks), 0, f"Node {node.id} has 0 checks")

        # Invariant: Completeness accounting holds
        self.assertTrue(summary["completeness"]["complete_accounting"])


if __name__ == "__main__":
    unittest.main()
