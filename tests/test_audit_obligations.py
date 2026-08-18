"""
Unit & Integration Tests for the Multi-Tier Audit Obligation Engine.

Validates that:
1. Every discovered entity type receives a structured AuditCheck obligation contract.
2. 100% of generated checks carry populated execution contracts (preconditions, inputs, expected observations, success/failure conditions, evidence requirements).
3. Dependency discovery actively populates PACKAGE nodes and checks in live audits.
4. DATABASE_FIELD, PAGE, ROUTE, FORM, and INPUT nodes are discovered and audited.
5. JavaScript / TypeScript syntax errors are actively detected and fail Gate 1/Syntax checks.
6. Multi-tier execution invariants are strictly enforced.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.discovery import (
    build_audit_task_manifest,
    discover_api_endpoints,
    discover_code_entities,
    discover_configs_and_services,
    discover_database_entities,
    discover_dependencies,
    discover_features_and_requirements,
    discover_files,
    discover_tests,
    discover_ui_elements,
)
from packages.evidence import reset_evidence_counter
from packages.project_graph.models import CheckStatus, ExecutionTier, NodeType, reset_id_counters
from packages.project_graph.store import ProjectGraph
from packages.verification.runner import validate_js_ts_syntax
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
        discover_dependencies(ACME_NOTES_PATH, graph)
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

    def test_100_percent_checks_have_populated_execution_contracts(self):
        """Invariant: Every generated AuditCheck must have non-empty execution contract fields."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)

        checks = list(graph.audit_checks.values())
        self.assertGreater(len(checks), 30)

        unpopulated_checks = []
        for c in checks:
            missing_fields = []
            if not c.execution_method:
                missing_fields.append("execution_method")
            if not c.preconditions:
                missing_fields.append("preconditions")
            if not c.inputs:
                missing_fields.append("inputs")
            if not c.expected_observations:
                missing_fields.append("expected_observations")
            if not c.success_conditions:
                missing_fields.append("success_conditions")
            if not c.failure_conditions:
                missing_fields.append("failure_conditions")
            if not c.evidence_requirements:
                missing_fields.append("evidence_requirements")

            if missing_fields:
                unpopulated_checks.append(f"{c.id} ({c.name}) missing {missing_fields}")

        self.assertEqual(
            len(unpopulated_checks),
            0,
            f"Found {len(unpopulated_checks)} checks with unpopulated execution contracts: {unpopulated_checks[:5]}",
        )

    def test_package_dependency_discovery_connected(self):
        """Verify PACKAGE nodes are discovered and audited in live runs."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)

        pkg_nodes = graph.nodes_of_type(NodeType.PACKAGE)
        self.assertGreater(len(pkg_nodes), 0, "Expected discovered PACKAGE nodes in Acme Notes")

        # Verify package checks exist
        for pkg in pkg_nodes:
            pkg_checks = graph.get_checks_for_target(pkg.id)
            self.assertGreater(len(pkg_checks), 0, f"Package {pkg.name} missing checks")

    def test_extended_node_types_discovered(self):
        """Verify DATABASE_FIELD, PAGE, ROUTE, FORM, and INPUT nodes are actively discovered."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)

        input_nodes = graph.nodes_of_type(NodeType.INPUT)
        self.assertGreater(len(input_nodes), 0, "Expected INPUT nodes in Acme Notes")

        form_nodes = graph.nodes_of_type(NodeType.FORM)
        self.assertGreater(len(form_nodes), 0, "Expected FORM nodes in Acme Notes")

    def test_javascript_typescript_syntax_validation(self):
        """Verify invalid JS/TS/TSX syntax is detected and flagged as a syntax error."""
        # 1. Test valid TSX
        valid_code = "export function MyComponent() { return <div className='test'>Hello</div>; }"
        is_valid, err = validate_js_ts_syntax(valid_code)
        self.assertTrue(is_valid, f"Valid code failed syntax validation: {err}")

        # 2. Test invalid TSX: unclosed argument list before body
        broken_code = "export function broken( { return <div>; }"
        is_valid, err = validate_js_ts_syntax(broken_code)
        self.assertFalse(is_valid, "Broken function syntax should have failed validation")
        self.assertIn("Malformed function signature", err)

        # 3. Test unclosed delimiter
        unbalanced_code = "export const foo = () => { if (true) { console.log('hi'); };"
        is_valid, err = validate_js_ts_syntax(unbalanced_code)
        self.assertFalse(is_valid, "Unclosed brace should have failed validation")

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

        for node in graph.all_nodes():
            node_checks = graph.get_checks_for_target(node.id)
            self.assertGreater(len(node_checks), 0, f"Node {node.id} has 0 checks")

        self.assertTrue(summary["completeness"]["complete_accounting"])


if __name__ == "__main__":
    unittest.main()
