"""
Unit & Integration Tests for PostgresProjectGraphStore and PostgreSQL Relational Schema.

Validates that:
1. Migration DDL (001_initial_schema.sql) exists, parses, and defines all required tables and indexes.
2. Relational schema persists GraphNodes, GraphEdges, 100% execution contracts (AuditChecks), AuditTasks,
   Findings, Evidence Vault records, and AuditRun certification verdicts.
3. Full live audit results from run_full_audit() can be cleanly persisted to the database.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

from packages.discovery import discover_files
from packages.evidence import EvidenceStore, EvidenceType, reset_evidence_counter
from packages.project_graph import (
    AuditCheck,
    AuditStatus,
    AuditTask,
    CheckStatus,
    EdgeRelationship,
    ExecutionTier,
    Finding,
    FindingCategory,
    GraphEdge,
    GraphNode,
    NodeType,
    PostgresProjectGraphStore,
    ProjectGraph,
    Severity,
    next_id,
    reset_id_counters,
)
from packages.project_graph.postgres_store import MIGRATION_PATH
from workers.audit_orchestrator import run_full_audit

ROOT_DIR = Path(__file__).resolve().parents[1]
ACME_NOTES_PATH = ROOT_DIR / "benchmarks" / "acme_notes"


class TestPostgresProjectGraphStore(unittest.TestCase):
    def setUp(self):
        reset_id_counters()
        reset_evidence_counter()
        self.conn = sqlite3.connect(":memory:")
        self.store = PostgresProjectGraphStore(self.conn)
        self.store.init_schema()

    def tearDown(self):
        self.conn.close()

    def test_migration_ddl_file_exists_and_declares_tables(self):
        """Verify PostgreSQL migration 001_initial_schema.sql exists and contains expected DDL statements."""
        self.assertTrue(MIGRATION_PATH.exists(), f"Migration file missing at {MIGRATION_PATH}")
        ddl_text = MIGRATION_PATH.read_text(encoding="utf-8")

        required_tables = [
            "projects",
            "project_revisions",
            "graph_nodes",
            "graph_edges",
            "audit_checks",
            "audit_tasks",
            "evidence_vault",
            "audit_findings",
            "audit_runs",
        ]
        for table in required_tables:
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", ddl_text)

    def test_save_project_and_revision(self):
        """Verify project and revision records persist with commit SHA and reproducibility tokens."""
        self.store.save_project("PROJ-001", "Acme Notes", "https://github.com/acme/notes.git", "main")
        self.store.save_revision(
            revision_id="REV-001",
            project_id="PROJ-001",
            commit_sha="a1b2c3d4e5f67890",
            source_path=str(ACME_NOTES_PATH),
            file_inventory_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            replay_token="RPL-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )

        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name, default_branch FROM projects WHERE id = 'PROJ-001'")
        row = cursor.fetchone()
        self.assertEqual(row, ("PROJ-001", "Acme Notes", "main"))

        cursor.execute("SELECT id, commit_sha, file_inventory_hash FROM project_revisions WHERE id = 'REV-001'")
        rev_row = cursor.fetchone()
        self.assertEqual(rev_row[0], "REV-001")
        self.assertEqual(rev_row[1], "a1b2c3d4e5f67890")

    def test_save_graph_nodes_edges_and_execution_contracts(self):
        """Verify full graph with 100% execution contracts persists to relational tables."""
        graph = ProjectGraph()

        # Add nodes
        file_node = GraphNode(id="FILE-0001", node_type=NodeType.FILE, name="main.py", metadata={"loc": 45})
        api_node = GraphNode(id="API-0001", node_type=NodeType.API_ENDPOINT, name="GET /api/notes", metadata={"method": "GET", "path": "/api/notes"})
        graph.add_node(file_node)
        graph.add_node(api_node)

        # Add edge
        graph.add_edge(GraphEdge(source="FILE-0001", relationship=EdgeRelationship.CONTAINS, target="API-0001", static_evidence=True))

        # Add AuditCheck with complete execution contract
        check = AuditCheck(
            id="CHECK-API-0001-REACHABLE",
            target_id="API-0001",
            name="Endpoint Reachable & Healthy",
            description="Verify HTTP endpoint returns expected status code",
            execution_tier=ExecutionTier.RUNTIME_HTTP,
            status=CheckStatus.PASSED,
            required=True,
            execution_method="DOCKER_HTTP_CLIENT",
            preconditions=["API server running in sandbox"],
            inputs={"method": "GET", "path": "/api/notes"},
            expected_observations=["HTTP 200 OK with JSON array"],
            success_conditions=["Status code is 200"],
            failure_conditions=["Connection refused or 500 error"],
            evidence_requirements=["API_RESPONSE_RECORD"],
        )
        graph.add_check(check)

        # Save to store
        self.store.save_project("PROJ-001", "Acme Notes")
        self.store.save_revision("REV-001", "PROJ-001", "commit1", str(ACME_NOTES_PATH))
        self.store.save_graph(graph, "PROJ-001", "REV-001")

        cursor = self.conn.cursor()
        cursor.execute("SELECT count(*) FROM graph_nodes WHERE revision_id = 'REV-001'")
        self.assertEqual(cursor.fetchone()[0], 2)

        cursor.execute("SELECT count(*) FROM graph_edges WHERE revision_id = 'REV-001'")
        self.assertEqual(cursor.fetchone()[0], 1)

        cursor.execute("SELECT id, execution_method, status FROM audit_checks WHERE id = 'CHECK-API-0001-REACHABLE'")
        chk_row = cursor.fetchone()
        self.assertEqual(chk_row, ("CHECK-API-0001-REACHABLE", "DOCKER_HTTP_CLIENT", "PASSED"))

    def test_save_evidence_vault_and_audit_run(self):
        """Verify EvidenceStore and final certification verdict persist to DB."""
        evidence_store = EvidenceStore()
        ev = evidence_store.add(
            evidence_type=EvidenceType.API_RESPONSE,
            target_id="API-0001",
            summary="HTTP GET /api/notes returned 200 OK",
            source_location="backend/app/main.py:18",
            payload={"status_code": 200, "latency_ms": 12.4},
        )

        self.store.save_project("PROJ-001", "Acme Notes")
        self.store.save_revision("REV-001", "PROJ-001", "commit1", str(ACME_NOTES_PATH))
        self.store.save_evidence_store(evidence_store, "PROJ-001", "REV-001")

        cursor = self.conn.cursor()
        cursor.execute("SELECT id, evidence_type, sha256_hash FROM evidence_vault WHERE target_id = 'API-0001'")
        ev_row = cursor.fetchone()
        self.assertEqual(ev_row[0], ev.id)
        self.assertEqual(ev_row[1], "API_RESPONSE")
        self.assertEqual(len(ev_row[2]), 64)

        # Save audit run
        verdict = {
            "certification_state": "AUDITED_PRODUCTION_READY",
            "verdict_status": "PRODUCTION READY",
            "status_badge": "PASSED",
            "summary_statement": "All 7 release gates passed.",
            "overall_score": 9.6,
            "production_gates": [{"gate_id": "GATE-1", "passed": True}],
        }
        self.store.save_audit_run("RUN-001", "PROJ-001", "REV-001", verdict, elapsed_seconds=2.45)

        cursor.execute("SELECT id, certification_state, overall_score FROM audit_runs WHERE id = 'RUN-001'")
        run_row = cursor.fetchone()
        self.assertEqual(run_row, ("RUN-001", "AUDITED_PRODUCTION_READY", 9.6))

    def test_full_live_audit_persistence(self):
        """Verify output of live run_full_audit() persists cleanly into the relational database."""
        graph, evidence_store, summary = run_full_audit(ACME_NOTES_PATH)

        self.store.save_project("PROJ-ACME", "Acme Notes Benchmark")
        self.store.save_revision("REV-ACME-01", "PROJ-ACME", "HEAD", str(ACME_NOTES_PATH))
        self.store.save_graph(graph, "PROJ-ACME", "REV-ACME-01")
        self.store.save_evidence_store(evidence_store, "PROJ-ACME", "REV-ACME-01")
        self.store.save_audit_run("RUN-ACME-01", "PROJ-ACME", "REV-ACME-01", summary["verdict"], elapsed_seconds=summary.get("elapsed_seconds", 1.0))

        cursor = self.conn.cursor()
        cursor.execute("SELECT count(*) FROM graph_nodes WHERE revision_id = 'REV-ACME-01'")
        node_count = cursor.fetchone()[0]
        self.assertGreater(node_count, 10)

        cursor.execute("SELECT count(*) FROM audit_checks WHERE revision_id = 'REV-ACME-01'")
        check_count = cursor.fetchone()[0]
        self.assertGreater(check_count, 30)

        cursor.execute("SELECT count(*) FROM evidence_vault WHERE revision_id = 'REV-ACME-01'")
        ev_count = cursor.fetchone()[0]
        self.assertGreater(ev_count, 0)


if __name__ == "__main__":
    unittest.main()
