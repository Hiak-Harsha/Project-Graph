"""
PostgreSQL Storage Adapter for Project Graph & Audit Universe (spec Milestone 1 §7 / Master Plan §4)

Provides production persistence to PostgreSQL for:
- Projects & Revisions
- Project Graph Nodes & Edges
- 100% Execution Contracts (AuditChecks)
- Dependency DAG Tasks (AuditTasks)
- Tamper-Evident Evidence Vault (EvidenceRecords)
- Audit Findings & Release Verdicts

Includes fallback/mock DB-API connection handling for offline environments and integration testing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from packages.evidence import Evidence, EvidenceStore, EvidenceType
from packages.project_graph.models import (
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
    Severity,
)
from packages.project_graph.store import ProjectGraph

MIGRATION_PATH = Path(__file__).parent / "migrations" / "001_initial_schema.sql"


class PostgresProjectGraphStore:
    """PostgreSQL storage backend for the multi-tenant audit control plane."""

    def __init__(self, connection_or_factory: Any) -> None:
        """
        Accepts a DB-API connection object, connection string, or connection pool.
        Supports standard psycopg2, psycopg3, sqlite3 (with schema translation for testing),
        or any PEP 249 compliant connection.
        """
        self._conn = connection_or_factory

    def get_connection(self) -> Any:
        if hasattr(self._conn, "cursor"):
            return self._conn
        if callable(self._conn):
            return self._conn()
        return self._conn

    def init_schema(self) -> None:
        """Executes the DDL migration to create all required tables and indexes."""
        if not MIGRATION_PATH.exists():
            raise FileNotFoundError(f"Migration file not found at {MIGRATION_PATH}")

        sql_script = MIGRATION_PATH.read_text(encoding="utf-8")
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            # Handle SQLite syntax compatibility in test mock mode
            is_sqlite = "sqlite" in type(conn).__module__.lower()
            if is_sqlite:
                self._init_sqlite_schema(cursor)
            else:
                cursor.execute(sql_script)
            conn.commit()
        finally:
            cursor.close()

    def _init_sqlite_schema(self, cursor: Any) -> None:
        """Creates SQLite-compatible tables for offline testing and validation."""
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                repository_url TEXT,
                default_branch TEXT DEFAULT 'main',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS project_revisions (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                branch TEXT DEFAULT 'main',
                source_path TEXT NOT NULL,
                file_inventory_hash TEXT,
                replay_token TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                name TEXT NOT NULL,
                metadata TEXT,
                static_status TEXT DEFAULT 'UNVERIFIED',
                runtime_status TEXT DEFAULT 'UNVERIFIED',
                audit_status TEXT DEFAULT 'UNVERIFIED',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, revision_id)
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                target_id TEXT NOT NULL,
                static_evidence INTEGER DEFAULT 0,
                runtime_evidence INTEGER DEFAULT 0,
                confidence REAL DEFAULT 1.0,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_checks (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                execution_tier TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                required INTEGER DEFAULT 1,
                execution_method TEXT NOT NULL,
                preconditions TEXT,
                inputs TEXT,
                expected_observations TEXT,
                success_conditions TEXT,
                failure_conditions TEXT,
                evidence_requirements TEXT,
                timeout INTEGER DEFAULT 10,
                risk_level TEXT DEFAULT 'READ_ONLY',
                destructive INTEGER DEFAULT 0,
                unverified_reason TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, revision_id)
            );

            CREATE TABLE IF NOT EXISTS audit_tasks (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                required_checks TEXT,
                status TEXT DEFAULT 'PENDING',
                dependencies TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, revision_id)
            );

            CREATE TABLE IF NOT EXISTS evidence_vault (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                source_location TEXT,
                timestamp REAL NOT NULL,
                payload TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, revision_id)
            );

            CREATE TABLE IF NOT EXISTS audit_findings (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'CONFIRMED',
                confidence REAL DEFAULT 1.0,
                affected_feature TEXT,
                affected_nodes TEXT,
                description TEXT NOT NULL,
                observed_behavior TEXT,
                expected_behavior TEXT,
                evidence_ids TEXT,
                root_cause TEXT,
                recommendation TEXT,
                reproduction_steps TEXT,
                adversarial_verdict TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, revision_id)
            );

            CREATE TABLE IF NOT EXISTS audit_runs (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                certification_state TEXT NOT NULL,
                verdict_status TEXT NOT NULL,
                status_badge TEXT NOT NULL,
                summary_statement TEXT NOT NULL,
                overall_score REAL NOT NULL,
                production_gates TEXT,
                domain_scores TEXT,
                check_summary TEXT,
                findings_summary TEXT,
                top_blockers TEXT,
                elapsed_seconds REAL DEFAULT 0.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

    def save_project(self, project_id: str, name: str, repository_url: Optional[str] = None, default_branch: str = "main") -> None:
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO projects (id, name, repository_url, default_branch)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    repository_url = EXCLUDED.repository_url,
                    default_branch = EXCLUDED.default_branch
                """ if "sqlite" not in type(conn).__module__.lower() else """
                INSERT OR REPLACE INTO projects (id, name, repository_url, default_branch)
                VALUES (?, ?, ?, ?)
                """,
                (project_id, name, repository_url, default_branch),
            )
            conn.commit()
        finally:
            cursor.close()

    def save_revision(
        self,
        revision_id: str,
        project_id: str,
        commit_sha: str,
        source_path: str,
        file_inventory_hash: Optional[str] = None,
        replay_token: Optional[str] = None,
        branch: str = "main",
    ) -> None:
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO project_revisions (id, project_id, commit_sha, branch, source_path, file_inventory_hash, replay_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    commit_sha = EXCLUDED.commit_sha,
                    file_inventory_hash = EXCLUDED.file_inventory_hash,
                    replay_token = EXCLUDED.replay_token
                """ if "sqlite" not in type(conn).__module__.lower() else """
                INSERT OR REPLACE INTO project_revisions (id, project_id, commit_sha, branch, source_path, file_inventory_hash, replay_token)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (revision_id, project_id, commit_sha, branch, source_path, file_inventory_hash, replay_token),
            )
            conn.commit()
        finally:
            cursor.close()

    def save_graph(self, graph: ProjectGraph, project_id: str, revision_id: str) -> None:
        """Atomically persists nodes, edges, checks, and tasks for a given revision."""
        conn = self.get_connection()
        cursor = conn.cursor()
        is_sqlite = "sqlite" in type(conn).__module__.lower()
        ph = "?" if is_sqlite else "%s"

        try:
            # 1. Save Nodes
            for n in graph.all_nodes():
                cursor.execute(
                    f"""
                    INSERT INTO graph_nodes (id, project_id, revision_id, node_type, name, metadata, static_status, runtime_status, audit_status)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """ if is_sqlite else f"""
                    INSERT INTO graph_nodes (id, project_id, revision_id, node_type, name, metadata, static_status, runtime_status, audit_status)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    ON CONFLICT (id, revision_id) DO UPDATE SET
                        static_status = EXCLUDED.static_status,
                        runtime_status = EXCLUDED.runtime_status,
                        audit_status = EXCLUDED.audit_status,
                        metadata = EXCLUDED.metadata
                    """,
                    (
                        n.id,
                        project_id,
                        revision_id,
                        n.node_type.value,
                        n.name,
                        json.dumps(n.metadata),
                        n.static_status.value,
                        n.runtime_status.value,
                        n.audit_status.value,
                    ),
                )

            # 2. Save Edges
            for e in graph.edges:
                cursor.execute(
                    f"""
                    INSERT INTO graph_edges (project_id, revision_id, source_id, relationship, target_id, static_evidence, runtime_evidence, confidence, metadata)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """,
                    (
                        project_id,
                        revision_id,
                        e.source,
                        e.relationship.value,
                        e.target,
                        int(e.static_evidence) if is_sqlite else e.static_evidence,
                        int(e.runtime_evidence) if is_sqlite else e.runtime_evidence,
                        e.confidence,
                        json.dumps(e.metadata) if hasattr(e, "metadata") else "{}",
                    ),
                )

            # 3. Save Audit Checks (100% Execution Contracts)
            for c in graph.audit_checks.values():
                cursor.execute(
                    f"""
                    INSERT INTO audit_checks (
                        id, project_id, revision_id, target_id, name, description, execution_tier,
                        status, required, execution_method, preconditions, inputs, expected_observations,
                        success_conditions, failure_conditions, evidence_requirements, timeout,
                        risk_level, destructive, unverified_reason, details
                    )
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """ if is_sqlite else f"""
                    INSERT INTO audit_checks (
                        id, project_id, revision_id, target_id, name, description, execution_tier,
                        status, required, execution_method, preconditions, inputs, expected_observations,
                        success_conditions, failure_conditions, evidence_requirements, timeout,
                        risk_level, destructive, unverified_reason, details
                    )
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    ON CONFLICT (id, revision_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        unverified_reason = EXCLUDED.unverified_reason,
                        details = EXCLUDED.details
                    """,
                    (
                        c.id,
                        project_id,
                        revision_id,
                        c.target_id,
                        c.name,
                        c.description,
                        c.execution_tier.value,
                        c.status.value,
                        int(c.required) if is_sqlite else c.required,
                        c.execution_method,
                        json.dumps(c.preconditions),
                        json.dumps(c.inputs),
                        json.dumps(c.expected_observations),
                        json.dumps(c.success_conditions),
                        json.dumps(c.failure_conditions),
                        json.dumps(c.evidence_requirements),
                        c.timeout,
                        c.risk_level,
                        int(c.destructive) if is_sqlite else c.destructive,
                        c.unverified_reason,
                        json.dumps(c.details),
                    ),
                )

            # 4. Save Audit Tasks
            for t in graph.audit_tasks.values():
                cursor.execute(
                    f"""
                    INSERT INTO audit_tasks (id, project_id, revision_id, task_type, target_id, required_checks, status, dependencies)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """ if is_sqlite else f"""
                    INSERT INTO audit_tasks (id, project_id, revision_id, task_type, target_id, required_checks, status, dependencies)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    ON CONFLICT (id, revision_id) DO UPDATE SET
                        status = EXCLUDED.status
                    """,
                    (
                        t.id,
                        project_id,
                        revision_id,
                        t.task_type,
                        t.target_id,
                        json.dumps(t.required_checks),
                        t.status,
                        json.dumps(t.dependencies),
                    ),
                )

            # 5. Save Findings
            for f in graph.findings.values():
                cursor.execute(
                    f"""
                    INSERT INTO audit_findings (
                        id, project_id, revision_id, title, category, severity, status,
                        confidence, affected_feature, affected_nodes, description,
                        observed_behavior, expected_behavior, evidence_ids, root_cause,
                        recommendation, reproduction_steps, adversarial_verdict
                    )
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """ if is_sqlite else f"""
                    INSERT INTO audit_findings (
                        id, project_id, revision_id, title, category, severity, status,
                        confidence, affected_feature, affected_nodes, description,
                        observed_behavior, expected_behavior, evidence_ids, root_cause,
                        recommendation, reproduction_steps, adversarial_verdict
                    )
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    ON CONFLICT (id, revision_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        confidence = EXCLUDED.confidence,
                        adversarial_verdict = EXCLUDED.adversarial_verdict
                    """,
                    (
                        f.id,
                        project_id,
                        revision_id,
                        f.title,
                        f.category.value if hasattr(f.category, "value") else str(f.category),
                        f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        f.status,
                        f.confidence,
                        f.affected_feature,
                        json.dumps(f.affected_nodes),
                        f.description,
                        f.observed_behavior,
                        f.expected_behavior,
                        json.dumps(f.evidence_ids),
                        f.root_cause,
                        f.recommendation,
                        json.dumps(f.reproduction_steps),
                        f.adversarial_verdict,
                    ),
                )

            conn.commit()
        finally:
            cursor.close()

    def save_evidence_store(self, store: EvidenceStore, project_id: str, revision_id: str) -> None:
        """Persists cryptographic evidence records to the evidence_vault table."""
        conn = self.get_connection()
        cursor = conn.cursor()
        is_sqlite = "sqlite" in type(conn).__module__.lower()
        ph = "?" if is_sqlite else "%s"

        try:
            for ev in store.all():
                cursor.execute(
                    f"""
                    INSERT INTO evidence_vault (id, project_id, revision_id, target_id, evidence_type, summary, sha256_hash, source_location, timestamp, payload)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    """ if is_sqlite else f"""
                    INSERT INTO evidence_vault (id, project_id, revision_id, target_id, evidence_type, summary, sha256_hash, source_location, timestamp, payload)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                    ON CONFLICT (id, revision_id) DO NOTHING
                    """,
                    (
                        ev.id,
                        project_id,
                        revision_id,
                        ev.target_id,
                        ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type),
                        ev.summary,
                        ev.sha256_hash,
                        ev.source_location,
                        ev.timestamp,
                        json.dumps(ev.payload),
                    ),
                )
            conn.commit()
        finally:
            cursor.close()

    def save_audit_run(self, run_id: str, project_id: str, revision_id: str, verdict_summary: dict[str, Any], elapsed_seconds: float = 0.0) -> None:
        """Persists production certification run summary."""
        conn = self.get_connection()
        cursor = conn.cursor()
        is_sqlite = "sqlite" in type(conn).__module__.lower()
        ph = "?" if is_sqlite else "%s"

        try:
            cursor.execute(
                f"""
                INSERT INTO audit_runs (
                    id, project_id, revision_id, certification_state, verdict_status, status_badge,
                    summary_statement, overall_score, production_gates, domain_scores,
                    check_summary, findings_summary, top_blockers, elapsed_seconds
                )
                VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                """ if is_sqlite else f"""
                INSERT INTO audit_runs (
                    id, project_id, revision_id, certification_state, verdict_status, status_badge,
                    summary_statement, overall_score, production_gates, domain_scores,
                    check_summary, findings_summary, top_blockers, elapsed_seconds
                )
                VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                ON CONFLICT (id) DO UPDATE SET
                    certification_state = EXCLUDED.certification_state,
                    overall_score = EXCLUDED.overall_score
                """,
                (
                    run_id,
                    project_id,
                    revision_id,
                    verdict_summary.get("certification_state", "UNVERIFIED"),
                    verdict_summary.get("verdict_status", "PARTIAL"),
                    verdict_summary.get("status_badge", "PARTIAL"),
                    verdict_summary.get("summary_statement", ""),
                    float(verdict_summary.get("overall_score", 0.0)),
                    json.dumps(verdict_summary.get("production_gates", [])),
                    json.dumps(verdict_summary.get("domain_scores", {})),
                    json.dumps(verdict_summary.get("check_summary", {})),
                    json.dumps(verdict_summary.get("findings_summary", {})),
                    json.dumps(verdict_summary.get("top_blockers", [])),
                    elapsed_seconds,
                ),
            )
            conn.commit()
        finally:
            cursor.close()
