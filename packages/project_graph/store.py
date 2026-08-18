"""
ProjectGraph: In-memory graph representation with SQLite/relational persistence
and P1 completeness invariant checking.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional, Any

from .models import (
    AuditCheck,
    AuditStatus,
    AuditTask,
    CheckStatus,
    ExecutionTier,
    Finding,
    GraphEdge,
    GraphNode,
    NodeType,
    EdgeRelationship,
)


class ProjectGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.audit_tasks: dict[str, AuditTask] = {}
        self.audit_checks: dict[str, AuditCheck] = {}
        self.findings: dict[str, Finding] = {}
        self.metadata: dict[str, Any] = {}

    # -- mutations -----------------------------------------------------
    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self.edges.append(edge)
        return edge

    def add_task(self, task: AuditTask) -> AuditTask:
        self.audit_tasks[task.id] = task
        return task

    def add_check(self, check: AuditCheck) -> AuditCheck:
        self.audit_checks[check.id] = check
        if check.target_id in self.nodes:
            if check.id not in self.nodes[check.target_id].checks:
                self.nodes[check.target_id].checks.append(check.id)
        return check

    def add_finding(self, finding: Finding) -> Finding:
        self.findings[finding.id] = finding
        return finding

    def update_node_status(self, node_id: str, status: AuditStatus) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].audit_status = status

    def recompute_all_audit_statuses(self) -> None:
        for node in self.nodes.values():
            node.refresh_audit_status(self.get_checks_for_target(node.id))

    # -- queries --------------------------------------------------------
    def all_nodes(self) -> list[GraphNode]:
        return list(self.nodes.values())

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_checks_for_target(self, target_id: str) -> list[AuditCheck]:
        return [c for c in self.audit_checks.values() if c.target_id == target_id]

    def nodes_of_type(self, node_type: NodeType) -> list[GraphNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def edges_from(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.source == node_id]

    def edges_to(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.target == node_id]

    def counts_by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes.values():
            out[n.node_type.value] = out.get(n.node_type.value, 0) + 1
        return out

    def status_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes.values():
            out[n.audit_status.value] = out.get(n.audit_status.value, 0) + 1
        return out

    # -- P1 completeness & check obligation accounting -----------------
    def completeness_report(self) -> dict[str, Any]:
        """
        P1 Check-Obligation & Entity Accounting:
        Every discoverable entity and every applicable check obligation
        must terminate in a known status. Nothing is silently dropped.
        """
        # 1. Entity-Level Accounting
        discovered_entities = len(self.nodes)
        verified_entities = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.VERIFIED)
        failed_entities = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.FAILED)
        na_entities = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.NOT_APPLICABLE)
        unverified_entities = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.UNVERIFIED)
        terminal_entities = verified_entities + failed_entities + na_entities

        entity_coverage_pct = round((terminal_entities / discovered_entities * 100), 1) if discovered_entities > 0 else 0.0

        # 2. Check Obligation Accounting (First-class check lifecycle)
        total_checks = len(self.audit_checks)
        passed_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.PASSED)
        failed_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.FAILED)
        unverified_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.UNVERIFIED)
        blocked_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.BLOCKED)
        error_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.ERROR)
        pending_checks = sum(1 for c in self.audit_checks.values() if c.status in (CheckStatus.PENDING, CheckStatus.RUNNING))
        na_checks = sum(1 for c in self.audit_checks.values() if c.status == CheckStatus.NOT_APPLICABLE)
        resolved_checks = passed_checks + failed_checks + na_checks

        check_coverage_pct = round((resolved_checks / total_checks * 100), 1) if total_checks > 0 else 0.0

        # 3. Multi-Tier Breakdown (Static AST vs Runtime Dynamic)
        static_checks = [c for c in self.audit_checks.values() if c.execution_tier in (ExecutionTier.STATIC_AST, ExecutionTier.STATIC_PATTERN, ExecutionTier.STATIC_GRAPH)]
        runtime_checks = [c for c in self.audit_checks.values() if c.execution_tier in (ExecutionTier.TEST_RUNNER, ExecutionTier.RUNTIME_HTTP, ExecutionTier.RUNTIME_BROWSER, ExecutionTier.RUNTIME_TEST)]

        static_total = len(static_checks)
        static_executed = sum(1 for c in static_checks if c.status in (CheckStatus.PASSED, CheckStatus.FAILED, CheckStatus.ERROR))
        static_passed = sum(1 for c in static_checks if c.status == CheckStatus.PASSED)
        static_coverage = round((static_executed / static_total * 100), 1) if static_total > 0 else 0.0
        static_pass_rate = round((static_passed / static_executed * 100), 1) if static_executed > 0 else 0.0

        runtime_total = len(runtime_checks)
        runtime_executed = sum(1 for c in runtime_checks if c.status in (CheckStatus.PASSED, CheckStatus.FAILED, CheckStatus.ERROR))
        runtime_passed = sum(1 for c in runtime_checks if c.status == CheckStatus.PASSED)
        runtime_coverage = round((runtime_executed / runtime_total * 100), 1) if runtime_total > 0 else 0.0
        runtime_pass_rate = round((runtime_passed / runtime_executed * 100), 1) if runtime_executed > 0 else 0.0

        return {
            # Entity dimensions
            "discovered_entities": discovered_entities,
            "verified_entities": verified_entities,
            "failed_entities": failed_entities,
            "na_entities": na_entities,
            "terminal_entities": terminal_entities,
            "unverified_entities": unverified_entities,
            "entity_coverage_pct": entity_coverage_pct,
            "audit_coverage_pct": entity_coverage_pct,
            # Check obligation dimensions (P1 Truth)
            "total_check_obligations": total_checks,
            "passed_check_obligations": passed_checks,
            "failed_check_obligations": failed_checks,
            "unverified_check_obligations": unverified_checks,
            "blocked_check_obligations": blocked_checks,
            "error_check_obligations": error_checks,
            "pending_check_obligations": pending_checks,
            "check_coverage_pct": check_coverage_pct,
            # Multi-tier verification breakdown
            "static_obligations_total": static_total,
            "static_obligations_executed": static_executed,
            "static_obligations_passed": static_passed,
            "static_coverage_pct": static_coverage,
            "static_pass_rate_pct": static_pass_rate,
            "runtime_obligations_total": runtime_total,
            "runtime_obligations_executed": runtime_executed,
            "runtime_obligations_passed": runtime_passed,
            "runtime_coverage_pct": runtime_coverage,
            "runtime_pass_rate_pct": runtime_pass_rate,
            # Invariants
            "complete_accounting": (resolved_checks + unverified_checks + blocked_checks + error_checks + pending_checks) == total_checks and (terminal_entities + unverified_entities) == discovered_entities,
            "audit_fully_resolved": (unverified_checks + blocked_checks + error_checks + pending_checks) == 0 and unverified_entities == 0 and total_checks > 0,
        }

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "audit_tasks": [t.to_dict() for t in self.audit_tasks.values()],
            "audit_checks": [c.to_dict() for c in self.audit_checks.values()],
            "findings": [f.to_dict() for f in self.findings.values()],
            "counts": self.counts_by_type(),
            "status_counts": self.status_counts(),
            "completeness": self.completeness_report(),
        }

    def persist(self, sqlite_path: Path, evidence_store: Any = None) -> None:
        sqlite_path = Path(sqlite_path)
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(sqlite_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT PRIMARY KEY,
                    node_type TEXT,
                    name TEXT,
                    metadata TEXT,
                    audit_status TEXT,
                    static_status TEXT,
                    runtime_status TEXT,
                    checks TEXT
                );
                CREATE TABLE IF NOT EXISTS graph_edges (
                    source TEXT,
                    relationship TEXT,
                    target TEXT,
                    static_evidence INTEGER,
                    runtime_evidence INTEGER,
                    confidence REAL,
                    evidence_level TEXT,
                    metadata TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT,
                    target_id TEXT,
                    required_checks TEXT,
                    status TEXT,
                    dependencies TEXT,
                    results TEXT,
                    evidence_ids TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_checks (
                    id TEXT PRIMARY KEY,
                    target_id TEXT,
                    name TEXT,
                    description TEXT,
                    execution_tier TEXT,
                    status TEXT,
                    required INTEGER,
                    evidence_ids TEXT,
                    details TEXT,
                    unverified_reason TEXT,
                    execution_method TEXT,
                    preconditions TEXT,
                    inputs TEXT,
                    expected_observations TEXT,
                    success_conditions TEXT,
                    failure_conditions TEXT,
                    evidence_requirements TEXT,
                    timeout INTEGER,
                    risk_level TEXT,
                    destructive INTEGER
                );
                CREATE TABLE IF NOT EXISTS evidence_records (
                    id TEXT PRIMARY KEY,
                    evidence_type TEXT,
                    target_id TEXT,
                    summary TEXT,
                    source_location TEXT,
                    sha256_hash TEXT,
                    timestamp TEXT,
                    execution_id TEXT,
                    commit_sha TEXT,
                    environment_id TEXT,
                    tool_version TEXT,
                    producer TEXT,
                    artifact_uri TEXT,
                    mime_type TEXT,
                    payload TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    category TEXT,
                    severity TEXT,
                    status TEXT,
                    confidence REAL,
                    affected_feature TEXT,
                    affected_nodes TEXT,
                    description TEXT,
                    observed_behavior TEXT,
                    expected_behavior TEXT,
                    evidence_ids TEXT,
                    root_cause TEXT,
                    recommendation TEXT,
                    reproduction_steps TEXT,
                    adversarial_verdict TEXT
                );
                """
            )
            # Schema migration for existing SQLite databases
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(evidence_records)").fetchall()}
            for col, col_type in [
                ("execution_id", "TEXT"),
                ("commit_sha", "TEXT"),
                ("environment_id", "TEXT"),
                ("tool_version", "TEXT"),
                ("producer", "TEXT"),
                ("artifact_uri", "TEXT"),
                ("mime_type", "TEXT"),
            ]:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE evidence_records ADD COLUMN {col} {col_type}")
                    except Exception:
                        pass
            conn.executemany(
                "INSERT OR REPLACE INTO graph_nodes VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        n.id,
                        n.node_type.value,
                        n.name,
                        json.dumps(n.metadata),
                        n.audit_status.value,
                        n.static_status.value,
                        n.runtime_status.value,
                        json.dumps(n.checks),
                    )
                    for n in self.nodes.values()
                ],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO graph_edges VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        e.source,
                        e.relationship.value,
                        e.target,
                        int(e.static_evidence),
                        int(e.runtime_evidence),
                        e.confidence,
                        e.evidence_level.value if hasattr(e.evidence_level, "value") else str(e.evidence_level),
                        json.dumps(e.metadata),
                    )
                    for e in self.edges
                ],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO audit_tasks VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        t.id,
                        t.task_type,
                        t.target_id,
                        json.dumps(t.required_checks),
                        t.status,
                        json.dumps(t.dependencies),
                        json.dumps(t.results),
                        json.dumps(t.evidence_ids),
                    )
                    for t in self.audit_tasks.values()
                ],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO audit_checks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        c.id,
                        c.target_id,
                        c.name,
                        c.description,
                        c.execution_tier.value,
                        c.status.value,
                        int(c.required),
                        json.dumps(c.evidence_ids),
                        json.dumps(c.details),
                        c.unverified_reason,
                        c.execution_method,
                        json.dumps(c.preconditions),
                        json.dumps(c.inputs),
                        json.dumps(c.expected_observations),
                        json.dumps(c.success_conditions),
                        json.dumps(c.failure_conditions),
                        json.dumps(c.evidence_requirements),
                        c.timeout,
                        c.risk_level,
                        int(c.destructive),
                    )
                    for c in self.audit_checks.values()
                ],
            )
            if evidence_store is not None:
                conn.executemany(
                    "INSERT OR REPLACE INTO evidence_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            ev.id,
                            ev.evidence_type.value,
                            ev.target_id,
                            ev.summary,
                            ev.source_location,
                            ev.sha256_hash,
                            ev.timestamp,
                            getattr(ev, "execution_id", None),
                            getattr(ev, "commit_sha", None),
                            getattr(ev, "environment_id", None),
                            getattr(ev, "tool_version", "2.0.0-truth"),
                            getattr(ev, "producer", "project-graph-auditor"),
                            getattr(ev, "artifact_uri", None),
                            getattr(ev, "mime_type", "application/json"),
                            json.dumps(ev.payload),
                        )
                        for ev in evidence_store.all()
                    ],
                )
            conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        f.id,
                        f.title,
                        f.category.value,
                        f.severity.value,
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
                    )
                    for f in self.findings.values()
                ],
            )
            conn.commit()
        finally:
            conn.close()
