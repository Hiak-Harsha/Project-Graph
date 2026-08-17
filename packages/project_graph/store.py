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
    AuditStatus,
    AuditTask,
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

    def add_finding(self, finding: Finding) -> Finding:
        self.findings[finding.id] = finding
        return finding

    def update_node_status(self, node_id: str, status: AuditStatus) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].audit_status = status

    # -- queries --------------------------------------------------------
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

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

    # -- P1 completeness invariant --------------------------------------
    def completeness_report(self) -> dict[str, Any]:
        """
        P1 Invariant: Every discovered entity must end in
        VERIFIED | FAILED | UNVERIFIED | NOT_APPLICABLE.
        Nothing is silently dropped.
        """
        discovered = len(self.nodes)
        verified = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.VERIFIED)
        failed = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.FAILED)
        na = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.NOT_APPLICABLE)
        unverified = sum(1 for n in self.nodes.values() if n.audit_status == AuditStatus.UNVERIFIED)

        terminal = verified + failed + na

        # Coverage is the proportion of entities that have reached a terminal state (verified/failed/na)
        coverage_pct = round((terminal / discovered * 100), 1) if discovered > 0 else 0.0

        return {
            "discovered_entities": discovered,
            "verified_entities": verified,
            "failed_entities": failed,
            "na_entities": na,
            "terminal_entities": terminal,
            "unverified_entities": unverified,
            "audit_coverage_pct": coverage_pct,
            "complete_accounting": (terminal + unverified) == discovered,
            "audit_fully_resolved": unverified == 0 and discovered > 0,
        }

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "audit_tasks": [t.to_dict() for t in self.audit_tasks.values()],
            "findings": [f.to_dict() for f in self.findings.values()],
            "counts": self.counts_by_type(),
            "status_counts": self.status_counts(),
            "completeness": self.completeness_report(),
        }

    def persist(self, db_path: str | Path) -> None:
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(
                """
                DROP TABLE IF EXISTS graph_nodes;
                DROP TABLE IF EXISTS graph_edges;
                DROP TABLE IF EXISTS audit_tasks;
                DROP TABLE IF EXISTS findings;

                CREATE TABLE graph_nodes (
                    id TEXT PRIMARY KEY,
                    node_type TEXT,
                    name TEXT,
                    metadata TEXT,
                    audit_status TEXT
                );
                CREATE TABLE graph_edges (
                    source TEXT,
                    relationship TEXT,
                    target TEXT,
                    static_evidence INTEGER,
                    runtime_evidence INTEGER,
                    confidence REAL,
                    metadata TEXT
                );
                CREATE TABLE audit_tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT,
                    target_id TEXT,
                    required_checks TEXT,
                    status TEXT,
                    dependencies TEXT,
                    results TEXT,
                    evidence_ids TEXT
                );
                CREATE TABLE findings (
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
            conn.executemany(
                "INSERT INTO graph_nodes VALUES (?,?,?,?,?)",
                [
                    (n.id, n.node_type.value, n.name, json.dumps(n.metadata), n.audit_status.value)
                    for n in self.nodes.values()
                ],
            )
            conn.executemany(
                "INSERT INTO graph_edges VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        e.source,
                        e.relationship.value,
                        e.target,
                        int(e.static_evidence),
                        int(e.runtime_evidence),
                        e.confidence,
                        json.dumps(e.metadata),
                    )
                    for e in self.edges
                ],
            )
            conn.executemany(
                "INSERT INTO audit_tasks VALUES (?,?,?,?,?,?,?,?)",
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
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
