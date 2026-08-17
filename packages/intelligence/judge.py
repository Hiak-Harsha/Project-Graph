"""
Judge Engine (spec Milestone 3 §27 / P4)

Applies the strict Evidence Hierarchy to resolve conflicting claims:
Runtime Evidence > Integration / Test Evidence > Static Source AST > Model Inference
"""
from __future__ import annotations

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import AuditStatus, Finding
from packages.project_graph.store import ProjectGraph

EVIDENCE_WEIGHTS = {
    EvidenceType.DOM_INTERACTION: 10,
    EvidenceType.NETWORK_TRACE: 10,
    EvidenceType.AUTH_BOUNDARY_TEST: 10,
    EvidenceType.API_RESPONSE: 9,
    EvidenceType.TEST_EXECUTION: 8,
    EvidenceType.SOURCE_AST: 6,
    EvidenceType.STATIC_ANALYSIS: 5,
    EvidenceType.CONFIG_AUDIT: 5,
    EvidenceType.DATABASE_OBSERVATION: 5,
    EvidenceType.REPRODUCTION_TRACE: 7,
}


class Judge:
    def __init__(self, graph: ProjectGraph, evidence_store: EvidenceStore) -> None:
        self.graph = graph
        self.evidence_store = evidence_store

    def resolve_conflicts(self) -> dict:
        resolved_count = 0
        for finding in self.graph.findings.values():
            weights = []
            for ev_id in finding.evidence_ids:
                ev = self.evidence_store.get(ev_id)
                if ev:
                    weights.append(EVIDENCE_WEIGHTS.get(ev.evidence_type, 1))

            if weights:
                max_w = max(weights)
                # Compute calibrated confidence based on strongest evidence
                finding.confidence = min(0.99, max(0.60, max_w / 10.0))
                resolved_count += 1

        return {"evaluated_findings": resolved_count}
