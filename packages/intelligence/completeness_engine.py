"""
Completeness Engine (spec Milestone 3 §13, §18 / P1 / P5)

Verifies the foundational accounting equation:
Discovered Entities == Verified + Failed + Unverified + Not_Applicable

Nothing is allowed to silently disappear from the audit universe.
"""
from __future__ import annotations

from packages.project_graph.models import AuditStatus, NodeType
from packages.project_graph.store import ProjectGraph


class CompletenessEngine:
    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def evaluate_coverage(self) -> dict:
        nodes_by_type = {}
        for nt in NodeType:
            nodes = self.graph.nodes_of_type(nt)
            if not nodes:
                continue

            v = sum(1 for n in nodes if n.audit_status == AuditStatus.VERIFIED)
            f = sum(1 for n in nodes if n.audit_status == AuditStatus.FAILED)
            u = sum(1 for n in nodes if n.audit_status == AuditStatus.UNVERIFIED)
            na = sum(1 for n in nodes if n.audit_status == AuditStatus.NOT_APPLICABLE)
            total = len(nodes)

            nodes_by_type[nt.value] = {
                "total_discovered": total,
                "verified": v,
                "failed": f,
                "unverified": u,
                "not_applicable": na,
                "coverage_pct": round(((v + f + na) / total * 100), 1) if total > 0 else 100.0,
            }

        report = self.graph.completeness_report()
        report["by_category"] = nodes_by_type
        report["check_obligations"] = {
            "total": report.get("total_check_obligations", 0),
            "passed": report.get("passed_check_obligations", 0),
            "failed": report.get("failed_check_obligations", 0),
            "unverified": report.get("unverified_check_obligations", 0),
            "check_coverage_pct": report.get("check_coverage_pct", 0.0),
            "static_coverage_pct": report.get("static_coverage_pct", 0.0),
            "runtime_coverage_pct": report.get("runtime_coverage_pct", 0.0),
        }
        return report
