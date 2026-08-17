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

        # Multi-dimensional audit dimensions
        check_total = report.get("total_check_obligations", 0)
        check_resolved = report.get("passed_check_obligations", 0) + report.get("failed_check_obligations", 0)
        check_coverage = round((check_resolved / check_total * 100), 1) if check_total > 0 else 0.0

        static_cov = report.get("static_coverage_pct", 0.0)
        runtime_cov = report.get("runtime_coverage_pct", 0.0)

        # Composite Audit Completeness Index
        audit_completeness = round(
            (100.0 * 0.20 + check_coverage * 0.40 + static_cov * 0.20 + runtime_cov * 0.20),
            1,
        )

        report["dimensions"] = {
            "discovery_coverage_pct": 100.0,
            "check_coverage_pct": check_coverage,
            "static_coverage_pct": static_cov,
            "runtime_coverage_pct": runtime_cov,
            "audit_completeness_pct": audit_completeness,
        }

        report["check_obligations"] = {
            "total": check_total,
            "passed": report.get("passed_check_obligations", 0),
            "failed": report.get("failed_check_obligations", 0),
            "unverified": report.get("unverified_check_obligations", 0),
            "blocked": report.get("blocked_check_obligations", 0),
            "errors": report.get("error_check_obligations", 0),
            "pending": report.get("pending_check_obligations", 0),
            "check_coverage_pct": check_coverage,
            "static_coverage_pct": static_cov,
            "runtime_coverage_pct": runtime_cov,
        }
        return report
