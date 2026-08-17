"""
Production Verdict Engine (spec Milestone 3 §14, §27)

Calculates transparent domain scores and outputs the definitive Executive Production Verdict:
READY | NOT PRODUCTION READY | READY WITH CONDITIONS
"""
from __future__ import annotations

from packages.project_graph.models import AuditStatus, FindingCategory, Severity
from packages.project_graph.store import ProjectGraph


class VerdictEngine:
    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def compute_verdict(self) -> dict:
        findings = list(self.graph.findings.values())

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL and f.status == "CONFIRMED")
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH and f.status == "CONFIRMED")
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM and f.status == "CONFIRMED")
        low_count = sum(1 for f in findings if f.severity == Severity.LOW and f.status == "CONFIRMED")

        # Compute Domain Scores (0.0 to 10.0)
        # Baseline is 10.0, deductions per confirmed finding severity in that domain
        def domain_score(category: FindingCategory, base=10.0) -> float:
            cat_findings = [f for f in findings if f.category == category and f.status == "CONFIRMED"]
            deduction = 0.0
            for f in cat_findings:
                if f.severity == Severity.CRITICAL:
                    deduction += 3.5
                elif f.severity == Severity.HIGH:
                    deduction += 2.0
                elif f.severity == Severity.MEDIUM:
                    deduction += 1.0
                elif f.severity == Severity.LOW:
                    deduction += 0.5
            return max(1.0, round(base - deduction, 1))

        score_security = domain_score(FindingCategory.SECURITY)
        score_reliability = domain_score(FindingCategory.RELIABILITY)
        score_testing = domain_score(FindingCategory.TESTING_GAP)
        score_ux = domain_score(FindingCategory.DEAD_FUNCTIONALITY)
        score_arch = domain_score(FindingCategory.ARCHITECTURE)
        score_requirements = domain_score(FindingCategory.MISSING_REQUIREMENT)

        # Overall weighted score
        overall = round(
            (
                score_security * 0.25
                + score_reliability * 0.20
                + score_testing * 0.15
                + score_ux * 0.15
                + score_arch * 0.15
                + score_requirements * 0.10
            ),
            1,
        )

        # Deterministic Verdict determination:
        # Any CRITICAL issue or >= 2 HIGH issues immediately marks NOT PRODUCTION READY
        if critical_count > 0 or high_count >= 2 or overall < 7.0:
            status = "NOT PRODUCTION READY"
            status_badge = "FAILED"
        elif high_count == 1 or medium_count >= 3:
            status = "READY WITH CONDITIONS"
            status_badge = "WARNING"
        else:
            status = "PRODUCTION READY"
            status_badge = "PASSED"

        # Extract Top Blockers
        sorted_findings = sorted(
            [f for f in findings if f.status == "CONFIRMED"],
            key=lambda x: (
                0 if x.severity == Severity.CRITICAL else (1 if x.severity == Severity.HIGH else 2)
            ),
        )
        top_blockers = [f.to_dict() for f in sorted_findings[:5]]

        return {
            "verdict_status": status,
            "status_badge": status_badge,
            "overall_score": overall,
            "domain_scores": {
                "Architecture": score_arch,
                "Security": score_security,
                "Reliability": score_reliability,
                "Testing": score_testing,
                "User Experience (UX)": score_ux,
                "Product Requirements": score_requirements,
            },
            "findings_summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "total": len(findings),
            },
            "top_blockers": top_blockers,
        }
