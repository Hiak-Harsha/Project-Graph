"""
Adversarial Reviewer (spec Milestone 3 §10 / P2 / P4)

A skeptical auditor pass that formally challenges every candidate finding:
- "What evidence proves this claim wrong?"
- "Is the severity justified by concrete risk or is it speculative?"
- "Does this finding carry cryptographically valid evidence links?"
"""
from __future__ import annotations

from packages.evidence import EvidenceStore
from packages.project_graph.models import Finding
from packages.project_graph.store import ProjectGraph


class AdversarialReviewer:
    def __init__(self, graph: ProjectGraph, evidence_store: EvidenceStore) -> None:
        self.graph = graph
        self.evidence_store = evidence_store

    def review(self) -> dict[str, int]:
        return self.review_all()

    def review_all(self) -> dict[str, int]:
        confirmed_count = 0
        downgraded_count = 0
        rejected_count = 0

        for finding in list(self.graph.findings.values()):
            # Rule 1: Must have at least 1 valid evidence ID
            valid_evs = [self.evidence_store.get(ev_id) for ev_id in finding.evidence_ids if self.evidence_store.get(ev_id)]

            if not valid_evs:
                # No evidence backing this finding -> REJECT per Invariant P2
                finding.status = "REJECTED"
                finding.adversarial_verdict = "REJECT"
                rejected_count += 1
                continue

            # Rule 2: If finding is CRITICAL, verify that concrete attack vector / defect is present
            if finding.severity.value == "CRITICAL":
                has_critical_ev = any(
                    "BOLA" in e.summary or "CRITICAL" in str(e.payload) or "vulnerability" in e.summary.lower()
                    for e in valid_evs
                )
                if not has_critical_ev:
                    finding.severity = "HIGH"  # Downgrade if risk not catastrophic
                    finding.adversarial_verdict = "DOWNGRADE"
                    downgraded_count += 1
                    continue

            # Confirmed with evidence
            finding.status = "CONFIRMED"
            finding.adversarial_verdict = "CONFIRM"
            confirmed_count += 1

        return {
            "confirmed": confirmed_count,
            "downgraded": downgraded_count,
            "rejected": rejected_count,
            "total_reviewed": len(self.graph.findings),
        }
