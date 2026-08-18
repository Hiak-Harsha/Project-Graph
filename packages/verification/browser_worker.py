"""
Playwright Dynamic Browser Verification Worker (spec Milestone 2 §10-12 / Master Plan §6)

Consumes UI AuditTasks and browser contracts, executes headless Playwright sessions
against active sandbox ExecutionTargets, captures DOM screenshots, network dispatches,
console logs, and reconciles dynamic runtime observations against the static Project Graph.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import (
    AuditCheck,
    AuditStatus,
    CheckStatus,
    ExecutionTier,
    GraphNode,
    NodeType,
)
from packages.project_graph.store import ProjectGraph
from packages.sandbox.environment import detect_environment_capabilities
from packages.sandbox.execution_target import ExecutionTarget
from packages.verification.browser_lab import BrowserLaboratory
from packages.verification.reconciliation import ReconciliationEngine, ReconciliationReport


@dataclass
class BrowserFlowStepResult:
    step_id: str
    target_id: str
    selector: str
    action: str
    success: bool
    url_before: str
    url_after: str
    evidence_id: Optional[str] = None
    error_message: str = ""


@dataclass
class BrowserAuditResult:
    status: str  # COMPLETED | BLOCKED | FAILED | ERROR
    flows_executed: int
    steps_executed: int
    rendered_elements: int
    console_errors_count: int
    network_requests_count: int
    reconciliation: Optional[ReconciliationReport] = None
    step_results: list[BrowserFlowStepResult] = field(default_factory=list)
    reason: str = ""
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.reconciliation:
            d["reconciliation"] = self.reconciliation.to_dict()
        return d


class PlaywrightVerificationWorker:
    """End-to-end worker orchestrating dynamic browser verification and reconciliation."""

    def __init__(
        self,
        root: Path,
        graph: ProjectGraph,
        evidence_store: EvidenceStore,
    ) -> None:
        self.root = root
        self.graph = graph
        self.evidence_store = evidence_store
        self.reconciliation_engine = ReconciliationEngine(graph)
        self.browser_lab = BrowserLaboratory(root, evidence_store, graph)
        self.caps = detect_environment_capabilities()

    def run_browser_verification(
        self,
        target: Optional[ExecutionTarget] = None,
        base_url: Optional[str] = None,
    ) -> BrowserAuditResult:
        """Executes browser verification workflows against target container."""
        active_url = base_url or (target.base_url if target and target.is_healthy else None)
        exec_id = target.execution_id if target else "BROWSER-LOCAL"

        if not active_url:
            self._mark_checks_blocked("No active healthy container ExecutionTarget available for browser execution.")
            return BrowserAuditResult(
                status="BLOCKED",
                flows_executed=0,
                steps_executed=0,
                rendered_elements=0,
                console_errors_count=0,
                network_requests_count=0,
                reason="No active healthy container ExecutionTarget available.",
            )

        # Execute browser laboratory run
        lab_res = self.browser_lab.run_browser_audit(base_url=active_url, execution_id=exec_id)

        if lab_res.get("status") in ("BLOCKED", "ERROR"):
            reason = lab_res.get("reason", "Browser execution blocked.")
            self._mark_checks_blocked(reason)
            return BrowserAuditResult(
                status=lab_res.get("status", "BLOCKED"),
                flows_executed=0,
                steps_executed=lab_res.get("clicks_executed", 0),
                rendered_elements=lab_res.get("rendered_elements", 0),
                console_errors_count=0,
                network_requests_count=0,
                reason=reason,
            )

        # Run DOM reconciliation if live elements were observed
        dom_report = self.reconciliation_engine.reconcile_ui(
            live_dom_selectors=lab_res.get("observed_selectors", [])
        )

        return BrowserAuditResult(
            status="COMPLETED",
            flows_executed=lab_res.get("flows_count", 1),
            steps_executed=lab_res.get("clicks_executed", 0),
            rendered_elements=lab_res.get("rendered_elements", 0),
            console_errors_count=lab_res.get("console_errors_count", 0),
            network_requests_count=lab_res.get("network_count", 0),
            reconciliation=dom_report,
            evidence_ids=lab_res.get("evidence_ids", []),
        )

    def _mark_checks_blocked(self, reason: str) -> None:
        for check in self.graph.audit_checks.values():
            if check.execution_tier == ExecutionTier.RUNTIME_BROWSER:
                check.status = CheckStatus.BLOCKED
                check.unverified_reason = reason
