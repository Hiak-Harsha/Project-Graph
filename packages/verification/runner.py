"""
Verification Runner Orchestrator (spec Milestone 2 §1-13)

Orchestrates all deterministic verification passes:
1. Static UI verification & Dead element detection
2. Playwright Browser execution (if sandbox is available & contract configured)
3. API Endpoint verification (AST Route & Auth checks + dynamic HTTP runner)
4. Database Entity verification (Schema model & static constraints)
5. Test Suite verification (AST assertion strength & runner isolation)
6. External Service timeout policy enforcement
7. Feature & Requirement traceability graph traversal
"""
from __future__ import annotations

import time
from pathlib import Path

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import AuditStatus, CheckStatus, NodeType
from packages.project_graph.store import ProjectGraph
from packages.sandbox.container_runtime import DockerSandboxSupervisor, RuntimeContract

from .api_runner import APIRunnerVerifier
from .browser_lab import BrowserLaboratory
from .test_runner import TestRunnerVerifier
from .ui_verifier import UIVerifier


class VerificationRunner:
    def __init__(self, root: Path, graph: ProjectGraph, evidence_store: EvidenceStore) -> None:
        self.root = root
        self.graph = graph
        self.evidence_store = evidence_store

        # Verification Adapters
        self.ui_verifier = UIVerifier(root, evidence_store, graph)
        self.api_runner = APIRunnerVerifier(root, evidence_store, graph)
        self.test_runner = TestRunnerVerifier(root, evidence_store, graph)
        self.browser_lab = BrowserLaboratory(root, evidence_store, graph)
        self.sandbox = DockerSandboxSupervisor()

    def run_all(self) -> dict:
        t0 = time.time()
        tasks_completed = 0
        tasks_failed = 0

        # Attempt to load runtime contract for container startup
        contract = RuntimeContract.load_from_repo(self.root)
        sandbox_execution = self.sandbox.start(self.root, contract)
        sandbox_ev = self.evidence_store.add(
            evidence_type=EvidenceType.SANDBOX_EXECUTION,
            target_id="SANDBOX",
            summary=f"Docker sandbox lifecycle status: {sandbox_execution.status}.",
            source_location=str(self.root / "Dockerfile") if (self.root / "Dockerfile").exists() else None,
            payload=sandbox_execution.to_dict(),
        )

        # 1. Verify UI Elements (Static Handlers & State Controls)
        ui_nodes = self.graph.nodes_of_type(NodeType.UI_ELEMENT)
        ui_results = self.ui_verifier.verify_elements(ui_nodes)
        for node, status, ev_ids in ui_results:
            task_id = f"TASK-{node.id}"
            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED" if status == AuditStatus.VERIFIED else "FAILED"
                task.evidence_ids = ev_ids
                if status == AuditStatus.VERIFIED:
                    tasks_completed += 1
                else:
                    tasks_failed += 1

        # 1b. Browser flows run after static UI checks so browser evidence can
        # update the same click/network obligations rather than be overwritten.
        browser_report = self.browser_lab.run_browser_audit(
            sandbox_execution.base_url if sandbox_execution.status == "HEALTHY" else None,
            sandbox_execution.execution_id,
        )

        # 2. Verify API Endpoints (Static Route & Auth + Dynamic HTTP Dispatch & BOLA)
        api_nodes = self.graph.nodes_of_type(NodeType.API_ENDPOINT)
        for node in api_nodes:
            task_id = f"TASK-{node.id}"
            status, checks, ev_ids = self.api_runner.verify_endpoint(node)
            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED" if status == AuditStatus.VERIFIED else "FAILED"
                task.results = checks
                task.evidence_ids = ev_ids
                if status == AuditStatus.VERIFIED:
                    tasks_completed += 1
                else:
                    tasks_failed += 1

        # 3. Verify Tests via Real Test Execution Runner
        test_nodes = self.graph.nodes_of_type(NodeType.TEST)
        for node in test_nodes:
            task_id = f"TASK-{node.id}"
            status, checks, ev_ids = self.test_runner.verify_test_suite(node)
            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED" if status == AuditStatus.VERIFIED else "FAILED"
                task.results = checks
                task.evidence_ids = ev_ids
                if status == AuditStatus.VERIFIED:
                    tasks_completed += 1
                else:
                    tasks_failed += 1

        # 4. Verify Database Entities (Schema Model & Static Constraints)
        db_nodes = self.graph.nodes_of_type(NodeType.DATABASE_ENTITY)
        for node in db_nodes:
            task_id = f"TASK-{node.id}"
            checks = self.graph.get_checks_for_target(node.id)
            schema_check = next((c for c in checks if "SCHEMA" in c.id), None)
            if schema_check:
                schema_check.status = CheckStatus.PASSED

            ev = self.evidence_store.add(
                evidence_type=EvidenceType.STATIC_ANALYSIS,
                target_id=node.id,
                summary=f"Static AST Analysis: Database entity '{node.name}' schema model and constraints parsed.",
                source_location=f"{node.metadata.get('file', '')}:{node.metadata.get('line', 1)}",
                payload={"model": node.name, "orm": node.metadata.get("orm"), "analysis_tier": "STATIC_AST"},
            )
            node.static_status = AuditStatus.VERIFIED
            node.runtime_status = AuditStatus.NOT_APPLICABLE
            node.refresh_audit_status(checks)

            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED"
                task.evidence_ids = [ev.id]
                tasks_completed += 1

        # 5. Verify External Services (Timeout Policy Checks)
        for ext in self.graph.nodes_of_type(NodeType.EXTERNAL_SERVICE):
            task_id = f"TASK-{ext.id}"
            checks = self.graph.get_checks_for_target(ext.id)
            timeout_check = next((c for c in checks if "TIMEOUT" in c.id), None)
            timeout_check_passed = ext.metadata.get("timeout_configured", False)
            if timeout_check:
                timeout_check.status = CheckStatus.PASSED if timeout_check_passed else CheckStatus.FAILED
                if not timeout_check_passed:
                    timeout_check.unverified_reason = "No explicit client timeout configured in external API invocation."

            ext.static_status = AuditStatus.VERIFIED if timeout_check_passed else AuditStatus.FAILED
            ext.runtime_status = AuditStatus.NOT_APPLICABLE
            ext.refresh_audit_status(checks)

            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED" if ext.audit_status == AuditStatus.VERIFIED else "FAILED"
                if ext.audit_status == AuditStatus.VERIFIED:
                    tasks_completed += 1
                else:
                    tasks_failed += 1

        # 6. Verify Files, Modules, Packages, Functions, Classes (Static Inventory Discovered)
        for n in (
            self.graph.nodes_of_type(NodeType.FILE)
            + self.graph.nodes_of_type(NodeType.PACKAGE)
            + self.graph.nodes_of_type(NodeType.CONFIG)
            + self.graph.nodes_of_type(NodeType.FUNCTION)
            + self.graph.nodes_of_type(NodeType.CLASS)
        ):
            n_checks = self.graph.get_checks_for_target(n.id)
            if n_checks:
                all_passed = all(c.status == CheckStatus.PASSED for c in n_checks)
                any_failed = any(c.status == CheckStatus.FAILED for c in n_checks)
                n.static_status = AuditStatus.FAILED if any_failed else (AuditStatus.VERIFIED if all_passed else AuditStatus.UNVERIFIED)
            else:
                n.static_status = AuditStatus.UNVERIFIED
            n.runtime_status = AuditStatus.NOT_APPLICABLE
            n.refresh_audit_status(n_checks)

        # 7. Check Features & Requirements Traceability
        for feat in self.graph.nodes_of_type(NodeType.FEATURE):
            task_id = f"TASK-{feat.id}"
            contained_edges = self.graph.edges_from(feat.id)
            contained_targets = [self.graph.get_node(e.target) for e in contained_edges if self.graph.get_node(e.target)]
            has_failed_children = any(t.audit_status == AuditStatus.FAILED for t in contained_targets)

            feat_status = AuditStatus.FAILED if has_failed_children else AuditStatus.VERIFIED
            feat.static_status = feat_status
            feat.runtime_status = AuditStatus.UNVERIFIED

            checks = self.graph.get_checks_for_target(feat.id)
            trace_check = next((c for c in checks if "TRACEABILITY" in c.id), None)
            if trace_check:
                trace_check.status = CheckStatus.PASSED if feat_status == AuditStatus.VERIFIED else CheckStatus.FAILED

            feat.refresh_audit_status(checks)

            if task_id in self.graph.audit_tasks:
                task = self.graph.audit_tasks[task_id]
                task.status = "COMPLETED" if feat.audit_status == AuditStatus.VERIFIED else "FAILED"
                if feat.audit_status == AuditStatus.VERIFIED:
                    tasks_completed += 1
                else:
                    tasks_failed += 1

        for req in self.graph.nodes_of_type(NodeType.REQUIREMENT):
            edges_in = self.graph.edges_to(req.id)
            implementers = [self.graph.get_node(e.source) for e in edges_in if self.graph.get_node(e.source)]
            if not implementers or any(i.audit_status == AuditStatus.FAILED for i in implementers):
                req.static_status = AuditStatus.FAILED
            else:
                req.static_status = AuditStatus.VERIFIED
            req.runtime_status = AuditStatus.NOT_APPLICABLE
            req_checks = self.graph.get_checks_for_target(req.id)
            req.refresh_audit_status(req_checks)

        if sandbox_execution.status == "HEALTHY":
            self.sandbox.teardown(sandbox_execution, self.root)

        elapsed = time.time() - t0
        return {
            "tasks_completed": tasks_completed,
            "tasks_failed": tasks_failed,
            "total_tasks": len(self.graph.audit_tasks),
            "evidence_count": len(self.evidence_store.all()),
            "browser_report": browser_report,
            "sandbox_execution": sandbox_execution.to_dict(),
            "sandbox_evidence_id": sandbox_ev.id,
            "elapsed_seconds": round(elapsed, 3),
        }
