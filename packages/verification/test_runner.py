"""
Test Quality Verifier (spec Milestone 2 §11 / P4)

Analyzes assertion quality (detecting trivial assertions like 'assert True').
Runtime test execution is deliberately blocked until the Docker sandbox adapter
selects and runs the project's real test command.
"""
from __future__ import annotations

import ast
import sys
import time
from pathlib import Path
from typing import Any

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


class TestRunnerVerifier:
    def __init__(self, root: Path, evidence_store: EvidenceStore, graph: ProjectGraph) -> None:
        self.root = root
        self.evidence_store = evidence_store
        self.graph = graph

    def verify_all_tests(self) -> None:
        for node in self.graph.nodes_of_type(NodeType.TEST):
            self.verify_test_suite(node)

    def verify_test_suite(self, node: GraphNode) -> tuple[AuditStatus, dict[str, Any], list[str]]:
        meta = node.metadata
        file_rel = meta.get("file", "")
        file_path = self.root / file_rel

        checks = self.graph.get_checks_for_target(node.id)
        struct_check = next((c for c in checks if "STRUCTURE" in c.id), None)
        exec_check = next((c for c in checks if "EXECUTION" in c.id), None)

        evidence_ids: list[str] = []

        if not file_path.exists():
            node.audit_status = AuditStatus.FAILED
            node.static_status = AuditStatus.FAILED
            node.runtime_status = AuditStatus.FAILED
            if struct_check:
                struct_check.status = CheckStatus.FAILED
            if exec_check:
                exec_check.status = CheckStatus.FAILED
            return AuditStatus.FAILED, {}, []

        # 1. Static Assertion Quality Check
        weak_assertions: list[str] = []
        test_case_count = 0
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"))
            for stmt in ast.walk(tree):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
                    test_case_count += 1
                    # Check for trivial assertions inside test
                    for child in ast.walk(stmt):
                        if isinstance(child, ast.Assert):
                            if isinstance(child.test, ast.Constant) and child.test.value is True:
                                weak_assertions.append(f"{stmt.name}: assert True")
        except Exception:
            pass

        has_weak_tests = len(weak_assertions) > 0
        if struct_check:
            if has_weak_tests:
                struct_check.status = CheckStatus.FAILED
                struct_check.details = {"weak_assertions": weak_assertions}
                ev = self.evidence_store.add(
                    evidence_type=EvidenceType.STATIC_AST_MATCH,
                    target_id=node.id,
                    summary=f"Weak test assertions detected in '{file_rel}': {len(weak_assertions)} tests use trivial 'assert True'.",
                    source_location=file_rel,
                    payload={"weak_assertions": weak_assertions, "file": file_rel},
                )
                evidence_ids.append(ev.id)
                struct_check.evidence_ids.append(ev.id)
            else:
                struct_check.status = CheckStatus.PASSED

        # P6: executing a repository's tests on the control-plane host would
        # grant untrusted code host access. The sandbox test adapter will select
        # and run the project's real test command after container startup.
        if exec_check:
            exec_check.status = CheckStatus.BLOCKED
            exec_check.unverified_reason = "Host test execution is disabled by sandbox policy; requires Docker sandbox test adapter."

        node.static_status = AuditStatus.FAILED if has_weak_tests else AuditStatus.VERIFIED
        node.runtime_status = AuditStatus.UNVERIFIED
        node.refresh_audit_status(checks)
        return node.audit_status, {"blocked": True, "weak_assertions": weak_assertions}, evidence_ids
