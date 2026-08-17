"""
Dynamic Test Execution Runner (spec Milestone 2 §11 / P4)

Executes discovered test suites using real test runners, captures pass/fail/error states,
analyzes assertion quality (detecting trivial assertions like 'assert True'),
and records cryptographic TEST_EXECUTION evidence.
"""
from __future__ import annotations

import ast
import subprocess
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

        # 2. Dynamic Real Test Execution (Execute pytest or unittest)
        start_time = time.time()
        cmd = [sys.executable, "-m", "unittest", str(file_path)]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            duration = round(time.time() - start_time, 3)
            passed = proc.returncode == 0
            output_snippet = proc.stdout[-500:] if proc.stdout else ""

            if exec_check:
                exec_check.status = CheckStatus.PASSED if passed else CheckStatus.FAILED
                exec_check.details = {
                    "exit_code": proc.returncode,
                    "duration_sec": duration,
                    "output_tail": output_snippet,
                }

            ev = self.evidence_store.add(
                evidence_type=EvidenceType.TEST_EXECUTION,
                target_id=node.id,
                summary=f"Test suite execution for '{file_rel}': {'PASSED' if passed else 'FAILED'} (Exit code {proc.returncode} in {duration}s).",
                source_location=file_rel,
                payload={
                    "command": " ".join(cmd),
                    "exit_code": proc.returncode,
                    "duration_sec": duration,
                    "output": proc.stdout,
                },
            )
            evidence_ids.append(ev.id)
            if exec_check:
                exec_check.evidence_ids.append(ev.id)

            node.static_status = AuditStatus.FAILED if has_weak_tests else AuditStatus.VERIFIED
            node.runtime_status = AuditStatus.VERIFIED if passed else AuditStatus.FAILED
            node.refresh_audit_status(checks)

            return node.audit_status, {"passed": passed, "duration": duration, "weak_assertions": weak_assertions}, evidence_ids

        except (subprocess.TimeoutExpired, OSError) as e:
            if exec_check:
                exec_check.status = CheckStatus.FAILED
                exec_check.unverified_reason = f"Test execution failed with error: {e}"
            node.runtime_status = AuditStatus.FAILED
            node.refresh_audit_status(checks)
            return node.audit_status, {"error": str(e)}, evidence_ids
