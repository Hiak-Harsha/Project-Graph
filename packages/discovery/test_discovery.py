"""
Phase: TEST DISCOVERY (spec Milestone 1 §16)

Inventories test files and test suites, so later phases can compute
"Feature X has 0 linked tests" as an explicit testing gap finding.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

TEST_FILE_PATTERN = re.compile(
    r"(\.spec\.[jt]sx?$)|(\.test\.[jt]sx?$)|(^test_.*\.py$)|(_test\.py$)"
)


def discover_tests(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(seg in {".git", "node_modules", ".venv", "venv"} for seg in path.parts):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if TEST_FILE_PATTERN.search(path.name) or "tests" in path.parts or "__tests__" in path.parts:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""

            test_case_matches = re.findall(r"\b(?:it|test)\s*\(\s*[\"']([^\"']+)[\"']", text)
            py_test_matches = re.findall(r"\bdef\s+(test_[A-Za-z0-9_]+)", text)
            test_cases = test_case_matches + py_test_matches

            node = GraphNode(
                id=next_id(NodeType.TEST),
                node_type=NodeType.TEST,
                name=rel,
                metadata={
                    "file": rel,
                    "estimated_case_count": len(test_cases) or 1,
                    "test_cases": test_cases[:20],
                    "framework_guess": "pytest" if path.suffix == ".py" else "jest/vitest/playwright",
                },
            )
            graph.add_node(node)
            discovered.append(node)
    return discovered
