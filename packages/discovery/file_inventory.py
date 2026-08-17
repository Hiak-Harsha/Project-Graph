"""
Phase: FILE INVENTORY (spec Milestone 1 §5)

"Every file gets an ID." Core completeness guarantee.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

IGNORE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".pytest_cache",
    ".mypy_cache",
    ".gemini",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "AppData",
    "proc",
    "sys",
    "dev",
    "etc",
}

EXCLUSION_POLICIES = {
    ".git": "Version control metadata (audited via Git commit/ref resolution)",
    "node_modules": "Generated external package tree (audited via package.json manifest)",
    "__pycache__": "Compiled Python bytecode cache (ignored for source analysis)",
    ".venv": "Local virtual environment (audited via requirements/pyproject manifest)",
    "venv": "Local virtual environment (audited via requirements/pyproject manifest)",
    "dist": "Build artifacts output directory",
    "build": "Build intermediate output directory",
    ".next": "Next.js compilation output directory",
    ".pytest_cache": "Test runner temporary cache",
    ".mypy_cache": "Type checker cache",
    ".gemini": "Agent temporary worktree",
}

MAX_FILE_LIMIT = 10000


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        h.update(path.read_bytes())
    except (OSError, UnicodeDecodeError):
        return "unreadable"
    return h.hexdigest()[:16]


def _loc(path: Path) -> int | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def discover_files(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    skipped_count = 0
    encountered_exclusions = set()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        # Check exclusion policies
        matching_exclusion = next((part for part in path.parts if part in IGNORE_DIRS), None)
        if matching_exclusion:
            encountered_exclusions.add(matching_exclusion)
            continue

        if len(discovered) >= MAX_FILE_LIMIT:
            skipped_count += 1
            continue

        rel_path = str(path.relative_to(root)).replace("\\", "/")
        is_binary = path.suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".exe",
        }

        node = GraphNode(
            id=next_id(NodeType.FILE),
            node_type=NodeType.FILE,
            name=rel_path,
            metadata={
                "path": rel_path,
                "extension": path.suffix,
                "size_bytes": path.stat().st_size,
                "loc": _loc(path)
                if path.suffix
                in {
                    ".py",
                    ".js",
                    ".jsx",
                    ".ts",
                    ".tsx",
                    ".java",
                    ".go",
                    ".rs",
                    ".sql",
                    ".prisma",
                    ".html",
                    ".css",
                }
                else None,
                "hash": _hash_file(path),
                "binary": is_binary,
            },
        )
        graph.add_node(node)
        discovered.append(node)

    # Record explicit discovery universe accounting
    if not isinstance(graph.metadata, dict):
        graph.metadata = {}
    graph.metadata["file_discovery_universe"] = {
        "files_discovered": len(discovered),
        "files_skipped_due_to_limit": skipped_count,
        "discovery_truncated": skipped_count > 0,
        "max_limit": MAX_FILE_LIMIT,
        "excluded_directories": [
            {"directory": d, "policy": EXCLUSION_POLICIES.get(d, "System/binary ignored path")}
            for d in sorted(encountered_exclusions)
        ],
    }

    return discovered
