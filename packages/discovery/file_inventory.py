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
}


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        h.update(path.read_bytes())
    except (OSError, UnicodeDecodeError):
        return "unreadable"
    return h.hexdigest()[:16]


def _loc(path: Path) -> int | None:
    try:
        return sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
    except OSError:
        return None


def discover_files(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
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
    return discovered
