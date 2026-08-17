"""
Phase: DEPENDENCY DISCOVERY (spec Milestone 1 §7)

Extracts dependencies and maps them to DEP-xxxx nodes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph


def discover_dependencies(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []

    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        for section, direct in (("dependencies", True), ("devDependencies", False)):
            for name, version in data.get(section, {}).items():
                node = GraphNode(
                    id=next_id(NodeType.PACKAGE),
                    node_type=NodeType.PACKAGE,
                    name=name,
                    metadata={
                        "package_name": name,
                        "version": version,
                        "package_manager": "npm",
                        "direct": direct,
                        "source_file": "package.json",
                    },
                )
                graph.add_node(node)
                discovered.append(node)

    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]{1,2}\s*[\w.\-]+)?", line)
                if not m:
                    continue
                name, version = m.group(1), (m.group(2) or "").strip()
                node = GraphNode(
                    id=next_id(NodeType.PACKAGE),
                    node_type=NodeType.PACKAGE,
                    name=name,
                    metadata={
                        "package_name": name,
                        "version": version or "unpinned",
                        "package_manager": "pip",
                        "direct": True,
                        "source_file": "requirements.txt",
                    },
                )
                graph.add_node(node)
                discovered.append(node)
        except OSError:
            pass

    return discovered
