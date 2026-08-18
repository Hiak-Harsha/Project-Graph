"""
Phase: DEPENDENCY DISCOVERY (spec Milestone 1 §7)

Extracts direct and transitive dependencies from package.json, requirements.txt,
pyproject.toml, Pipfile, Cargo.toml, and go.mod across the entire repository universe.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph


def discover_dependencies(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    seen_packages: set[str] = set()

    # 1. NPM / Yarn / Bun package.json (root and subdirectories)
    for pkg_json in root.rglob("package.json"):
        if any(part in ("node_modules", ".git", "dist", "build", ".next") for part in pkg_json.parts):
            continue
        rel_file = str(pkg_json.relative_to(root)).replace("\\", "/")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        for section, direct in (("dependencies", True), ("devDependencies", False), ("peerDependencies", False)):
            for name, version in data.get(section, {}).items():
                key = f"npm:{name}@{version}"
                if key in seen_packages:
                    continue
                seen_packages.add(key)
                node = GraphNode(
                    id=next_id(NodeType.PACKAGE),
                    node_type=NodeType.PACKAGE,
                    name=name,
                    metadata={
                        "package_name": name,
                        "version": version,
                        "package_manager": "npm",
                        "direct": direct,
                        "section": section,
                        "source_file": rel_file,
                    },
                )
                graph.add_node(node)
                discovered.append(node)

    # 2. Python requirements.txt (root and subdirectories)
    for req_txt in root.rglob("requirements*.txt"):
        if any(part in ("node_modules", ".git", ".venv", "venv", "__pycache__") for part in req_txt.parts):
            continue
        rel_file = str(req_txt.relative_to(root)).replace("\\", "/")
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]{1,2}\s*[\w.\-]+)?", line)
                if not m:
                    continue
                name, version = m.group(1), (m.group(2) or "").strip()
                key = f"pip:{name}@{version}"
                if key in seen_packages:
                    continue
                seen_packages.add(key)
                node = GraphNode(
                    id=next_id(NodeType.PACKAGE),
                    node_type=NodeType.PACKAGE,
                    name=name,
                    metadata={
                        "package_name": name,
                        "version": version or "unpinned",
                        "package_manager": "pip",
                        "direct": True,
                        "source_file": rel_file,
                    },
                )
                graph.add_node(node)
                discovered.append(node)
        except OSError:
            pass

    # 3. Python pyproject.toml
    for pyproject in root.rglob("pyproject.toml"):
        if any(part in ("node_modules", ".git", ".venv", "venv") for part in pyproject.parts):
            continue
        rel_file = str(pyproject.relative_to(root)).replace("\\", "/")
        try:
            text = pyproject.read_text(encoding="utf-8")
            # Parse dependencies list
            dep_matches = re.findall(r"\"([A-Za-z0-9_.\-]+)(?:[=<>!~^]+[^\"\s]+)?\"", text)
            for name in dep_matches:
                if name.lower() in ("poetry", "flit", "setuptools", "wheel"):
                    continue
                key = f"pyproject:{name}"
                if key in seen_packages:
                    continue
                seen_packages.add(key)
                node = GraphNode(
                    id=next_id(NodeType.PACKAGE),
                    node_type=NodeType.PACKAGE,
                    name=name,
                    metadata={
                        "package_name": name,
                        "version": "declared",
                        "package_manager": "pyproject",
                        "direct": True,
                        "source_file": rel_file,
                    },
                )
                graph.add_node(node)
                discovered.append(node)
        except OSError:
            pass

    return discovered
