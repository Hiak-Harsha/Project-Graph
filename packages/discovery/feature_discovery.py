"""
Phase: FEATURE & REQUIREMENT DISCOVERY (spec Milestone 1 §17-18)

Extracts explicit features and requirements from repository README/docs,
and dynamically clusters API/UI modules into high-level features.
Zero hardcoded domain or benchmark assumptions.
"""
from __future__ import annotations

import re
from pathlib import Path
from collections import defaultdict

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph


def discover_features_and_requirements(root: Path, graph: ProjectGraph) -> tuple[list[GraphNode], list[GraphNode]]:
    features: list[GraphNode] = []
    requirements: list[GraphNode] = []

    # 1. Parse README.md / docs for explicit feature bullets
    readme_paths = list(root.glob("README.md")) + list(root.glob("readme.md")) + list(root.glob("docs/*.md"))
    discovered_explicit_feature_names: list[str] = []

    for rpath in readme_paths:
        try:
            content = rpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Look for headers like Features, Capabilities, User Stories, Key Features
        lines = content.splitlines()
        in_feature_section = False
        for line in lines:
            if re.match(r"^#{1,3}\s+(Features|Capabilities|Key Features|User Stories|Requirements)", line, re.IGNORECASE):
                in_feature_section = True
                continue
            elif re.match(r"^#{1,3}\s+", line):
                in_feature_section = False

            if in_feature_section and (line.startswith("- ") or line.startswith("* ") or re.match(r"^\d+\.\s+", line)):
                text = re.sub(r"^[-*\d.]+\s+", "", line).strip()
                if len(text) > 4:
                    discovered_explicit_feature_names.append(text)
                    # Create Requirement node
                    req_node = GraphNode(
                        id=next_id(NodeType.REQUIREMENT),
                        node_type=NodeType.REQUIREMENT,
                        name=text[:60],
                        metadata={
                            "statement": text,
                            "source_doc": str(rpath.relative_to(root)).replace("\\", "/"),
                            "kind": "EXPLICIT",
                        },
                    )
                    graph.add_node(req_node)
                    requirements.append(req_node)

    api_nodes = graph.nodes_of_type(NodeType.API_ENDPOINT)
    ui_nodes = graph.nodes_of_type(NodeType.UI_ELEMENT)
    db_nodes = graph.nodes_of_type(NodeType.DATABASE_ENTITY)

    # 2. Derive Features from explicit README declarations (if present)
    if discovered_explicit_feature_names:
        for feat_text in discovered_explicit_feature_names:
            # Extract meaningful words (len >= 3)
            words = [w.lower() for w in re.findall(r"\b[A-Za-z]{3,}\b", feat_text) if w.lower() not in {"and", "the", "for", "with", "using", "from"}]
            
            matched_apis = [
                a for a in api_nodes
                if any(w in a.name.lower() or w in a.metadata.get("path", "").lower() for w in words)
            ]
            matched_uis = [
                u for u in ui_nodes
                if any(w in u.name.lower() or w in u.metadata.get("file", "").lower() or w in u.metadata.get("label", "").lower() for w in words)
            ]
            matched_dbs = [
                d for d in db_nodes
                if any(w in d.name.lower() for w in words)
            ]

            has_implementation = bool(matched_apis or matched_uis or matched_dbs)

            f_node = GraphNode(
                id=next_id(NodeType.FEATURE),
                node_type=NodeType.FEATURE,
                name=feat_text[:60],
                metadata={
                    "matched_api_count": len(matched_apis),
                    "matched_ui_count": len(matched_uis),
                    "matched_db_count": len(matched_dbs),
                    "has_implementation": has_implementation,
                    "cluster_type": "EXPLICIT_SPECIFICATION",
                },
            )
            graph.add_node(f_node)
            features.append(f_node)
    else:
        # 3. Derive Features dynamically from discovered API prefixes & UI components
        route_clusters: dict[str, list[GraphNode]] = defaultdict(list)
        for a in api_nodes:
            path = a.metadata.get("path", a.name).strip("/")
            prefix = path.split("/")[0] if "/" in path else path
            if prefix in {"api", "v1", "v2"} and "/" in path:
                parts = path.split("/")
                prefix = parts[1] if len(parts) > 1 else parts[0]
            route_clusters[prefix].append(a)

        for prefix, cluster in route_clusters.items():
            feat_name = f"{prefix.replace('-', ' ').replace('_', ' ').title()} Management"
            matched_uis = [u for u in ui_nodes if prefix.lower() in u.name.lower() or prefix.lower() in u.metadata.get("file", "").lower()]
            matched_dbs = [d for d in db_nodes if prefix.lower() in d.name.lower()]

            f_node = GraphNode(
                id=next_id(NodeType.FEATURE),
                node_type=NodeType.FEATURE,
                name=feat_name,
                metadata={
                    "matched_api_count": len(cluster),
                    "matched_ui_count": len(matched_uis),
                    "matched_db_count": len(matched_dbs),
                    "has_implementation": True,
                    "cluster_type": "INFERRED_FROM_ROUTES",
                },
            )
            graph.add_node(f_node)
            features.append(f_node)

        # Fallback if no routes found but UI exists
        if not features and ui_nodes:
            f_node = GraphNode(
                id=next_id(NodeType.FEATURE),
                node_type=NodeType.FEATURE,
                name="Frontend Application Interface",
                metadata={
                    "matched_api_count": 0,
                    "matched_ui_count": len(ui_nodes),
                    "matched_db_count": len(db_nodes),
                    "has_implementation": True,
                    "cluster_type": "INFERRED_FROM_UI",
                },
            )
            graph.add_node(f_node)
            features.append(f_node)

    return features, requirements
