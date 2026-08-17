"""
Phase: FEATURE & REQUIREMENT DISCOVERY (spec Milestone 1 §17-18)

Extracts explicit features and requirements from README/docs,
and clusters API/UI modules into high-level features.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph


def discover_features_and_requirements(root: Path, graph: ProjectGraph) -> tuple[list[GraphNode], list[GraphNode]]:
    features: list[GraphNode] = []
    requirements: list[GraphNode] = []

    # 1. Parse README.md / docs for explicit feature bullets
    readme_paths = list(root.glob("README.md")) + list(root.glob("readme.md")) + list(root.glob("docs/*.md"))
    for rpath in readme_paths:
        try:
            content = rpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Look for headers like Features, Capabilities, User Stories
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

    # 2. Derive Features from API / UI naming clusters if few/no explicit features found
    api_nodes = graph.nodes_of_type(NodeType.API_ENDPOINT)
    ui_nodes = graph.nodes_of_type(NodeType.UI_ELEMENT)

    # Cluster by keywords: Auth, Resume, Career Graph, Profile, Recommendation, Payment, User
    domain_keywords = {
        "Authentication & Authorization": ["auth", "login", "signup", "logout", "token", "user"],
        "Resume Generation & Management": ["resume", "cv", "export", "generate", "template"],
        "Career Graph Visualization": ["graph", "career", "node", "path", "network"],
        "Recommendations & Analytics": ["recommend", "analytic", "match", "score", "insight"],
        "Profile & Account Settings": ["profile", "setting", "account", "preference"],
    }

    for feat_name, kws in domain_keywords.items():
        matched_apis = [a for a in api_nodes if any(kw in a.name.lower() or kw in a.metadata.get("path", "").lower() for kw in kws)]
        matched_uis = [u for u in ui_nodes if any(kw in u.name.lower() or kw in u.metadata.get("file", "").lower() for kw in kws)]

        if matched_apis or matched_uis:
            f_node = GraphNode(
                id=next_id(NodeType.FEATURE),
                node_type=NodeType.FEATURE,
                name=feat_name,
                metadata={
                    "matched_api_count": len(matched_apis),
                    "matched_ui_count": len(matched_uis),
                    "cluster_type": "DERIVED_FROM_CODEBASE",
                },
            )
            graph.add_node(f_node)
            features.append(f_node)

    return features, requirements
