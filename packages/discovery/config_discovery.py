"""
Phase: CONFIGURATION & EXTERNAL SERVICES DISCOVERY (spec Milestone 1 §14-15)

Discovers environment variables, configuration files, and third-party integrations
(OpenAI, Stripe, GitHub OAuth, AWS S3, SendGrid, Postgres, Redis) with sanitization.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

KNOWN_INTEGRATIONS = {
    "openai": ("OpenAI API", "AI Model Provider"),
    "anthropic": ("Anthropic API", "AI Model Provider"),
    "stripe": ("Stripe", "Payment Gateway"),
    "aws-sdk": ("AWS S3 / Cloud", "Cloud Infrastructure"),
    "boto3": ("AWS S3 / Cloud", "Cloud Infrastructure"),
    "@auth/core": ("OAuth / NextAuth", "Authentication Provider"),
    "passport": ("Passport.js OAuth", "Authentication Provider"),
    "google-auth": ("Google OAuth", "Authentication Provider"),
    "jsonwebtoken": ("JWT Service", "Authentication Provider"),
    "sendgrid": ("SendGrid", "Email Delivery"),
    "resend": ("Resend", "Email Delivery"),
    "redis": ("Redis Cache / Queue", "In-Memory Store / Broker"),
}


def discover_configs_and_services(root: Path, graph: ProjectGraph) -> tuple[list[GraphNode], list[GraphNode]]:
    config_nodes: list[GraphNode] = []
    service_nodes: list[GraphNode] = []

    # 1. Config files (.env.example, .env, docker-compose, tsconfig, etc.)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(root)).replace("\\", "/")
        if any(seg in {".git", "node_modules", ".venv", "venv", "dist", "build"} for seg in path.parts):
            continue

        if path.name.startswith(".env") or path.suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg"} or path.name in {"docker-compose.yml", "docker-compose.yaml", "Dockerfile"}:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                lines = []

            keys = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key = line.split("=")[0].strip()
                    keys.append(key)

            node = GraphNode(
                id=next_id(NodeType.CONFIG),
                node_type=NodeType.CONFIG,
                name=f"Config: {rel_path}",
                metadata={
                    "file": rel_path,
                    "declared_keys": keys[:30],
                    "total_keys": len(keys),
                },
            )
            graph.add_node(node)
            config_nodes.append(node)

    # 2. External Services (derived from package dependencies & env names)
    detected_services = set()
    for pkg_node in graph.nodes_of_type(NodeType.PACKAGE):
        pkg_name = pkg_node.name.lower()
        for marker, (svc_name, svc_type) in KNOWN_INTEGRATIONS.items():
            if marker in pkg_name and svc_name not in detected_services:
                detected_services.add(svc_name)
                s_node = GraphNode(
                    id=next_id(NodeType.EXTERNAL_SERVICE),
                    node_type=NodeType.EXTERNAL_SERVICE,
                    name=svc_name,
                    metadata={
                        "service_type": svc_type,
                        "triggered_by_package": pkg_name,
                        "failure_handling_verified": False,
                    },
                )
                graph.add_node(s_node)
                service_nodes.append(s_node)

    return config_nodes, service_nodes
