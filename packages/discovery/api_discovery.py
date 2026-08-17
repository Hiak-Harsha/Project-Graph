"""
Phase: API DISCOVERY (spec Milestone 1 §9)

Static route discovery for Express, FastAPI, Flask, Django, Next.js API routes.
Flags authentication presence signals and parameter bindings.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

EXPRESS_PATTERN = re.compile(
    r"(?<!@)(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
FASTAPI_FLASK_PATTERN = re.compile(
    r"@(?:app|router|api_router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
DJANGO_PATH_PATTERN = re.compile(
    r"path\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*([A-Za-z0-9_.]+)", re.IGNORECASE
)

AUTH_HINTS = re.compile(
    r"auth|jwt|bearer|token|require_login|login_required|Depends\(|authenticate|passport|verifyToken",
    re.IGNORECASE,
)


def _scan_file(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    seen_routes: set[tuple[str, str, int]] = set()

    # Python backend files (FastAPI, Flask, Django)
    if path.suffix == ".py":
        for m in FASTAPI_FLASK_PATTERN.finditer(text):
            method, route_path = m.group(1).upper(), m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            key = (method, route_path, line_no)
            if key in seen_routes:
                continue
            seen_routes.add(key)

            window = text[max(0, m.start() - 250) : m.end() + 250]
            has_auth = bool(AUTH_HINTS.search(window))

            node = GraphNode(
                id=next_id(NodeType.API_ENDPOINT),
                node_type=NodeType.API_ENDPOINT,
                name=f"{method} {route_path}",
                metadata={
                    "method": method,
                    "path": route_path,
                    "file": rel_name,
                    "line": line_no,
                    "auth_hint_nearby": has_auth,
                    "discovery_method": "python_ast_decorator",
                },
            )
            graph.add_node(node)
            out.append(node)

    # JS/TS backend files (Express, Nest, Next.js)
    elif path.suffix in {".js", ".ts"}:
        for m in EXPRESS_PATTERN.finditer(text):
            method, route_path = m.group(1).upper(), m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            key = (method, route_path, line_no)
            if key in seen_routes:
                continue
            seen_routes.add(key)

            window = text[max(0, m.start() - 250) : m.end() + 250]
            has_auth = bool(AUTH_HINTS.search(window))

            node = GraphNode(
                id=next_id(NodeType.API_ENDPOINT),
                node_type=NodeType.API_ENDPOINT,
                name=f"{method} {route_path}",
                metadata={
                    "method": method,
                    "path": route_path,
                    "file": rel_name,
                    "line": line_no,
                    "auth_hint_nearby": has_auth,
                    "discovery_method": "express_route",
                },
            )
            graph.add_node(node)
            out.append(node)

    # Next.js App / Pages router API detection
    if ("/api/" in rel_name or rel_name.startswith("api/")) and path.suffix in {".js", ".ts"}:
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            if f"export async function {method}" in text or f"export function {method}" in text:
                route_path = "/" + rel_name.replace("pages/", "").replace("app/", "").replace("route.ts", "").replace("route.js", "").rstrip("/")
                key = (method, route_path, 1)
                if key in seen_routes:
                    continue
                seen_routes.add(key)

                node = GraphNode(
                    id=next_id(NodeType.API_ENDPOINT),
                    node_type=NodeType.API_ENDPOINT,
                    name=f"{method} {route_path}",
                    metadata={
                        "method": method,
                        "path": route_path,
                        "file": rel_name,
                        "line": 1,
                        "auth_hint_nearby": bool(AUTH_HINTS.search(text)),
                        "discovery_method": "nextjs_route",
                    },
                )
                graph.add_node(node)
                out.append(node)

    return out


def discover_api_endpoints(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".js", ".ts", ".py"}:
            continue
        if any(seg in {".git", "node_modules", ".venv", "venv", "dist", "build"} for seg in path.parts):
            continue
        rel_path = str(path.relative_to(root)).replace("\\", "/")
        discovered += _scan_file(path, rel_path, graph)
    return discovered
