"""
Phase: FUNCTION/CLASS DISCOVERY (spec Milestone 1 §8)

Language-aware AST discovery for Python + heuristic & pattern discovery for JS/TS.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

JS_FUNC_PATTERNS = [
    re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("),
    re.compile(r"(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function"),
    re.compile(r"(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
]


def _discover_python_file(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content)
    except (SyntaxError, ValueError, OSError):
        return out

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check docstrings and arguments
            doc = ast.get_docstring(node) or ""
            args = [a.arg for a in node.args.args]
            is_async = isinstance(node, ast.AsyncFunctionDef)
            n = GraphNode(
                id=next_id(NodeType.FUNCTION),
                node_type=NodeType.FUNCTION,
                name=node.name,
                metadata={
                    "file": rel_name,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "is_async": is_async,
                    "args": args,
                    "docstring": doc[:100] if doc else None,
                    "extraction_method": "ast",
                },
            )
            graph.add_node(n)
            out.append(n)
        elif isinstance(node, ast.ClassDef):
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            doc = ast.get_docstring(node) or ""
            n = GraphNode(
                id=next_id(NodeType.CLASS),
                node_type=NodeType.CLASS,
                name=node.name,
                metadata={
                    "file": rel_name,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "bases": bases,
                    "docstring": doc[:100] if doc else None,
                    "extraction_method": "ast",
                },
            )
            graph.add_node(n)
            out.append(n)
    return out


def _discover_js_file(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for i, line in enumerate(text.splitlines(), start=1):
        for pattern in JS_FUNC_PATTERNS:
            m = pattern.search(line)
            if m:
                name = m.group(1)
                is_class = "class " in line
                n = GraphNode(
                    id=next_id(NodeType.CLASS if is_class else NodeType.FUNCTION),
                    node_type=NodeType.CLASS if is_class else NodeType.FUNCTION,
                    name=name,
                    metadata={
                        "file": rel_name,
                        "line_start": i,
                        "extraction_method": "heuristic",
                    },
                )
                graph.add_node(n)
                out.append(n)
                break
    return out


def discover_code_entities(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if any(seg in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"} for seg in path.parts):
            continue
        if path.suffix == ".py":
            discovered += _discover_python_file(path, rel, graph)
        elif path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
            discovered += _discover_js_file(path, rel, graph)
    return discovered
