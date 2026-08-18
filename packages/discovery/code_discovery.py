"""
Phase: FUNCTION/CLASS DISCOVERY (spec Milestone 1 §8)

Language-aware AST discovery for Python + heuristic & pattern discovery for JS/TS.
Extracts functions, methods, classes, arguments, return signatures, exceptions, and docstrings.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

JS_FUNC_PATTERNS = [
    re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
    re.compile(r"(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"),
    re.compile(r"(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)"),
    re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{"),
]
JS_CLASS_PATTERN = re.compile(r"(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+([A-Za-z_$][\w$]*))?")


def _discover_python_file(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content)
    except (SyntaxError, ValueError, OSError):
        return out

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node) or ""
            args = [a.arg for a in node.args.args]
            is_async = isinstance(node, ast.AsyncFunctionDef)
            
            # Detect return statements and raised exceptions
            has_return = any(isinstance(child, ast.Return) for child in ast.walk(node))
            raises = [
                child.exc.id
                for child in ast.walk(node)
                if isinstance(child, ast.Raise) and isinstance(getattr(child, "exc", None), ast.Name)
            ]
            decorators = [
                d.id if isinstance(d, ast.Name) else (d.attr if isinstance(d, ast.Attribute) else "decorated")
                for d in node.decorator_list
            ]

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
                    "arg_count": len(args),
                    "has_return": has_return,
                    "raises_exceptions": raises,
                    "decorators": decorators,
                    "has_docstring": bool(doc),
                    "docstring": doc[:120] if doc else None,
                    "extraction_method": "ast",
                },
            )
            graph.add_node(n)
            out.append(n)
        elif isinstance(node, ast.ClassDef):
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            doc = ast.get_docstring(node) or ""
            method_names = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            
            n = GraphNode(
                id=next_id(NodeType.CLASS),
                node_type=NodeType.CLASS,
                name=node.name,
                metadata={
                    "file": rel_name,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "bases": bases,
                    "methods": method_names,
                    "method_count": len(method_names),
                    "has_docstring": bool(doc),
                    "docstring": doc[:120] if doc else None,
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

    seen_names: set[str] = set()

    for i, line in enumerate(text.splitlines(), start=1):
        # 1. Classes
        cm = JS_CLASS_PATTERN.search(line)
        if cm:
            cname = cm.group(1)
            base = cm.group(2) if cm.lastindex and cm.lastindex >= 2 else None
            if cname not in seen_names:
                seen_names.add(cname)
                n = GraphNode(
                    id=next_id(NodeType.CLASS),
                    node_type=NodeType.CLASS,
                    name=cname,
                    metadata={
                        "file": rel_name,
                        "line_start": i,
                        "base_class": base,
                        "extraction_method": "heuristic",
                    },
                )
                graph.add_node(n)
                out.append(n)
            continue

        # 2. Functions
        for pattern in JS_FUNC_PATTERNS:
            m = pattern.search(line)
            if m:
                name = m.group(1)
                raw_args = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                args = [a.strip().split(":")[0].strip() for a in raw_args.split(",") if a.strip()]
                is_async = "async" in line

                if name not in seen_names and name not in {"if", "for", "while", "switch", "catch"}:
                    seen_names.add(name)
                    n = GraphNode(
                        id=next_id(NodeType.FUNCTION),
                        node_type=NodeType.FUNCTION,
                        name=name,
                        metadata={
                            "file": rel_name,
                            "line_start": i,
                            "is_async": is_async,
                            "args": args,
                            "arg_count": len(args),
                            "extraction_method": "heuristic",
                        },
                    )
                    graph.add_node(n)
                    out.append(n)
                break

    return out


def discover_code_entities(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    entities: list[GraphNode] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in ("node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv") for part in p.parts):
            continue

        rel = str(p.relative_to(root)).replace("\\", "/")
        if p.suffix.lower() == ".py":
            entities.extend(_discover_python_file(p, rel, graph))
        elif p.suffix.lower() in (".js", ".jsx", ".ts", ".tsx"):
            entities.extend(_discover_js_file(p, rel, graph))

    return entities
