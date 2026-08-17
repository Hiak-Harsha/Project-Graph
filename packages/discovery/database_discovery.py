"""
Phase: DATABASE DISCOVERY (spec Milestone 1 §13)

Discovers database schemas, models, tables, columns, constraints, and relationships
from Prisma schemas, SQLAlchemy/Django models, and raw SQL files.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

PRISMA_MODEL_PATTERN = re.compile(r"model\s+([A-Za-z0-9_]+)\s*{([^}]+)}", re.DOTALL)
SQLALCHEMY_MODEL_PATTERN = re.compile(r"class\s+([A-Za-z0-9_]+)\s*\([^)]*Base[^)]*\):", re.DOTALL)
SQL_CREATE_TABLE_PATTERN = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"']+)\s*\(([^;]+)\);", re.IGNORECASE)


def _discover_prisma(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for m in PRISMA_MODEL_PATTERN.finditer(text):
        model_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith("//") and not line.startswith("@@"):
                parts = line.split()
                if len(parts) >= 2:
                    fields.append({"name": parts[0], "type": parts[1]})

        line_no = text[: m.start()].count("\n") + 1
        node = GraphNode(
            id=next_id(NodeType.DATABASE_ENTITY),
            node_type=NodeType.DATABASE_ENTITY,
            name=f"Model: {model_name}",
            metadata={
                "table_name": model_name.lower(),
                "model_name": model_name,
                "orm": "prisma",
                "fields": fields,
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)
    return out


def _discover_sql(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for m in SQL_CREATE_TABLE_PATTERN.finditer(text):
        table_name = m.group(1).replace('"', '').replace("'", '').split(".")[-1]
        line_no = text[: m.start()].count("\n") + 1
        node = GraphNode(
            id=next_id(NodeType.DATABASE_ENTITY),
            node_type=NodeType.DATABASE_ENTITY,
            name=f"Table: {table_name}",
            metadata={
                "table_name": table_name,
                "model_name": table_name,
                "orm": "raw_sql",
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)
    return out


def _discover_python_models(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for m in SQLALCHEMY_MODEL_PATTERN.finditer(text):
        model_name = m.group(1)
        line_no = text[: m.start()].count("\n") + 1
        node = GraphNode(
            id=next_id(NodeType.DATABASE_ENTITY),
            node_type=NodeType.DATABASE_ENTITY,
            name=f"Model: {model_name}",
            metadata={
                "table_name": model_name.lower() + "s",
                "model_name": model_name,
                "orm": "sqlalchemy",
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)
    return out


def discover_database_entities(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(seg in {".git", "node_modules", ".venv", "venv", "dist", "build"} for seg in path.parts):
            continue
        rel_path = str(path.relative_to(root)).replace("\\", "/")

        if path.suffix == ".prisma":
            discovered += _discover_prisma(path, rel_path, graph)
        elif path.suffix == ".sql":
            discovered += _discover_sql(path, rel_path, graph)
        elif path.suffix == ".py":
            discovered += _discover_python_models(path, rel_path, graph)
    return discovered
