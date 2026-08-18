"""
Phase: DATABASE DISCOVERY (spec Milestone 1 §13)

Discovers database schemas, models, tables, columns, constraints, and relationships
from Prisma schemas, SQLAlchemy/Django models, and raw SQL files.
Creates DATABASE_ENTITY for tables/models and DATABASE_FIELD for columns.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import EdgeRelationship, GraphEdge, GraphNode, NodeType, next_id
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
        field_nodes = []
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith("//") and not line.startswith("@@"):
                parts = line.split()
                if len(parts) >= 2:
                    fname, ftype = parts[0], parts[1]
                    is_pk = "@id" in line
                    is_fk = "@relation" in line
                    fields.append({"name": fname, "type": ftype, "is_pk": is_pk, "is_fk": is_fk})

                    field_node = GraphNode(
                        id=next_id(NodeType.DATABASE_FIELD),
                        node_type=NodeType.DATABASE_FIELD,
                        name=f"{model_name}.{fname}",
                        metadata={
                            "table_name": model_name.lower(),
                            "field_name": fname,
                            "data_type": ftype,
                            "is_primary_key": is_pk,
                            "is_foreign_key": is_fk,
                            "file": rel_name,
                        },
                    )
                    graph.add_node(field_node)
                    field_nodes.append(field_node)
                    out.append(field_node)

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
                "field_count": len(fields),
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)

        # Connect entity to fields
        for fn in field_nodes:
            graph.add_edge(GraphEdge(source=node.id, relationship=EdgeRelationship.CONTAINS, target=fn.id))

    return out


def _discover_sql(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for m in SQL_CREATE_TABLE_PATTERN.finditer(text):
        tbl_name = m.group(1).replace('"', "").replace("'", "").strip()
        body = m.group(2)
        fields = []
        field_nodes = []
        for line in body.split(","):
            line = line.strip()
            if line and not line.upper().startswith(("PRIMARY KEY", "CONSTRAINT", "FOREIGN KEY", "UNIQUE", "INDEX")):
                parts = line.split()
                if len(parts) >= 2:
                    col_name, col_type = parts[0], parts[1]
                    is_pk = "PRIMARY KEY" in line.upper()
                    fields.append({"name": col_name, "type": col_type, "is_pk": is_pk})

                    field_node = GraphNode(
                        id=next_id(NodeType.DATABASE_FIELD),
                        node_type=NodeType.DATABASE_FIELD,
                        name=f"{tbl_name}.{col_name}",
                        metadata={
                            "table_name": tbl_name.lower(),
                            "field_name": col_name,
                            "data_type": col_type,
                            "is_primary_key": is_pk,
                            "file": rel_name,
                        },
                    )
                    graph.add_node(field_node)
                    field_nodes.append(field_node)
                    out.append(field_node)

        line_no = text[: m.start()].count("\n") + 1
        node = GraphNode(
            id=next_id(NodeType.DATABASE_ENTITY),
            node_type=NodeType.DATABASE_ENTITY,
            name=f"Table: {tbl_name}",
            metadata={
                "table_name": tbl_name.lower(),
                "model_name": tbl_name,
                "orm": "sql",
                "fields": fields,
                "field_count": len(fields),
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)

        for fn in field_nodes:
            graph.add_edge(GraphEdge(source=node.id, relationship=EdgeRelationship.CONTAINS, target=fn.id))

    return out


def _discover_sqlalchemy_models(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for m in SQLALCHEMY_MODEL_PATTERN.finditer(text):
        model_name = m.group(1)
        # Parse table name attribute
        tbl_match = re.search(rf"class\s+{model_name}[^:]*:[^=]*__tablename__\s*=\s*['\"]([^'\"]+)['\"]", text)
        tbl_name = tbl_match.group(1) if tbl_match else model_name.lower()

        # Parse columns
        cols = []
        field_nodes = []
        for col_match in re.finditer(r"([A-Za-z0-9_]+)\s*=\s*Column\(([^)]*)\)", text):
            cname = col_match.group(1)
            cargs = col_match.group(2)
            is_pk = "primary_key=True" in cargs
            is_fk = "ForeignKey(" in cargs
            cols.append({"name": cname, "args": cargs, "is_pk": is_pk, "is_fk": is_fk})

            field_node = GraphNode(
                id=next_id(NodeType.DATABASE_FIELD),
                node_type=NodeType.DATABASE_FIELD,
                name=f"{model_name}.{cname}",
                metadata={
                    "table_name": tbl_name,
                    "field_name": cname,
                    "is_primary_key": is_pk,
                    "is_foreign_key": is_fk,
                    "file": rel_name,
                },
            )
            graph.add_node(field_node)
            field_nodes.append(field_node)
            out.append(field_node)

        line_no = text[: m.start()].count("\n") + 1
        node = GraphNode(
            id=next_id(NodeType.DATABASE_ENTITY),
            node_type=NodeType.DATABASE_ENTITY,
            name=f"Model: {model_name}",
            metadata={
                "table_name": tbl_name,
                "model_name": model_name,
                "orm": "sqlalchemy",
                "fields": cols,
                "field_count": len(cols),
                "file": rel_name,
                "line": line_no,
            },
        )
        graph.add_node(node)
        out.append(node)

        for fn in field_nodes:
            graph.add_edge(GraphEdge(source=node.id, relationship=EdgeRelationship.CONTAINS, target=fn.id))

    return out


def discover_database_entities(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    results: list[GraphNode] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in ("node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv") for part in p.parts):
            continue

        rel = str(p.relative_to(root)).replace("\\", "/")
        if p.name.endswith(".prisma") or "schema.prisma" in p.name:
            results.extend(_discover_prisma(p, rel, graph))
        elif p.suffix.lower() == ".sql" and "migration" not in p.name.lower():
            results.extend(_discover_sql(p, rel, graph))
        elif p.suffix.lower() == ".py" and any(k in p.name.lower() for k in ("model", "schema", "db", "entity")):
            results.extend(_discover_sqlalchemy_models(p, rel, graph))

    return results
