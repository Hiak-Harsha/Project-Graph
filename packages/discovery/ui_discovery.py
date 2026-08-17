"""
Phase: UI DISCOVERY (spec Milestone 1 §10-12)

Extracts UI interactive elements (BUTTON, LINK, FORM, INPUT, SELECT, TAB, MODAL)
and analyzes attached handlers for dead button / dead interaction candidate detection.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

ELEMENT_PATTERNS = {
    "BUTTON": re.compile(r"<button\b([^>]*)>(.*?)</button>", re.IGNORECASE | re.DOTALL),
    "LINK": re.compile(r"<(?:a|Link|NavLink)\b([^>]*)>(.*?)</(?:a|Link|NavLink)>", re.IGNORECASE | re.DOTALL),
    "FORM": re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL),
    "INPUT": re.compile(r"<input\b([^>]*)/?>", re.IGNORECASE),
    "SELECT": re.compile(r"<select\b([^>]*)>(.*?)</select>", re.IGNORECASE | re.DOTALL),
    "MODAL": re.compile(r"<(?:Modal|Dialog)\b([^>]*)>(.*?)</(?:Modal|Dialog)>", re.IGNORECASE | re.DOTALL),
    "TAB": re.compile(r"<(?:Tab|TabItem)\b([^>]*)>(.*?)</(?:Tab|TabItem)>", re.IGNORECASE | re.DOTALL),
}

HANDLER_ATTR = re.compile(
    r"(?:onClick|onSubmit|onChange|onSelect|onKeyDown|onPress)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')",
    re.IGNORECASE,
)
DISABLED_ATTR = re.compile(r"\bdisabled\b", re.IGNORECASE)
HREF_ATTR = re.compile(r"(?:href|to)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')", re.IGNORECASE)
LABEL_TAG_STRIP = re.compile(r"<[^>]+>")


def _clean_label(inner: str) -> str:
    text = LABEL_TAG_STRIP.sub(" ", inner).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:60] if text else ""


def _discover_in_file(path: Path, rel_name: str, graph: ProjectGraph) -> list[GraphNode]:
    out: list[GraphNode] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out

    for el_type, pattern in ELEMENT_PATTERNS.items():
        for m in pattern.finditer(text):
            attrs = m.group(1) or ""
            inner = m.group(2) if m.lastindex and m.lastindex >= 2 else ""

            handler_match = HANDLER_ATTR.search(attrs)
            disabled_match = DISABLED_ATTR.search(attrs)
            href_match = HREF_ATTR.search(attrs)

            handler_name = None
            if handler_match:
                handler_name = (
                    handler_match.group(1)
                    or handler_match.group(2)
                    or handler_match.group(3)
                    or ""
                ).strip()

            href_target = None
            if href_match:
                href_target = (
                    href_match.group(1)
                    or href_match.group(2)
                    or href_match.group(3)
                    or ""
                ).strip()

            line_no = text[: m.start()].count("\n") + 1

            label = _clean_label(inner)
            if not label:
                # Check for aria-label or placeholder
                aria_m = re.search(r"aria-label=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                placeholder_m = re.search(r"placeholder=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                name_m = re.search(r"name=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                if aria_m:
                    label = aria_m.group(1)
                elif placeholder_m:
                    label = placeholder_m.group(1)
                elif name_m:
                    label = f"field:{name_m.group(1)}"
                else:
                    label = f"(anonymous {el_type.lower()})"

            # A button without handler or a link with href="#" is a dead control candidate
            has_handler = bool(handler_name) or bool(href_target and href_target != "#" and href_target != "")

            node = GraphNode(
                id=next_id(NodeType.UI_ELEMENT),
                node_type=NodeType.UI_ELEMENT,
                name=f"{el_type}: {label}",
                metadata={
                    "element_type": el_type,
                    "label": label,
                    "file": rel_name,
                    "line": line_no,
                    "has_handler": has_handler,
                    "handler_name": handler_name,
                    "href_target": href_target,
                    "disabled": bool(disabled_match),
                    "discovery_method": "static",
                    "runtime_verified": False,
                },
            )
            graph.add_node(node)
            out.append(node)
    return out


def discover_ui_elements(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    discovered: list[GraphNode] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".jsx", ".tsx", ".html", ".vue", ".svelte"}:
            continue
        if any(seg in {".git", "node_modules", "dist", "build", ".next"} for seg in path.parts):
            continue
        rel_path = str(path.relative_to(root)).replace("\\", "/")
        discovered += _discover_in_file(path, rel_path, graph)
    return discovered
