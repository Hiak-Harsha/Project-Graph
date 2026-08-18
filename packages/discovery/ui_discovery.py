"""
Phase: UI, PAGE, ROUTE, FORM & INPUT DISCOVERY (spec Milestone 1 §10-12)

Extracts:
1. UI interactive elements (Button, IconButton, ActionButton, DialogTrigger, Link, Tab, Modal) -> NodeType.UI_ELEMENT
2. Web Pages and Views (files under pages/, views/, routes/, app/) -> NodeType.PAGE
3. Client-Side Routes (<Route path="..." />, <Link to="..." />) -> NodeType.ROUTE
4. Forms (<form onSubmit=...>) -> NodeType.FORM
5. Input Controls (<input>, <select>, <textarea>) -> NodeType.INPUT

Maintains handler references and ensures inputs inside forms are not falsely flagged as dead buttons.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

BUTTON_PATTERN = re.compile(
    r"<(?:button|Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)\b([^>]*)>(.*?)</(?:button|Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)>",
    re.IGNORECASE | re.DOTALL,
)
BUTTON_SELF_CLOSING = re.compile(
    r"<(?:Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)\b([^>]*?)/?>",
    re.IGNORECASE,
)
LINK_PATTERN = re.compile(
    r"<(?:a|Link|NavLink|RouteLink)\b([^>]*)>(.*?)</(?:a|Link|NavLink|RouteLink)>",
    re.IGNORECASE | re.DOTALL,
)
FORM_PATTERN = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_PATTERN = re.compile(r"<(?:input|TextInput|SearchInput)\b([^>]*)/?>", re.IGNORECASE)
TEXTAREA_PATTERN = re.compile(r"<(?:textarea|TextArea)\b([^>]*)>(.*?)</(?:textarea|TextArea)>", re.IGNORECASE | re.DOTALL)
SELECT_PATTERN = re.compile(r"<(?:select|Select|Dropdown)\b([^>]*)>(.*?)</(?:select|Select|Dropdown)>", re.IGNORECASE | re.DOTALL)
ROUTE_TAG_PATTERN = re.compile(r"<Route\b([^>]*)/?>", re.IGNORECASE)

HANDLER_ATTR = re.compile(
    r"(?:onClick|onSubmit|onChange|onSelect|onKeyDown|onPress|handleClick|handleSubmit)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')",
    re.IGNORECASE,
)
DISABLED_ATTR = re.compile(r"\b(?:disabled|isDisabled|aria-disabled=[\"'{]true)\b", re.IGNORECASE)
HREF_ATTR = re.compile(r"(?:href|to|path)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')", re.IGNORECASE)
NAME_ATTR = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
TYPE_ATTR = re.compile(r"type=[\"']([^\"']+)[\"']", re.IGNORECASE)
PLACEHOLDER_ATTR = re.compile(r"placeholder=[\"']([^\"']+)[\"']", re.IGNORECASE)
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

    # 1. Page Discovery (Files under pages/, views/, routes/, or app/)
    norm_rel = rel_name.replace("\\", "/").lower()
    if any(seg in norm_rel for seg in ("/pages/", "/views/", "/routes/", "app/page.", "app/layout.")):
        page_name = path.stem
        if page_name.lower() not in ("index", "_app", "_document", "page", "layout"):
            p_label = page_name
        else:
            p_label = Path(norm_rel).parent.name or page_name
        page_node = GraphNode(
            id=next_id(NodeType.PAGE),
            node_type=NodeType.PAGE,
            name=f"Page: {p_label}",
            metadata={"file": rel_name, "route_path": f"/{p_label.lower()}" if p_label != "index" else "/"},
        )
        graph.add_node(page_node)
        out.append(page_node)

    # 2. Client-Side Routes (<Route path="..." element={...} />)
    for rm in ROUTE_TAG_PATTERN.finditer(text):
        rattrs = rm.group(1) or ""
        pm = HREF_ATTR.search(rattrs)
        rpath = pm.group(1) or pm.group(2) or pm.group(3) if pm else "/"
        route_node = GraphNode(
            id=next_id(NodeType.ROUTE),
            node_type=NodeType.ROUTE,
            name=f"Route: {rpath}",
            metadata={"file": rel_name, "path": rpath, "line": text[: rm.start()].count("\n") + 1},
        )
        graph.add_node(route_node)
        out.append(route_node)

    # 3. Forms (<form>)
    for fm in FORM_PATTERN.finditer(text):
        fattrs = fm.group(1) or ""
        hm = HANDLER_ATTR.search(fattrs)
        hname = hm.group(1) or hm.group(2) or hm.group(3) if hm else None
        form_node = GraphNode(
            id=next_id(NodeType.FORM),
            node_type=NodeType.FORM,
            name=f"Form: {path.stem}Form",
            metadata={"file": rel_name, "handler_name": hname, "line": text[: fm.start()].count("\n") + 1},
        )
        graph.add_node(form_node)
        out.append(form_node)

    # 4. Inputs (<input>, <textarea>, <select>)
    for inp_pattern, inp_kind in [(INPUT_PATTERN, "INPUT"), (TEXTAREA_PATTERN, "TEXTAREA"), (SELECT_PATTERN, "SELECT")]:
        for im in inp_pattern.finditer(text):
            iattrs = im.group(1) or ""
            nm = NAME_ATTR.search(iattrs)
            tm = TYPE_ATTR.search(iattrs)
            pm = PLACEHOLDER_ATTR.search(iattrs)
            name_val = nm.group(1) if nm else (pm.group(1) if pm else f"anon_{inp_kind.lower()}")
            input_type = tm.group(1) if tm else ("text" if inp_kind == "INPUT" else inp_kind.lower())

            # Check if input is submit button
            if input_type.lower() == "submit":
                continue

            input_node = GraphNode(
                id=next_id(NodeType.INPUT),
                node_type=NodeType.INPUT,
                name=f"Input: {name_val} ({input_type})",
                metadata={
                    "file": rel_name,
                    "field_name": name_val,
                    "input_type": input_type,
                    "placeholder": pm.group(1) if pm else None,
                    "line": text[: im.start()].count("\n") + 1,
                },
            )
            graph.add_node(input_node)
            out.append(input_node)

    # 5. Interactive UI Elements (Buttons, Action Controls, Navigation Links)
    seen_positions: set[int] = set()

    for pattern, kind in [
        (BUTTON_PATTERN, "BUTTON"),
        (BUTTON_SELF_CLOSING, "BUTTON"),
        (LINK_PATTERN, "LINK"),
    ]:
        for m in pattern.finditer(text):
            pos = m.start()
            if pos in seen_positions:
                continue
            seen_positions.add(pos)

            attrs = m.group(1) or ""
            inner = m.group(2) if m.lastindex and m.lastindex >= 2 else ""

            handler_match = HANDLER_ATTR.search(attrs)
            disabled_match = DISABLED_ATTR.search(attrs)
            href_match = HREF_ATTR.search(attrs)
            type_match = TYPE_ATTR.search(attrs)

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
                aria_m = re.search(r"aria-label=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                title_m = re.search(r"title=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                name_m = re.search(r"name=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                if aria_m:
                    label = aria_m.group(1)
                elif title_m:
                    label = title_m.group(1)
                elif name_m:
                    label = name_m.group(1)
                else:
                    label = f"(anonymous {kind.lower()})"

            has_handler = bool(handler_name) or bool(href_target and href_target != "#" and href_target != "")

            # Submit buttons in forms inherit form submission
            if type_match and type_match.group(1).lower() == "submit" and not has_handler:
                has_handler = bool(re.search(r"onSubmit\s*=", text, re.IGNORECASE))
                if has_handler:
                    handler_name = "form.onSubmit"

            node = GraphNode(
                id=next_id(NodeType.UI_ELEMENT),
                node_type=NodeType.UI_ELEMENT,
                name=f"{kind}: {label}",
                metadata={
                    "element_type": kind,
                    "label": label,
                    "file": rel_name,
                    "line": line_no,
                    "handler_name": handler_name,
                    "href_target": href_target,
                    "has_handler": has_handler,
                    "is_disabled": bool(disabled_match),
                    "has_loading_feedback": bool(re.search(r"(?:loading|isPending|spinner|disabled={loading)", text, re.IGNORECASE)),
                    "has_error_feedback": bool(re.search(r"(?:error|toast|alert|setError|isError)", text, re.IGNORECASE)),
                },
            )
            graph.add_node(node)
            out.append(node)

    return out


def discover_ui_elements(root: Path, graph: ProjectGraph) -> list[GraphNode]:
    results: list[GraphNode] = []
    extensions = {".tsx", ".jsx", ".vue", ".svelte", ".html", ".js", ".ts"}

    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            if any(part in ("node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv") for part in p.parts):
                continue
            rel_path = str(p.relative_to(root)).replace("\\", "/")
            elements = _discover_in_file(p, rel_path, graph)
            results.extend(elements)

    return results
