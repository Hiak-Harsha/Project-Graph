"""
Phase: UI DISCOVERY (spec Milestone 1 §10-12)

Extracts UI interactive elements:
- Buttons (<button>, <Button>, <IconButton>, <* as="button">, <DialogTrigger>)
- Navigation Links (<a>, <Link>, <NavLink>)
- Forms & Inputs (<form>, <input>, <select>, <textarea>)
- Containers & Dialogs (<Modal>, <Dialog>, <Tab>, <Drawer>)

Captures attached event handlers, loading states, accessibility properties,
and analyzes handler binding for dead interaction candidate detection.
"""
from __future__ import annotations

import re
from pathlib import Path

from packages.project_graph.models import GraphNode, NodeType, next_id
from packages.project_graph.store import ProjectGraph

ELEMENT_PATTERNS = {
    "BUTTON": re.compile(r"<(?:button|Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)\b([^>]*)>(.*?)</(?:button|Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)>", re.IGNORECASE | re.DOTALL),
    "BUTTON_SELF_CLOSING": re.compile(r"<(?:Button|IconButton|CustomButton|SubmitButton|PrimaryButton|SecondaryButton|ActionButton|DialogTrigger)\b([^>]*?)/?>", re.IGNORECASE),
    "LINK": re.compile(r"<(?:a|Link|NavLink|RouteLink)\b([^>]*)>(.*?)</(?:a|Link|NavLink|RouteLink)>", re.IGNORECASE | re.DOTALL),
    "FORM": re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL),
    "INPUT": re.compile(r"<(?:input|TextInput|SearchInput)\b([^>]*)/?>", re.IGNORECASE),
    "TEXTAREA": re.compile(r"<(?:textarea|TextArea)\b([^>]*)>(.*?)</(?:textarea|TextArea)>", re.IGNORECASE | re.DOTALL),
    "SELECT": re.compile(r"<(?:select|Select|Dropdown)\b([^>]*)>(.*?)</(?:select|Select|Dropdown)>", re.IGNORECASE | re.DOTALL),
    "MODAL": re.compile(r"<(?:Modal|Dialog|Drawer|Sheet)\b([^>]*)>(.*?)</(?:Modal|Dialog|Drawer|Sheet)>", re.IGNORECASE | re.DOTALL),
    "TAB": re.compile(r"<(?:Tab|TabItem|Tabs\.Trigger)\b([^>]*)>(.*?)</(?:Tab|TabItem|Tabs\.Trigger)>", re.IGNORECASE | re.DOTALL),
}

HANDLER_ATTR = re.compile(
    r"(?:onClick|onSubmit|onChange|onSelect|onKeyDown|onPress|handleClick|handleSubmit)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')",
    re.IGNORECASE,
)
DISABLED_ATTR = re.compile(r"\b(?:disabled|isDisabled|aria-disabled=[\"'{]true)\b", re.IGNORECASE)
HREF_ATTR = re.compile(r"(?:href|to)\s*=\s*(?:{([^}]+)}|\"([^\"]+)\"|'([^']+)')", re.IGNORECASE)
TYPE_ATTR = re.compile(r"type=[\"']([^\"']+)[\"']", re.IGNORECASE)
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

    seen_positions: set[int] = set()

    for el_type, pattern in ELEMENT_PATTERNS.items():
        base_type = "BUTTON" if "BUTTON" in el_type else el_type
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
                # Check for aria-label, title, placeholder, or name
                aria_m = re.search(r"aria-label=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                placeholder_m = re.search(r"placeholder=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                name_m = re.search(r"name=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                title_m = re.search(r"title=[\"']([^\"']+)[\"']", attrs, re.IGNORECASE)
                if aria_m:
                    label = aria_m.group(1)
                elif placeholder_m:
                    label = placeholder_m.group(1)
                elif title_m:
                    label = title_m.group(1)
                elif name_m:
                    label = f"field:{name_m.group(1)}"
                else:
                    label = f"(anonymous {base_type.lower()})"

            # Interactive control handler validity
            has_handler = bool(handler_name) or bool(href_target and href_target != "#" and href_target != "")
            
            # Form submission or submit button inherits form handler
            if type_match and type_match.group(1).lower() == "submit" and not has_handler:
                # Inherits form submission in the component
                has_handler = bool(re.search(r"onSubmit\s*=", text, re.IGNORECASE))
                if has_handler and not handler_name:
                    handler_name = "form.onSubmit"

            node = GraphNode(
                id=next_id(NodeType.UI_ELEMENT),
                node_type=NodeType.UI_ELEMENT,
                name=f"{base_type}: {label}",
                metadata={
                    "element_type": base_type,
                    "label": label,
                    "file": rel_name,
                    "line": line_no,
                    "handler_name": handler_name,
                    "href_target": href_target,
                    "has_handler": has_handler,
                    "is_disabled": bool(disabled_match),
                    "input_type": type_match.group(1) if type_match else None,
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
            if any(part in ("node_modules", ".git", "dist", "build", ".next", "__pycache__") for part in p.parts):
                continue
            rel_path = str(p.relative_to(root)).replace("\\", "/")
            elements = _discover_in_file(p, rel_path, graph)
            results.extend(elements)

    return results
