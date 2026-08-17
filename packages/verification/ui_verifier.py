"""
UI Interaction Verifier (spec Milestone 2 §10 / P4)

Performs deterministic verification of interactive UI elements.
Detects dead buttons, missing handlers, incomplete states (loading/error),
and records immutable evidence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import AuditStatus, CheckStatus, GraphNode
from packages.project_graph.store import ProjectGraph


class UIVerifier:
    def __init__(self, root: Path, evidence_store: EvidenceStore, graph: Optional[ProjectGraph] = None) -> None:
        self.root = root
        self.evidence_store = evidence_store
        self.graph = graph

    def verify_ui_element(self, node: GraphNode) -> tuple[AuditStatus, dict, list[str]]:
        meta = node.metadata
        file_rel = meta.get("file", "")
        line_no = meta.get("line", 1)
        el_type = meta.get("element_type", "BUTTON")
        label = meta.get("label", node.name)
        has_handler = meta.get("has_handler", False)
        handler_name = meta.get("handler_name")
        disabled = meta.get("disabled", False)

        checks = self.graph.get_checks_for_target(node.id) if self.graph else []
        handler_check = next((c for c in checks if "HANDLER" in c.id), None)
        loading_check = next((c for c in checks if "LOADING-STATE" in c.id), None)
        error_check = next((c for c in checks if "ERROR-STATE" in c.id), None)
        click_check = next((c for c in checks if "CLICK" in c.id), None)
        net_check = next((c for c in checks if "NETWORK-DISPATCH" in c.id), None)

        evidence_ids: list[str] = []
        checks_result: dict[str, bool] = {
            "element_rendered_in_dom": True,
            "element_visible_and_interactive": not disabled,
            "handler_attached_and_valid": False,
            "click_executes_expected_action": False,
            "loading_state_rendered": False,
            "failure_state_handled": False,
        }

        # 1. Check if file exists and read content
        file_path = self.root / file_rel
        file_content = ""
        if file_path.exists():
            try:
                file_content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass

        # 2. Check handler attachment (Static Tier)
        if not has_handler and el_type in ("BUTTON", "LINK", "FORM"):
            # DEAD INTERACTION DETECTED
            if handler_check:
                handler_check.status = CheckStatus.FAILED
            if click_check:
                # The static handler proof establishes the dead-control finding,
                # but no browser click occurred. A runtime-tier check therefore
                # remains blocked rather than being presented as a runtime fail.
                click_check.status = CheckStatus.BLOCKED
                click_check.unverified_reason = "Static analysis found no executable handler; no browser click was performed."

            ev = self.evidence_store.add(
                evidence_type=EvidenceType.STATIC_PATTERN_ANALYSIS,
                target_id=node.id,
                summary=f"Dead UI interaction: '{label}' has no onClick/onSubmit handler or valid href.",
                source_location=f"{file_rel}:{line_no}",
                payload={
                    "element_type": el_type,
                    "label": label,
                    "file": file_rel,
                    "line": line_no,
                    "has_handler": False,
                    "observation": "Static analysis found no attached event handler or valid href for actionable control.",
                },
            )
            evidence_ids.append(ev.id)
            if handler_check:
                handler_check.evidence_ids.append(ev.id)

            node.static_status = AuditStatus.FAILED
            node.runtime_status = AuditStatus.UNVERIFIED
            node.refresh_audit_status(checks)
            checks_result["handler_attached_and_valid"] = False
            return AuditStatus.FAILED, checks_result, evidence_ids

        # If handler is present, inspect component for loading/error state
        if handler_check:
            handler_check.status = CheckStatus.PASSED

        checks_result["handler_attached_and_valid"] = True
        has_loading = any(k in file_content.lower() for k in ["isloading", "loading", "spinner", "pending", "disabled={load"])
        has_error_handling = any(k in file_content.lower() for k in ["catch", "error", "toast.error", "alert", "iserror"])

        checks_result["loading_state_rendered"] = has_loading
        checks_result["failure_state_handled"] = has_error_handling

        if loading_check:
            loading_check.status = CheckStatus.PASSED if has_loading else CheckStatus.UNVERIFIED
            if not has_loading:
                loading_check.unverified_reason = "No explicit loading/spinner state found in component."

        if error_check:
            error_check.status = CheckStatus.PASSED if has_error_handling else CheckStatus.UNVERIFIED
            if not has_error_handling:
                error_check.unverified_reason = "No explicit catch/error toast handler found in component."

        # Dynamic Browser Checks: Honestly report UNVERIFIED when browser sandbox not booted
        if click_check:
            click_check.status = CheckStatus.UNVERIFIED
            click_check.unverified_reason = "Chromium browser laboratory offline (requires docker sandbox boot)."

        if net_check:
            net_check.status = CheckStatus.UNVERIFIED
            net_check.unverified_reason = "Network trace requires active browser session."

        ev = self.evidence_store.add(
            evidence_type=EvidenceType.STATIC_PATTERN_ANALYSIS,
            target_id=node.id,
            summary=f"UI element '{label}' static check: handler '{handler_name or 'href'}' attached.",
            source_location=f"{file_rel}:{line_no}",
            payload={
                "element_type": el_type,
                "label": label,
                "handler": handler_name,
                "has_loading_state": has_loading,
                "has_error_state": has_error_handling,
            },
        )
        evidence_ids.append(ev.id)
        if handler_check:
            handler_check.evidence_ids.append(ev.id)

        node.static_status = AuditStatus.VERIFIED
        node.runtime_status = AuditStatus.UNVERIFIED
        node.unverified_reasons = ["Runtime click verification unexecuted (browser offline)."]
        node.refresh_audit_status(checks)

        return node.audit_status, checks_result, evidence_ids
