"""Playwright Browser Lab bound to a healthy sandbox target.

Browser execution is contract-driven: routes, selectors and expected observable
effects must be supplied in ``.project-graph/browser-contract.json``.  The lab
never opens local files or invents UI interactions for an audited repository.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import CheckStatus, ExecutionTier, GraphNode, NodeType
from packages.project_graph.store import ProjectGraph
from packages.sandbox.environment import detect_environment_capabilities


class BrowserLaboratory:
    def __init__(self, root: Path, arg2: Any = None, arg3: Any = None) -> None:
        self.root = root
        if isinstance(arg2, EvidenceStore):
            self.evidence_store = arg2
            self.graph = arg3
        else:
            self.graph = arg2
            self.evidence_store = arg3
        self.caps = detect_environment_capabilities()

    def run_browser_audit(self, base_url: Optional[str] = None, execution_id: Optional[str] = None) -> dict[str, Any]:
        contract = self._load_contract()
        if not base_url:
            return self._block_all("No healthy Docker sandbox browser target is available.")
        if not self.caps.playwright_available:
            return self._block_all("Playwright Chromium is unavailable in the execution environment.")
        if contract is None:
            return self._block_all("No valid .project-graph/browser-contract.json; browser paths and interactions are never guessed.")

        try:
            from playwright.sync_api import sync_playwright
            console_errors: list[str] = []
            network: list[dict[str, str]] = []
            rendered_count = 0
            clicks_executed = 0
            evidence_ids: list[str] = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.on("console", lambda message: console_errors.append(self._redact_text(message.text)) if message.type == "error" else None)
                page.on("request", lambda request: network.append({"method": request.method, "url": self._safe_url(request.url)}))

                for flow in contract["flows"]:
                    page.goto(f"{base_url.rstrip('/')}{flow['path']}", wait_until="networkidle", timeout=flow["timeout_ms"])
                    rendered_count += page.locator("button,a,input,textarea,select,form").count()
                    for step in flow["steps"]:
                        before_url = page.url
                        target = page.locator(step["selector"])
                        target.click(timeout=step.get("timeout_ms", 10000))
                        clicks_executed += 1
                        expectation = step.get("expect", {})
                        if "url_contains" in expectation and expectation["url_contains"] not in page.url:
                            raise AssertionError(f"Expected URL containing {expectation['url_contains']!r}, got {page.url!r}")
                        if expectation.get("url_changes") and page.url == before_url:
                            raise AssertionError("Expected click to change URL, but it did not.")
                        screenshot = page.screenshot()
                        ev = self.evidence_store.add(
                            EvidenceType.DOM_INTERACTION, step["target_id"],
                            f"Browser flow '{flow['id']}' clicked declared selector '{step['selector']}'.",
                            payload={"flow_id": flow["id"], "path": flow["path"], "selector": step["selector"], "url_before": before_url, "url_after": page.url, "expect": expectation, "console_errors": console_errors[-20:]},
                            artifact_bytes=screenshot, mime_type="image/png", execution_id=execution_id, producer="BrowserLaboratory",
                        )
                        evidence_ids.append(ev.id)
                        self._mark_runtime_step(
                            target_id=step["target_id"],
                            evidence_id=ev.id,
                            effect_verified=bool(expectation and (expectation.get("url_contains") or expectation.get("url_changes"))),
                            network_verified=bool(network),
                        )

                trace = self.evidence_store.add(
                    EvidenceType.BROWSER_TRACE, "BROWSER-LAB",
                    f"Browser sandbox execution captured {clicks_executed} declared interactions.",
                    payload={"network": network, "console_errors": console_errors, "flows": [flow["id"] for flow in contract["flows"]]},
                    artifact_bytes=json.dumps({"network": network, "console_errors": console_errors}).encode("utf-8"),
                    execution_id=execution_id, producer="BrowserLaboratory",
                )
                evidence_ids.append(trace.id)
                browser.close()
            return {"browser_available": True, "rendered_elements": rendered_count, "clicks_executed": clicks_executed, "status": "COMPLETED", "evidence_ids": evidence_ids}
        except Exception as exc:
            return self._block_all(f"Browser execution error: {type(exc).__name__}: {exc}", status="ERROR")

    def _load_contract(self) -> Optional[dict[str, Any]]:
        path = self.root / ".project-graph" / "browser-contract.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            flows = data.get("flows")
            if not isinstance(flows, list) or not flows:
                return None
            for flow in flows:
                if not isinstance(flow, dict) or not isinstance(flow.get("id"), str) or not isinstance(flow.get("path"), str) or not flow["path"].startswith("/") or not isinstance(flow.get("steps"), list):
                    return None
                flow.setdefault("timeout_ms", 15000)
                for step in flow["steps"]:
                    if not isinstance(step, dict) or not isinstance(step.get("target_id"), str) or not isinstance(step.get("selector"), str) or not step["selector"]:
                        return None
                    if not isinstance(step.get("expect", {}), dict):
                        return None
            return {"flows": flows}
        except (OSError, json.JSONDecodeError):
            return None

    def _mark_runtime_step(self, target_id: str, evidence_id: str, effect_verified: bool, network_verified: bool) -> None:
        for check in self.graph.get_checks_for_target(target_id):
            if "CLICK" in check.id:
                # Click executed proves interaction was triggered in DOM
                check.status = CheckStatus.PASSED
                check.evidence_ids.append(evidence_id)
            elif "EXPECTED-EFFECT" in check.id or "DOWNLOAD" in check.id or "NAVIGATION" in check.id:
                # Observable outcome required for feature success
                if effect_verified:
                    check.status = CheckStatus.PASSED
                    check.evidence_ids.append(evidence_id)
                else:
                    check.status = CheckStatus.UNVERIFIED
                    check.unverified_reason = "Click executed, but expected outcome/download/navigation was unverified."
            elif "NETWORK-DISPATCH" in check.id:
                if network_verified:
                    check.status = CheckStatus.PASSED
                    check.evidence_ids.append(evidence_id)
                else:
                    check.status = CheckStatus.UNVERIFIED
                    check.unverified_reason = "No outbound network dispatch captured during interaction."

        node = self.graph.get_node(target_id)
        if node:
            checks = self.graph.get_checks_for_target(target_id)
            runtime_checks = [check for check in checks if check.execution_tier == ExecutionTier.RUNTIME_BROWSER and check.required]
            if runtime_checks and all(check.status == CheckStatus.PASSED for check in runtime_checks):
                from packages.project_graph.models import AuditStatus
                node.runtime_status = AuditStatus.VERIFIED
            node.refresh_audit_status(checks)

    def _block_all(self, reason: str, status: str = "BLOCKED") -> dict[str, Any]:
        check_status = CheckStatus.ERROR if status == "ERROR" else CheckStatus.BLOCKED
        for check in self.graph.audit_checks.values():
            if check.execution_tier == ExecutionTier.RUNTIME_BROWSER:
                check.status = check_status
                check.unverified_reason = reason
        return {"browser_available": self.caps.playwright_available, "rendered_elements": 0, "clicks_executed": 0, "status": status, "reason": reason}

    @staticmethod
    def _safe_url(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    @staticmethod
    def _redact_text(text: str) -> str:
        return re.sub(r"(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)

    def reconcile_dom_inventory(self, static_ui_nodes: list[GraphNode], live_dom_nodes: list[dict[str, Any]]) -> dict[str, Any]:
        static_count, runtime_count = len(static_ui_nodes), len(live_dom_nodes)
        return {"static_ui_count": static_count, "runtime_dom_count": runtime_count, "discrepancy": runtime_count - static_count, "unrendered_static_elements": max(0, static_count - runtime_count), "dynamic_runtime_only_elements": max(0, runtime_count - static_count)}
