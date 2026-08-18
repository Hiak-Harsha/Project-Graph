"""
Dynamic API Execution Runner (spec Milestone 2 §12 / P4)

Executes physical dynamic HTTP requests against backend ASGI applications (FastAPI / Starlette),
captures actual response status codes, bodies, and latency, and executes multi-identity BOLA/IDOR
boundary tests with cryptographic API_RESPONSE and AUTH_BOUNDARY_TEST evidence.
Zero synthetic or mock responses are produced.
"""
from __future__ import annotations

import ast
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import (
    AuditCheck,
    AuditStatus,
    CheckStatus,
    ExecutionTier,
    GraphNode,
    NodeType,
)
from packages.project_graph.store import ProjectGraph


class APIRunnerVerifier:
    def __init__(self, root: Path, evidence_store: EvidenceStore, graph: ProjectGraph) -> None:
        self.root = root
        self.evidence_store = evidence_store
        self.graph = graph
        self._base_url: Optional[str] = None
        self._runtime_execution_id: Optional[str] = None
        self._identity_fixtures = self._load_identity_fixtures()
        self._api_contracts = self._load_api_contracts()
        # P6: audited repositories must never be imported into the audit
        # control-plane process. DockerSandboxSupervisor is now the only
        # approved runtime entry point; its HTTP adapter is the next slice.
        self._runtime_error = "In-process ASGI execution is disabled by sandbox policy; runtime HTTP requires a healthy Docker sandbox adapter."

    def configure_sandbox_target(self, base_url: Optional[str], execution_id: Optional[str]) -> None:
        """Accept only a URL emitted by DockerSandboxSupervisor after health success."""
        self._base_url = base_url.rstrip("/") if base_url else None
        self._runtime_execution_id = execution_id
        if self._base_url:
            self._runtime_error = ""

    def _load_api_contracts(self) -> dict[str, dict[str, Any]]:
        path = self.root / ".project-graph" / "api-contract.json"
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            endpoints = payload.get("endpoints", {})
            return endpoints if isinstance(endpoints, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _load_identity_fixtures(self) -> dict[str, dict[str, Any]]:
        """Load only explicit BOLA fixtures; absent/malformed input means no test."""
        path = self.root / ".project-graph" / "identity-fixtures.json"
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            endpoints = payload.get("endpoints", {})
            return endpoints if isinstance(endpoints, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _redact_headers(headers: dict[str, Any]) -> dict[str, str]:
        secret_headers = {"authorization", "cookie", "x-api-key"}
        return {str(k): "[REDACTED]" if str(k).lower() in secret_headers else str(v) for k, v in headers.items()}

    def verify_all_endpoints(self) -> None:
        for node in self.graph.nodes_of_type(NodeType.API_ENDPOINT):
            self.verify_endpoint(node)

    def verify_endpoint(self, node: GraphNode) -> tuple[AuditStatus, dict[str, Any], list[str]]:
        meta = node.metadata
        method = meta.get("method", "GET").upper()
        route_path = meta.get("path", "/")
        file_rel = meta.get("file", "")

        checks = self.graph.get_checks_for_target(node.id)
        route_reg_check = next((c for c in checks if "ROUTE-REG" in c.id), None)
        auth_dec_check = next((c for c in checks if "AUTH-DECLARED" in c.id), None)
        bola_static_check = next((c for c in checks if "BOLA-STATIC" in c.id), None)
        http_exec_check = next((c for c in checks if "HTTP-REACHABLE" in c.id), None)
        bola_runtime_check = next((c for c in checks if "BOLA-RUNTIME" in c.id), None)

        evidence_ids: list[str] = []

        # 1. Static Checks: Route registration & Auth declaration
        if route_reg_check:
            route_reg_check.status = CheckStatus.PASSED

        has_auth_hint = meta.get("auth_hint_nearby", False)
        if auth_dec_check:
            if has_auth_hint:
                auth_dec_check.status = CheckStatus.PASSED
                auth_dec_check.details["auth_requirement"] = "AUTH_REQUIRED"
            else:
                auth_dec_check.status = CheckStatus.UNVERIFIED
                auth_dec_check.details["auth_requirement"] = "UNKNOWN"
                auth_dec_check.unverified_reason = "Authentication requirement is not explicitly encoded in route decorators."

        # 2. Static AST Data-Flow Analysis for BOLA / IDOR
        is_catch_all = any(k in route_path.lower() for k in ("{full_path", "{path:", "static", "assets", "public", "*", "openapi", "docs"))
        is_parameterized = ("{" in route_path or ":" in route_path) and not is_catch_all
        has_static_bola_flaw = False
        if is_parameterized:
            has_static_bola_flaw = self._analyze_ast_bola(file_rel, meta.get("handler_name", ""))
            if bola_static_check:
                if has_static_bola_flaw:
                    bola_static_check.status = CheckStatus.FAILED
                    ev = self.evidence_store.add(
                        evidence_type=EvidenceType.STATIC_AST_MATCH,
                        target_id=node.id,
                        summary=f"AST Dataflow IDOR/BOLA in '{method} {route_path}': resource parameter queried without tenancy/user_id ownership filter.",
                        source_location=f"{file_rel}:{meta.get('line', 1)}",
                        payload={"route": route_path, "method": method, "reason": "No user ID ownership scoping in direct lookup."},
                    )
                    evidence_ids.append(ev.id)
                    bola_static_check.evidence_ids.append(ev.id)
                else:
                    bola_static_check.status = CheckStatus.PASSED
        elif bola_static_check:
            bola_static_check.status = CheckStatus.NOT_APPLICABLE

        # 3. Real Dynamic Execution Tier.  Never invent parameters, bodies or
        # identities: unknown contracts remain explicitly unverified.
        if self._base_url is not None:
            self._execute_safe_probe(node, method, route_path, file_rel, http_exec_check, evidence_ids)
            self._execute_bola_contract(node, method, route_path, file_rel, bola_runtime_check, evidence_ids)
        else:
            # Honest unverified status
            if http_exec_check:
                http_exec_check.status = CheckStatus.BLOCKED
                http_exec_check.unverified_reason = self._runtime_error
            if bola_runtime_check:
                contract = self._identity_fixtures.get(f"{method} {route_path}")
                required = {"owner_headers", "attacker_headers", "owner_resource_path", "provisioning_evidence"}
                if is_parameterized and (not isinstance(contract, dict) or not required.issubset(contract)):
                    bola_runtime_check.status = CheckStatus.BLOCKED
                    bola_runtime_check.unverified_reason = "Requires provisioned owner/attacker fixture contract in .project-graph/identity-fixtures.json; no synthetic identities were used."
                elif is_parameterized:
                    bola_runtime_check.status = CheckStatus.BLOCKED
                    bola_runtime_check.unverified_reason = self._runtime_error
                else:
                    bola_runtime_check.status = CheckStatus.NOT_APPLICABLE

        node.static_status = AuditStatus.FAILED if has_static_bola_flaw else AuditStatus.VERIFIED
        runtime_checks = [c for c in (http_exec_check, bola_runtime_check) if c]
        if any(c.status in (CheckStatus.FAILED, CheckStatus.ERROR) for c in runtime_checks):
            node.runtime_status = AuditStatus.FAILED
        elif runtime_checks and all(c.status in (CheckStatus.PASSED, CheckStatus.NOT_APPLICABLE) for c in runtime_checks):
            node.runtime_status = AuditStatus.VERIFIED
        else:
            node.runtime_status = AuditStatus.UNVERIFIED
        node.refresh_audit_status(checks)

        return node.audit_status, {}, evidence_ids

    def _execute_safe_probe(self, node: GraphNode, method: str, route_path: str, file_rel: str, check: Optional[AuditCheck], evidence_ids: list[str]) -> None:
        """Execute a declared safe HTTP contract against the healthy sandbox."""
        if not check:
            return
        contract = self._api_contracts.get(f"{method} {route_path}")
        if not isinstance(contract, dict):
            check.status = CheckStatus.BLOCKED
            check.unverified_reason = "No endpoint contract in .project-graph/api-contract.json; auditor will not invent request inputs."
            return
        request_path = contract.get("path")
        statuses = contract.get("expected_statuses")
        headers = contract.get("headers", {})
        if method not in {"GET", "HEAD"} or not isinstance(request_path, str) or not request_path.startswith("/") or not isinstance(statuses, list) or not statuses or not all(isinstance(status, int) for status in statuses) or not isinstance(headers, dict):
            check.status = CheckStatus.BLOCKED
            check.unverified_reason = "Endpoint contract must declare a safe GET/HEAD path, expected_statuses and string headers."
            return
        try:
            t0 = time.time()
            status_code, content, content_type = self._request(method, request_path, headers)
            duration = round(time.time() - t0, 3)
            check.status = CheckStatus.PASSED if status_code in statuses else CheckStatus.FAILED
            check.details = {"status_code": status_code, "expected_statuses": statuses, "duration_seconds": duration, "execution_kind": "SANDBOX_HTTP", "execution_id": self._runtime_execution_id}
            ev = self.evidence_store.add(
                evidence_type=EvidenceType.API_RESPONSE, target_id=node.id,
                summary=f"Sandbox HTTP contract {method} {request_path} returned HTTP {status_code} in {duration}s.",
                source_location=file_rel,
                payload={"route": request_path, "method": method, "status_code": status_code, "expected_statuses": statuses, "duration_seconds": duration, "execution_kind": "SANDBOX_HTTP", "headers": self._redact_headers(headers)},
                artifact_bytes=content, mime_type=content_type, execution_id=self._runtime_execution_id, producer="APIRunnerVerifier",
            )
            evidence_ids.append(ev.id); check.evidence_ids.append(ev.id)
        except Exception as ex:
            check.status = CheckStatus.ERROR
            check.unverified_reason = f"Sandbox HTTP dispatch error: {type(ex).__name__}: {ex}"

    def _execute_bola_contract(self, node: GraphNode, method: str, route_path: str, file_rel: str, check: Optional[AuditCheck], evidence_ids: list[str]) -> None:
        """Perform a real owner-vs-attacker boundary test only with provisioned fixtures."""
        if not check:
            return
        if not ("{" in route_path or ":" in route_path):
            check.status = CheckStatus.NOT_APPLICABLE
            return
        contract = self._identity_fixtures.get(f"{method} {route_path}")
        required = {"owner_headers", "attacker_headers", "owner_resource_path", "provisioning_evidence"}
        if not isinstance(contract, dict) or not required.issubset(contract):
            check.status = CheckStatus.BLOCKED
            check.unverified_reason = "Requires provisioned owner/attacker fixture contract in .project-graph/identity-fixtures.json; no synthetic identities were used."
            return
        path = contract["owner_resource_path"]
        if not isinstance(path, str) or not path.startswith("/"):
            check.status = CheckStatus.BLOCKED
            check.unverified_reason = "Identity fixture contract has an invalid owner_resource_path."
            return
        try:
            owner_status, owner_content, _ = self._request(method, path, contract["owner_headers"])
            attacker_status, attacker_content, _ = self._request(method, path, contract["attacker_headers"])
            forbidden = set(contract.get("forbidden_statuses", [401, 403, 404]))
            if owner_status >= 400:
                check.status = CheckStatus.BLOCKED
                check.unverified_reason = f"Owner fixture did not establish access (HTTP {owner_status})."
                return
            check.status = CheckStatus.PASSED if attacker_status in forbidden else CheckStatus.FAILED
            ev = self.evidence_store.add(
                evidence_type=EvidenceType.AUTH_BOUNDARY_TEST, target_id=node.id,
                summary=f"Sandbox BOLA boundary: owner HTTP {owner_status}; attacker HTTP {attacker_status}.", source_location=file_rel,
                payload={"test_type": "BOLA_OWNER_ATTACKER_BOUNDARY", "owner_status": owner_status, "attacker_status": attacker_status,
                         "forbidden_statuses": sorted(forbidden), "owner_resource_path": path,
                         "owner_headers": self._redact_headers(contract["owner_headers"]), "attacker_headers": self._redact_headers(contract["attacker_headers"]),
                         "provisioning_evidence": contract["provisioning_evidence"]},
                artifact_bytes=b"OWNER:\n" + owner_content + b"\nATTACKER:\n" + attacker_content, execution_id=self._runtime_execution_id, producer="APIRunnerVerifier",
            )
            evidence_ids.append(ev.id); check.evidence_ids.append(ev.id)
            if check.status == CheckStatus.FAILED:
                self.evidence_store.add_claim(
                    statement=f"Endpoint '{method} {route_path}' allowed a provisioned cross-tenant request.", target_id=node.id,
                    evidence_ids=[ev.id], evidence_strength="RUNTIME_OBSERVED", status="CONFIRMED",
                )
        except Exception as ex:
            check.status = CheckStatus.ERROR
            check.unverified_reason = f"BOLA boundary execution failed: {type(ex).__name__}: {ex}"

    def _request(self, method: str, path: str, headers: dict[str, Any]) -> tuple[int, bytes, str]:
        if not self._base_url:
            raise RuntimeError("No healthy sandbox base URL.")
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            raise ValueError("HTTP contract headers must be string pairs.")
        request = urllib.request.Request(f"{self._base_url}{path}", method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return int(response.status), response.read(), response.headers.get_content_type()
        except urllib.error.HTTPError as error:
            return int(error.code), error.read(), error.headers.get_content_type()

    def _analyze_ast_bola(self, file_rel: str, handler_name: str) -> bool:
        """Inspect source AST to determine if query parameters omit user ownership tenancy filtering."""
        if not file_rel:
            return True
        file_path = self.root / file_rel
        if not file_path.exists():
            return True

        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not handler_name or node.name.lower() == handler_name.lower() or (handler_name and handler_name.lower() in node.name.lower()):
                        # Check function arguments for current_user or session
                        arg_names = [arg.arg for arg in node.args.args]
                        has_user_arg = any("user" in a.lower() or "auth" in a.lower() for a in arg_names)
                        source_segment = ast.unparse(node)
                        has_ownership_filter = "user_id" in source_segment or "owner_id" in source_segment or "tenant_id" in source_segment
                        if not has_user_arg and not has_ownership_filter:
                            return True
            return False
        except Exception:
            return True
