"""
Generic Applicability Engine (spec Milestone 2.7)

Transforms:
Discovered Capabilities -> Applicability Rules -> Production Requirements -> AuditChecks

Ensures that requirements are applied conditionally:
- If a capability exists (e.g. Auth, Upload, DB, External Service), the corresponding production requirements apply.
- If a capability does NOT exist, the requirement is marked NOT_APPLICABLE (N_A), never FAILED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from packages.project_graph.models import AuditStatus, CheckStatus, NodeType
from packages.project_graph.store import ProjectGraph


class CapabilityType(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    FILE_UPLOAD = "FILE_UPLOAD"
    DATABASE_PERSISTENCE = "DATABASE_PERSISTENCE"
    EXTERNAL_SERVICE_INTEGRATION = "EXTERNAL_SERVICE_INTEGRATION"
    PARAMETERIZED_RESOURCE_API = "PARAMETERIZED_RESOURCE_API"
    UI_INTERACTION = "UI_INTERACTION"
    BACKGROUND_WORKER = "BACKGROUND_WORKER"
    PAYMENT_PROCESSING = "PAYMENT_PROCESSING"


@dataclass
class DiscoveredCapability:
    capability_type: CapabilityType
    confidence: float
    evidence_nodes: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApplicableRequirement:
    id: str
    name: str
    capability_type: CapabilityType
    is_applicable: bool
    reason: str
    required_checks: list[str] = field(default_factory=list)
    status: AuditStatus = AuditStatus.NOT_APPLICABLE


class ApplicabilityEngine:
    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def discover_capabilities(self) -> dict[CapabilityType, DiscoveredCapability]:
        capabilities: dict[CapabilityType, DiscoveredCapability] = {}

        api_nodes = self.graph.nodes_of_type(NodeType.API_ENDPOINT)
        ui_nodes = self.graph.nodes_of_type(NodeType.UI_ELEMENT)
        db_nodes = self.graph.nodes_of_type(NodeType.DATABASE_ENTITY)
        services = self.graph.nodes_of_type(NodeType.EXTERNAL_SERVICE)
        files = self.graph.nodes_of_type(NodeType.FILE)
        packages = self.graph.nodes_of_type(NodeType.PACKAGE)

        # 1. AUTHENTICATION
        auth_apis = [a for a in api_nodes if any(k in a.name.lower() or k in a.metadata.get("path", "").lower() for k in ["login", "auth", "token", "signup", "register", "session"])]
        auth_packages = [p for p in packages if any(k in p.name.lower() for k in ["jwt", "bcrypt", "passport", "auth0", "next-auth"])]
        if auth_apis or auth_packages:
            capabilities[CapabilityType.AUTHENTICATION] = DiscoveredCapability(
                capability_type=CapabilityType.AUTHENTICATION,
                confidence=0.95 if auth_apis else 0.80,
                evidence_nodes=[a.id for a in auth_apis] + [p.id for p in auth_packages],
                metadata={"auth_endpoint_count": len(auth_apis)},
            )

        # 2. FILE UPLOAD
        upload_apis = [a for a in api_nodes if any(k in a.name.lower() or k in a.metadata.get("path", "").lower() for k in ["upload", "file", "avatar", "attachment", "multipart", "document"])]
        if upload_apis:
            capabilities[CapabilityType.FILE_UPLOAD] = DiscoveredCapability(
                capability_type=CapabilityType.FILE_UPLOAD,
                confidence=0.90,
                evidence_nodes=[a.id for a in upload_apis],
                metadata={"upload_endpoint_count": len(upload_apis)},
            )

        # 3. DATABASE PERSISTENCE
        if db_nodes:
            capabilities[CapabilityType.DATABASE_PERSISTENCE] = DiscoveredCapability(
                capability_type=CapabilityType.DATABASE_PERSISTENCE,
                confidence=0.98,
                evidence_nodes=[d.id for d in db_nodes],
                metadata={"model_count": len(db_nodes)},
            )

        # 4. EXTERNAL SERVICE INTEGRATION
        if services:
            capabilities[CapabilityType.EXTERNAL_SERVICE_INTEGRATION] = DiscoveredCapability(
                capability_type=CapabilityType.EXTERNAL_SERVICE_INTEGRATION,
                confidence=0.95,
                evidence_nodes=[s.id for s in services],
                metadata={"service_count": len(services)},
            )

        # 5. PARAMETERIZED RESOURCE API (Subject to Authorization & Tenancy / BOLA checks)
        param_apis = [a for a in api_nodes if "{" in a.name or ":" in a.name or "<" in a.name or "{" in a.metadata.get("path", "")]
        if param_apis:
            capabilities[CapabilityType.PARAMETERIZED_RESOURCE_API] = DiscoveredCapability(
                capability_type=CapabilityType.PARAMETERIZED_RESOURCE_API,
                confidence=0.99,
                evidence_nodes=[a.id for a in param_apis],
                metadata={"parameterized_endpoint_count": len(param_apis)},
            )

        # 6. UI INTERACTION
        if ui_nodes:
            capabilities[CapabilityType.UI_INTERACTION] = DiscoveredCapability(
                capability_type=CapabilityType.UI_INTERACTION,
                confidence=0.95,
                evidence_nodes=[u.id for u in ui_nodes],
                metadata={"interactive_control_count": len(ui_nodes)},
            )

        return capabilities

    def derive_applicable_requirements(self) -> list[ApplicableRequirement]:
        caps = self.discover_capabilities()
        reqs: list[ApplicableRequirement] = []

        # Rule 1: Rate Limiting & Brute Force Protection
        if CapabilityType.AUTHENTICATION in caps:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-AUTH-RATELIMIT",
                name="Authentication Rate Limiting & Throttling",
                capability_type=CapabilityType.AUTHENTICATION,
                is_applicable=True,
                reason="Authentication endpoints discovered; rate-limiting is required for production security.",
                required_checks=["RATE_LIMIT_CHECK"],
                status=AuditStatus.UNVERIFIED,
            ))
        else:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-AUTH-RATELIMIT",
                name="Authentication Rate Limiting & Throttling",
                capability_type=CapabilityType.AUTHENTICATION,
                is_applicable=False,
                reason="No authentication routes or credential handling discovered.",
                status=AuditStatus.NOT_APPLICABLE,
            ))

        # Rule 2: File Upload Safety & Constraints
        if CapabilityType.FILE_UPLOAD in caps:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-UPLOAD-CONSTRAINTS",
                name="File Upload Size & MIME Constraints",
                capability_type=CapabilityType.FILE_UPLOAD,
                is_applicable=True,
                reason="File upload endpoints discovered; size validation and MIME type allowlist are required.",
                required_checks=["UPLOAD_SIZE_CHECK", "MIME_ALLOWLIST_CHECK"],
                status=AuditStatus.UNVERIFIED,
            ))
        else:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-UPLOAD-CONSTRAINTS",
                name="File Upload Size & MIME Constraints",
                capability_type=CapabilityType.FILE_UPLOAD,
                is_applicable=False,
                reason="No file upload endpoints discovered.",
                status=AuditStatus.NOT_APPLICABLE,
            ))

        # Rule 3: Object-Level Authorization Boundary (BOLA / IDOR)
        if CapabilityType.PARAMETERIZED_RESOURCE_API in caps:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-BOLA-AUTH-BOUNDARY",
                name="Object-Level Tenancy & Ownership Validation",
                capability_type=CapabilityType.PARAMETERIZED_RESOURCE_API,
                is_applicable=True,
                reason="Parameterized resource identifiers in API routes discovered; tenancy boundary validation applies.",
                required_checks=["BOLA_OWNERSHIP_CHECK"],
                status=AuditStatus.UNVERIFIED,
            ))
        else:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-BOLA-AUTH-BOUNDARY",
                name="Object-Level Tenancy & Ownership Validation",
                capability_type=CapabilityType.PARAMETERIZED_RESOURCE_API,
                is_applicable=False,
                reason="No parameterized resource identifier endpoints discovered.",
                status=AuditStatus.NOT_APPLICABLE,
            ))

        # Rule 4: External Service Resiliency & Timeouts
        if CapabilityType.EXTERNAL_SERVICE_INTEGRATION in caps:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-EXTERNAL-TIMEOUT",
                name="External Service Bounded Timeouts & Resilience",
                capability_type=CapabilityType.EXTERNAL_SERVICE_INTEGRATION,
                is_applicable=True,
                reason="External APIs/SDKs discovered; bounded timeout and retry policies apply.",
                required_checks=["TIMEOUT_CONFIG_CHECK"],
                status=AuditStatus.UNVERIFIED,
            ))
        else:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-EXTERNAL-TIMEOUT",
                name="External Service Bounded Timeouts & Resilience",
                capability_type=CapabilityType.EXTERNAL_SERVICE_INTEGRATION,
                is_applicable=False,
                reason="No external third-party service dependencies discovered.",
                status=AuditStatus.NOT_APPLICABLE,
            ))

        # Rule 5: UI Actionable Element Handlers
        if CapabilityType.UI_INTERACTION in caps:
            reqs.append(ApplicableRequirement(
                id="REQ-APP-UI-HANDLER-INTEGRITY",
                name="Actionable UI Element Handler Binding",
                capability_type=CapabilityType.UI_INTERACTION,
                is_applicable=True,
                reason="Interactive UI elements discovered; all clickable elements must have active execution handlers.",
                required_checks=["UI_HANDLER_CHECK"],
                status=AuditStatus.UNVERIFIED,
            ))

        return reqs
