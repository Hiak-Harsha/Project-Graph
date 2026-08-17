"""
Core data models for the Project Graph.

Invariants:
- P1: Discovery and auditing are separate. Every discovered entity terminates in
      VERIFIED | FAILED | UNVERIFIED | N_A.
- P2: Every finding must carry immutable evidence links.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional
import itertools


class AuditStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "N_A"


class NodeType(str, Enum):
    FILE = "FILE"
    MODULE = "MODULE"
    PACKAGE = "PACKAGE"
    FUNCTION = "FUNCTION"
    CLASS = "CLASS"
    UI_ELEMENT = "UI_ELEMENT"
    PAGE = "PAGE"
    ROUTE = "ROUTE"
    FORM = "FORM"
    INPUT = "INPUT"
    API_ENDPOINT = "API_ENDPOINT"
    DATABASE_ENTITY = "DATABASE_ENTITY"
    DATABASE_FIELD = "DATABASE_FIELD"
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"
    CONFIG = "CONFIG"
    TEST = "TEST"
    FEATURE = "FEATURE"
    REQUIREMENT = "REQUIREMENT"
    AUTH_IDENTITY = "AUTH_IDENTITY"
    USER_FLOW = "USER_FLOW"
    STATE = "STATE"


class EdgeRelationship(str, Enum):
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    HANDLED_BY = "HANDLED_BY"
    RENDERS = "RENDERS"
    WRITES_TO = "WRITES_TO"
    READS_FROM = "READS_FROM"
    TESTED_BY = "TESTED_BY"
    IMPLEMENTS = "IMPLEMENTS"
    DEPENDS_ON = "DEPENDS_ON"
    PROTECTED_BY = "PROTECTED_BY"
    TRANSITIONS_TO = "TRANSITIONS_TO"
    SUBMITS_TO = "SUBMITS_TO"


class EvidenceLevel(str, Enum):
    DIRECT_STATIC = "DIRECT_STATIC"
    STATIC_DATAFLOW = "STATIC_DATAFLOW"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    TEST_OBSERVED = "TEST_OBSERVED"
    INFERRED = "INFERRED"
    POSSIBLE = "POSSIBLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingCategory(str, Enum):
    SECURITY = "SECURITY"
    DEAD_FUNCTIONALITY = "DEAD_FUNCTIONALITY"
    MISSING_REQUIREMENT = "MISSING_REQUIREMENT"
    RELIABILITY = "RELIABILITY"
    ARCHITECTURE = "ARCHITECTURE"
    CODE_QUALITY = "CODE_QUALITY"
    TESTING_GAP = "TESTING_GAP"
    DATA_CONSISTENCY = "DATA_CONSISTENCY"


class ExecutionTier(str, Enum):
    STATIC_AST = "STATIC_AST"
    STATIC_PATTERN = "STATIC_PATTERN"
    STATIC_GRAPH = "STATIC_GRAPH"
    TEST_RUNNER = "TEST_RUNNER"
    RUNTIME_HTTP = "RUNTIME_HTTP"
    RUNTIME_BROWSER = "RUNTIME_BROWSER"
    RUNTIME_TEST = "RUNTIME_TEST"
    MODEL_REASONING = "MODEL_REASONING"


class CheckStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "N_A"
    SKIPPED = "SKIPPED"


@dataclass
class AuditCheck:
    id: str
    target_id: str
    name: str
    description: str
    execution_tier: ExecutionTier
    status: CheckStatus = CheckStatus.UNVERIFIED
    required: bool = True
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    unverified_reason: Optional[str] = None
    execution_method: str = "STATIC"
    preconditions: list[str] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    expected_observations: list[str] = field(default_factory=list)
    success_conditions: list[str] = field(default_factory=list)
    failure_conditions: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    timeout: Optional[int] = None
    risk_level: str = "MEDIUM"
    destructive: bool = False
    dependencies: list[str] = field(default_factory=list)
    capability_requirements: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["execution_tier"] = self.execution_tier.value
        d["status"] = self.status.value
        return d


# Monotonic per-type counters -> stable human-legible IDs (FILE-0001, UI-0092, ...)
_counters: dict[str, itertools.count] = {}

_PREFIX = {
    NodeType.FILE: "FILE",
    NodeType.MODULE: "MODULE",
    NodeType.PACKAGE: "DEP",
    NodeType.FUNCTION: "FUNC",
    NodeType.CLASS: "CLASS",
    NodeType.UI_ELEMENT: "UI",
    NodeType.PAGE: "PAGE",
    NodeType.ROUTE: "ROUTE",
    NodeType.FORM: "FORM",
    NodeType.INPUT: "INPUT",
    NodeType.API_ENDPOINT: "API",
    NodeType.DATABASE_ENTITY: "DB",
    NodeType.DATABASE_FIELD: "DBF",
    NodeType.EXTERNAL_SERVICE: "EXT",
    NodeType.CONFIG: "CFG",
    NodeType.TEST: "TEST",
    NodeType.FEATURE: "FEATURE",
    NodeType.REQUIREMENT: "REQ",
    NodeType.AUTH_IDENTITY: "IDENT",
    NodeType.USER_FLOW: "FLOW",
    NodeType.STATE: "STATE",
}


def next_id(node_type: NodeType) -> str:
    counter = _counters.setdefault(node_type.value, itertools.count(1))
    return f"{_PREFIX[node_type]}-{next(counter):04d}"


def reset_id_counters() -> None:
    """Reset counters at the start of every discovery run so IDs are deterministic."""
    _counters.clear()


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)
    audit_status: AuditStatus = AuditStatus.UNVERIFIED
    static_status: AuditStatus = AuditStatus.UNVERIFIED
    runtime_status: AuditStatus = AuditStatus.UNVERIFIED
    checks: list[str] = field(default_factory=list)
    unverified_reasons: list[str] = field(default_factory=list)

    def derive_audit_status(self, assigned_checks: Optional[list[AuditCheck]] = None) -> AuditStatus:
        if assigned_checks:
            req_checks = [c for c in assigned_checks if c.required]
            if not req_checks:
                return AuditStatus.VERIFIED

            if any(c.status in (CheckStatus.FAILED, CheckStatus.ERROR) for c in req_checks):
                return AuditStatus.FAILED

            if any(c.status in (CheckStatus.UNVERIFIED, CheckStatus.BLOCKED, CheckStatus.PENDING) for c in req_checks):
                return AuditStatus.UNVERIFIED

            if all(c.status in (CheckStatus.PASSED, CheckStatus.NOT_APPLICABLE, CheckStatus.SKIPPED) for c in req_checks):
                return AuditStatus.VERIFIED

        # Fallback to tier statuses if no checks provided
        if self.static_status == AuditStatus.FAILED or self.runtime_status == AuditStatus.FAILED:
            return AuditStatus.FAILED
        if self.static_status == AuditStatus.UNVERIFIED or self.runtime_status == AuditStatus.UNVERIFIED:
            return AuditStatus.UNVERIFIED
        if self.static_status == AuditStatus.NOT_APPLICABLE and self.runtime_status == AuditStatus.NOT_APPLICABLE:
            return AuditStatus.NOT_APPLICABLE
        if self.static_status == AuditStatus.VERIFIED and self.runtime_status in (AuditStatus.VERIFIED, AuditStatus.NOT_APPLICABLE):
            return AuditStatus.VERIFIED
        if self.static_status == AuditStatus.NOT_APPLICABLE and self.runtime_status == AuditStatus.VERIFIED:
            return AuditStatus.VERIFIED
        return AuditStatus.UNVERIFIED

    def refresh_audit_status(self, assigned_checks: Optional[list[AuditCheck]] = None) -> AuditStatus:
        self.audit_status = self.derive_audit_status(assigned_checks)
        return self.audit_status

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        d["audit_status"] = self.audit_status.value
        d["static_status"] = self.static_status.value
        d["runtime_status"] = self.runtime_status.value
        return d


@dataclass
class GraphEdge:
    source: str
    relationship: EdgeRelationship
    target: str
    static_evidence: bool = False
    runtime_evidence: bool = False
    confidence: float = 1.0
    evidence_level: EvidenceLevel = EvidenceLevel.DIRECT_STATIC
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["relationship"] = self.relationship.value
        d["evidence_level"] = self.evidence_level.value
        return d


@dataclass
class AuditTask:
    id: str
    task_type: str
    target_id: str
    required_checks: list[str]
    status: str = "PENDING"  # PENDING | COMPLETED | FAILED | SKIPPED
    dependencies: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    status: str  # CONFIRMED | UNVERIFIED | CHALLENGED | RESOLVED
    confidence: float  # 0.0 to 1.0
    affected_feature: str
    affected_nodes: list[str]
    description: str
    observed_behavior: str
    expected_behavior: str
    evidence_ids: list[str]
    root_cause: str
    recommendation: str
    reproduction_steps: list[str] = field(default_factory=list)
    adversarial_verdict: Optional[str] = None  # CONFIRM | REJECT | DOWNGRADE | UPGRADE

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d
