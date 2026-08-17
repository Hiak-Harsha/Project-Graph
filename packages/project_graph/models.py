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
    API_ENDPOINT = "API_ENDPOINT"
    DATABASE_ENTITY = "DATABASE_ENTITY"
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"
    CONFIG = "CONFIG"
    TEST = "TEST"
    FEATURE = "FEATURE"
    REQUIREMENT = "REQUIREMENT"


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
    NodeType.API_ENDPOINT: "API",
    NodeType.DATABASE_ENTITY: "DB",
    NodeType.EXTERNAL_SERVICE: "EXT",
    NodeType.CONFIG: "CFG",
    NodeType.TEST: "TEST",
    NodeType.FEATURE: "FEATURE",
    NodeType.REQUIREMENT: "REQ",
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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        d["audit_status"] = self.audit_status.value
        return d


@dataclass
class GraphEdge:
    source: str
    relationship: EdgeRelationship
    target: str
    static_evidence: bool = False
    runtime_evidence: bool = False
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["relationship"] = self.relationship.value
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
