"""
Evidence Data Model (spec Milestone 2 §11-12)

"Evidence should be immutable and hashed with SHA-256."
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class EvidenceType(str, Enum):
    STATIC_AST_MATCH = "STATIC_AST_MATCH"
    STATIC_PATTERN_ANALYSIS = "STATIC_PATTERN_ANALYSIS"
    SOURCE_AST = "SOURCE_AST"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DOM_INTERACTION = "DOM_INTERACTION"
    NETWORK_TRACE = "NETWORK_TRACE"
    API_RESPONSE = "API_RESPONSE"
    AUTH_BOUNDARY_TEST = "AUTH_BOUNDARY_TEST"
    TEST_EXECUTION = "TEST_EXECUTION"
    DATABASE_OBSERVATION = "DATABASE_OBSERVATION"
    CONFIG_AUDIT = "CONFIG_AUDIT"
    REPRODUCTION_TRACE = "REPRODUCTION_TRACE"


@dataclass
class Evidence:
    id: str
    evidence_type: EvidenceType
    target_id: str
    summary: str
    source_location: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)
    sha256_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.sha256_hash:
            content = f"{self.id}:{self.evidence_type.value}:{self.target_id}:{json.dumps(self.payload, sort_keys=True)}"
            self.sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence_type"] = self.evidence_type.value
        return d
