"""
Project Intake & Identity Data Models (spec Milestone 2 §1-4)

Decouples auditor platform from specific benchmarks by providing first-class
abstractions for Project, ProjectRevision, and AuditRun.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class SourceType(str, Enum):
    LOCAL_DIRECTORY = "LOCAL_DIRECTORY"
    ZIP_ARCHIVE = "ZIP_ARCHIVE"
    GIT_REPOSITORY = "GIT_REPOSITORY"


@dataclass
class Project:
    project_id: str
    name: str
    source_type: SourceType
    source_location: str
    is_benchmark: bool = False
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source_type"] = self.source_type.value if hasattr(self.source_type, "value") else str(self.source_type)
        return d


@dataclass
class ProjectRevision:
    revision_id: str
    project_id: str
    revision_type: str  # "GIT_COMMIT" or "CONTENT_DIGEST"
    content_hash: str
    source_path: str
    git_sha: Optional[str] = None
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditRunRecord:
    audit_id: str
    project_id: str
    revision_id: str
    status: str  # "RUNNING", "COMPLETED", "FAILED"
    certification_state: str = "EVALUATING"
    overall_score: float = 0.0
    elapsed_seconds: float = 0.0
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
