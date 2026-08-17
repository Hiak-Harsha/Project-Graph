"""
Project Intake Registry & Multi-Audit Manager (spec Milestone 2 §1-4)

Manages multi-tenant project registration, content-addressed revisions,
and isolated audit runs.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Optional

from packages.evidence.reproducibility import ReproducibilityEngine
from packages.evidence.store import EvidenceStore
from packages.intake.models import AuditRunRecord, Project, ProjectRevision, SourceType
from packages.project_graph.store import ProjectGraph
from workers.audit_orchestrator import run_full_audit


class ProjectRegistry:
    def __init__(self, workspace_dir: Optional[Path] = None) -> None:
        self.workspace_dir = workspace_dir or Path(tempfile.gettempdir()) / "project_graph_intake"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.projects: dict[str, Project] = {}
        self.revisions: dict[str, list[ProjectRevision]] = {}
        self.audit_runs: dict[str, AuditRunRecord] = {}
        self.audit_graphs: dict[str, ProjectGraph] = {}
        self.audit_evidence_stores: dict[str, EvidenceStore] = {}
        self._project_counter = 0
        self._audit_counter = 0

    def register_project(
        self,
        name: str,
        source_type: SourceType | str,
        source_location: str | Path,
        is_benchmark: bool = False,
    ) -> Project:
        if isinstance(source_type, str):
            source_type = SourceType(source_type)

        self._project_counter += 1
        project_id = f"PRJ-{self._project_counter:04d}"
        
        project = Project(
            project_id=project_id,
            name=name,
            source_type=source_type,
            source_location=str(source_location),
            is_benchmark=is_benchmark,
        )
        self.projects[project_id] = project
        self.revisions[project_id] = []
        return project

    def create_revision(self, project_id: str) -> ProjectRevision:
        project = self.projects.get(project_id)
        if not project:
            raise ValueError(f"Project '{project_id}' not found in registry.")

        source_path = Path(project.source_location)

        # If ZIP archive, extract to workspace
        if project.source_type == SourceType.ZIP_ARCHIVE and source_path.is_file():
            extract_dest = self.workspace_dir / project_id / "extracted"
            extract_dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(source_path, "r") as z:
                z.extractall(extract_dest)
            target_dir = extract_dest
        else:
            target_dir = source_path

        # Compute content-addressed Merkle hash and Git SHA
        repro = ReproducibilityEngine(EvidenceStore())
        inventory_hash = repro.compute_file_inventory_merkle_hash(target_dir)
        rev_id, rev_type, _ = repro.resolve_revision(target_dir)

        revision = ProjectRevision(
            revision_id=f"REV-{rev_id[:12]}",
            project_id=project_id,
            revision_type=rev_type,
            content_hash=inventory_hash,
            source_path=str(target_dir),
            git_sha=(rev_id if rev_type == "GIT_COMMIT" else None),
        )
        self.revisions[project_id].append(revision)
        return revision

    def run_audit_for_project(self, project_id: str, revision_id: Optional[str] = None) -> AuditRunRecord:
        project = self.projects.get(project_id)
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        # If no revision exists or requested, create one
        revs = self.revisions.get(project_id, [])
        if not revs:
            revision = self.create_revision(project_id)
        elif revision_id:
            revision = next((r for r in revs if r.revision_id == revision_id), None)
            if not revision:
                raise ValueError(f"Revision '{revision_id}' not found for project '{project_id}'.")
        else:
            revision = revs[-1]

        self._audit_counter += 1
        audit_id = f"AUDIT-{self._audit_counter:04d}"

        # Execute full audit against revision source
        graph, evidence_store, summary = run_full_audit(Path(revision.source_path))

        run_record = AuditRunRecord(
            audit_id=audit_id,
            project_id=project_id,
            revision_id=revision.revision_id,
            status="COMPLETED",
            certification_state=summary.get("verdict", {}).get("certification_state", "AUDITED_NOT_PRODUCTION_READY"),
            overall_score=summary.get("verdict", {}).get("overall_score", 0.0),
            elapsed_seconds=summary.get("elapsed_seconds", 0.0),
            summary=summary,
        )

        self.audit_runs[audit_id] = run_record
        self.audit_graphs[audit_id] = graph
        self.audit_evidence_stores[audit_id] = evidence_store

        return run_record

    def get_latest_audit(self) -> Optional[AuditRunRecord]:
        if not self.audit_runs:
            return None
        latest_id = sorted(self.audit_runs.keys())[-1]
        return self.audit_runs[latest_id]

    def list_projects(self) -> list[dict[str, Any]]:
        result = []
        for p in self.projects.values():
            p_dict = p.to_dict()
            p_dict["revisions_count"] = len(self.revisions.get(p.project_id, []))
            p_dict["audits_count"] = sum(1 for a in self.audit_runs.values() if a.project_id == p.project_id)
            result.append(p_dict)
        return result
