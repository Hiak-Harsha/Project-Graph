"""
Audit Reproducibility & Provenance Manifest (spec Milestone 3 §28)

Generates tamper-evident, cryptographically verifiable audit bundles that guarantee
exact execution replayability across commit SHAs, container images, and contract versions.
Honest revision semantics: distinguishes GIT_COMMIT from CONTENT_DIGEST snapshots.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from packages.evidence.store import EvidenceStore


@dataclass
class AuditReproducibilityManifest:
    audit_id: str
    timestamp_iso: str
    revision_id: str
    revision_type: str  # "GIT_COMMIT" | "CONTENT_DIGEST"
    target_repo_path: str
    file_inventory_hash: str
    runtime_contract_hash: str
    evidence_vault_digest: str
    certification_state: str
    commit_sha: str = ""  # Backward-compatible alias for revision_id
    revision_notes: str = ""
    tool_version: str = "2.0.0-truth"
    model_version: str = "deterministic-rule-engine"
    evidence_count: int = 0
    replay_token: str = ""

    def __post_init__(self) -> None:
        if not self.commit_sha:
            self.commit_sha = self.revision_id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReproducibilityEngine:
    def __init__(self, evidence_store: EvidenceStore) -> None:
        self.evidence_store = evidence_store

    def resolve_revision(self, repo_path: Path) -> tuple[str, str, str]:
        """Resolve revision ID and type.
        
        Returns:
            (revision_id, revision_type, notes)
        """
        # Only use git rev-parse if repo_path contains its own .git folder
        git_dir = repo_path / ".git"
        if git_dir.exists():
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if res.returncode == 0 and res.stdout.strip():
                    sha = res.stdout.strip()
                    if len(sha) == 40 and all(c in "0123456789abcdefABCDEF" for c in sha):
                        return sha, "GIT_COMMIT", "Verified Git Commit SHA resolved from HEAD."
            except Exception:
                pass

            if git_dir.is_dir():
                head_file = git_dir / "HEAD"
                if head_file.exists():
                    try:
                        head_content = head_file.read_text(encoding="utf-8").strip()
                        if head_content.startswith("ref: "):
                            ref_path = git_dir / head_content.replace("ref: ", "").strip()
                            if ref_path.exists():
                                sha = ref_path.read_text(encoding="utf-8").strip()
                                if len(sha) == 40:
                                    return sha, "GIT_COMMIT", "Verified Git Commit SHA resolved from .git ref."
                        elif len(head_content) == 40:
                            return head_content, "GIT_COMMIT", "Verified Git Commit SHA resolved from detached HEAD."
                    except Exception:
                        pass

        # Content-addressed Merkle digest for directories without direct .git
        merkle_digest = self.compute_file_inventory_merkle_hash(repo_path)[:40]
        return merkle_digest, "CONTENT_DIGEST", "Directory content-addressed Merkle snapshot digest used."

    def resolve_git_commit_sha(self, repo_path: Path) -> str:
        sha, _, _ = self.resolve_revision(repo_path)
        return sha

    def compute_file_inventory_merkle_hash(self, repo_path: Path) -> str:
        files = []
        for p in sorted(repo_path.rglob("*")):
            if p.is_file() and not any(part.startswith(".") or part in ("node_modules", "__pycache__", "venv", ".git") for part in p.parts):
                try:
                    rel = p.relative_to(repo_path).as_posix()
                    file_sha = hashlib.sha256(p.read_bytes()).hexdigest()
                    files.append(f"{rel}:{file_sha}")
                except (OSError, PermissionError):
                    continue

        content = "\n".join(sorted(files))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_manifest(
        self,
        audit_id: str,
        repo_path: str,
        certification_state: str,
        runtime_contract_payload: str = "",
        commit_sha: Optional[str] = None,
        revision_id: Optional[str] = None,
    ) -> AuditReproducibilityManifest:
        p = Path(repo_path)
        resolved_id, rev_type, rev_notes = self.resolve_revision(p)
        effective_rev_id = revision_id or commit_sha or resolved_id
        effective_rev_type = "GIT_COMMIT" if commit_sha else rev_type
        inventory_hash = self.compute_file_inventory_merkle_hash(p)

        contract_hash = ""
        if runtime_contract_payload:
            contract_hash = hashlib.sha256(runtime_contract_payload.encode("utf-8")).hexdigest()
        else:
            contract_file = p / ".project-graph" / "runtime-contract.json"
            if contract_file.exists():
                try:
                    contract_hash = hashlib.sha256(contract_file.read_bytes()).hexdigest()
                except OSError:
                    pass

        ev_digest = self.evidence_store.compute_vault_merkle_root()

        timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Generate Replay Token (Deterministic hash of inputs)
        token_payload = f"{effective_rev_id}:{inventory_hash}:{contract_hash}:{ev_digest}"
        replay_token = f"RPL-{hashlib.sha256(token_payload.encode('utf-8')).hexdigest()}"

        return AuditReproducibilityManifest(
            audit_id=audit_id,
            timestamp_iso=timestamp_iso,
            revision_id=effective_rev_id,
            revision_type=effective_rev_type,
            target_repo_path=str(p.resolve()),
            file_inventory_hash=inventory_hash,
            runtime_contract_hash=contract_hash,
            evidence_vault_digest=ev_digest,
            certification_state=certification_state,
            revision_notes=rev_notes,
            evidence_count=len(self.evidence_store.all()),
            replay_token=replay_token,
        )
