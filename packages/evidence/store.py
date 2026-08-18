"""
Evidence Store: In-memory registry with immutable hash tracking and serialization.
"""
from __future__ import annotations

import hashlib
import itertools
from typing import Optional
from .models import Evidence, EvidenceClaim, EvidenceType

_ev_counter = itertools.count(1)


def next_evidence_id() -> str:
    return f"EV-{next(_ev_counter):05d}"


_claim_counter = itertools.count(1)


def next_claim_id() -> str:
    return f"CLAIM-{next(_claim_counter):04d}"


def reset_evidence_counter() -> None:
    global _ev_counter, _claim_counter
    _ev_counter = itertools.count(1)
    _claim_counter = itertools.count(1)


class EvidenceStore:
    def __init__(self) -> None:
        self._records: dict[str, Evidence] = {}
        self._claims: dict[str, EvidenceClaim] = {}

    def add(
        self,
        evidence_type: EvidenceType,
        target_id: str,
        summary: str,
        source_location: Optional[str] = None,
        payload: Optional[dict] = None,
        artifact_bytes: Optional[bytes] = None,
        artifact_uri: Optional[str] = None,
        mime_type: str = "application/json",
        execution_id: Optional[str] = None,
        producer: str = "VerificationRunner",
    ) -> Evidence:
        ev_id = next_evidence_id()
        sha_hash = ""
        if artifact_bytes is not None:
            sha_hash = hashlib.sha256(artifact_bytes).hexdigest()

        ev = Evidence(
            id=ev_id,
            evidence_type=evidence_type,
            target_id=target_id,
            summary=summary,
            source_location=source_location,
            payload=payload or {},
            sha256_hash=sha_hash,
            artifact_uri=artifact_uri,
            mime_type=mime_type,
            execution_id=execution_id,
            producer=producer,
        )
        self._records[ev.id] = ev
        return ev

    def add_claim(
        self,
        statement: str,
        target_id: str,
        evidence_ids: list[str],
        counter_evidence_ids: Optional[list[str]] = None,
        evidence_strength: str = "RUNTIME_OBSERVED",
        source: str = "VerificationRunner",
        confidence: float = 1.0,
        status: str = "CONFIRMED",
    ) -> EvidenceClaim:
        claim_id = next_claim_id()
        claim = EvidenceClaim(
            id=claim_id,
            statement=statement,
            target_id=target_id,
            evidence_ids=evidence_ids,
            counter_evidence_ids=counter_evidence_ids or [],
            evidence_strength=evidence_strength,
            source=source,
            confidence=confidence,
            status=status,
        )
        self._claims[claim.id] = claim
        return claim

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._records.get(evidence_id)

    def get_claim(self, claim_id: str) -> Optional[EvidenceClaim]:
        return self._claims.get(claim_id)

    def find_by_target(self, target_id: str) -> list[Evidence]:
        return [e for e in self._records.values() if e.target_id == target_id]

    def find_claims_by_target(self, target_id: str) -> list[EvidenceClaim]:
        return [c for c in self._claims.values() if c.target_id == target_id]

    def all(self) -> list[Evidence]:
        return list(self._records.values())

    def all_claims(self) -> list[EvidenceClaim]:
        return list(self._claims.values())

    def to_dict_list(self) -> list[dict]:
        return [e.to_dict() for e in self._records.values()]

    def claims_to_dict_list(self) -> list[dict]:
        return [c.to_dict() for c in self._claims.values()]

    def compute_vault_merkle_root(self) -> str:
        hashes = [e.sha256_hash for e in sorted(self._records.values(), key=lambda x: x.id)]
        if not hashes:
            return hashlib.sha256(b"empty_vault").hexdigest()
        combined = "\n".join(hashes)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "records": [e.to_dict() for e in self._records.values()],
            "claims": [c.to_dict() for c in self._claims.values()],
            "merkle_root": self.compute_vault_merkle_root(),
        }
