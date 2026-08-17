"""
Evidence Store: In-memory registry with immutable hash tracking and serialization.
"""
from __future__ import annotations

import itertools
from typing import Optional
from .models import Evidence, EvidenceType

_ev_counter = itertools.count(1)


def next_evidence_id() -> str:
    return f"EV-{next(_ev_counter):05d}"


def reset_evidence_counter() -> None:
    global _ev_counter
    _ev_counter = itertools.count(1)


class EvidenceStore:
    def __init__(self) -> None:
        self._records: dict[str, Evidence] = {}

    def add(
        self,
        evidence_type: EvidenceType,
        target_id: str,
        summary: str,
        source_location: Optional[str] = None,
        payload: Optional[dict] = None,
    ) -> Evidence:
        ev_id = next_evidence_id()
        ev = Evidence(
            id=ev_id,
            evidence_type=evidence_type,
            target_id=target_id,
            summary=summary,
            source_location=source_location,
            payload=payload or {},
        )
        self._records[ev.id] = ev
        return ev

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._records.get(evidence_id)

    def find_by_target(self, target_id: str) -> list[Evidence]:
        return [e for e in self._records.values() if e.target_id == target_id]

    def all(self) -> list[Evidence]:
        return list(self._records.values())

    def to_dict_list(self) -> list[dict]:
        return [e.to_dict() for e in self._records.values()]
