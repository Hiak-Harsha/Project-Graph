"""
Identity Fixture Manager (spec Milestone 2 §6 / P6)

Provisions canonical multi-tenant personas and resource mappings for deterministic
BOLA/IDOR and access boundary verification without synthetic or guessed identities:
- anonymous: unauthenticated client
- user_A: primary resource owner (Tenant A)
- user_B: isolated secondary user (Attacker / Tenant B)
- admin: privileged operator
- expired_user: revoked or timed-out session
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class IdentityPersona:
    id: str
    role: str
    headers: dict[str, str] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)
    owned_resources: list[str] = field(default_factory=list)


@dataclass
class AuthorizationProbe:
    probe_id: str
    actor: str
    target_resource_id: str
    owner: str
    expected_status: int
    probe_category: str  # OWNER_ACCESS | CROSS_TENANT_ACCESS | UNAUTHENTICATED_ACCESS | ADMIN_ACCESS


class IdentityFixtureManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.identities: dict[str, IdentityPersona] = self._default_personas()

    def _default_personas(self) -> dict[str, IdentityPersona]:
        return {
            "anonymous": IdentityPersona(
                id="anonymous",
                role="ANONYMOUS",
                headers={},
                claims={},
                owned_resources=[],
            ),
            "user_A": IdentityPersona(
                id="user-001",
                role="USER",
                headers={"Authorization": "Bearer token-user-a-valid"},
                claims={"sub": "user-001", "role": "USER", "tenant_id": "tenant-a"},
                owned_resources=["resume-001", "profile-001"],
            ),
            "user_B": IdentityPersona(
                id="user-002",
                role="USER",
                headers={"Authorization": "Bearer token-user-b-valid"},
                claims={"sub": "user-002", "role": "USER", "tenant_id": "tenant-b"},
                owned_resources=["resume-002", "profile-002"],
            ),
            "admin": IdentityPersona(
                id="admin-001",
                role="ADMIN",
                headers={"Authorization": "Bearer token-admin-valid"},
                claims={"sub": "admin-001", "role": "ADMIN"},
                owned_resources=[],
            ),
        }

    def generate_authorization_matrix(self, resource_id: str, owner: str = "user_A") -> list[AuthorizationProbe]:
        """Generate canonical 4-identity authorization probes for a given resource."""
        return [
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-OWNER",
                actor="user_A",
                target_resource_id=resource_id,
                owner=owner,
                expected_status=200,
                probe_category="OWNER_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-BOLA-CROSS-TENANT",
                actor="user_B",
                target_resource_id=resource_id,
                owner=owner,
                expected_status=403,
                probe_category="CROSS_TENANT_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-UNAUTHENTICATED",
                actor="anonymous",
                target_resource_id=resource_id,
                owner=owner,
                expected_status=401,
                probe_category="UNAUTHENTICATED_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-ADMIN",
                actor="admin",
                target_resource_id=resource_id,
                owner=owner,
                expected_status=200,
                probe_category="ADMIN_ACCESS",
            ),
        ]

    def load_or_create_fixtures(self) -> dict[str, Any]:
        path = self.root / ".project-graph" / "identity-fixtures.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Synthesize default fixture template
        data = {
            "version": "1.0",
            "identities": {k: asdict(v) for k, v in self.identities.items()},
            "endpoints": {
                "GET /api/resume/{id}": {
                    "owner_identity": "user_A",
                    "attacker_identity": "user_B",
                    "resource_id": "1",
                    "expected_owner_status": 200,
                    "expected_attacker_status": 403,
                }
            },
        }
        return data
