"""
Identity Fixture & Provisioning Manager (spec Milestone 2 §6 / P6)

Distinguishes between:
1. IdentityTemplate: Unauthenticated descriptor/specification (role, requirements, scope)
2. ProvisionedIdentity: Authenticated runtime identity backed by live container session/token

Enforces that identity templates NEVER become synthetic credentials automatically.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class IdentityTemplate:
    persona_name: str
    role: str
    description: str
    required_claims: dict[str, Any] = field(default_factory=dict)
    owned_resources: list[str] = field(default_factory=list)


@dataclass
class ProvisionedIdentity:
    persona_name: str
    user_id: str
    role: str
    headers: dict[str, str] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)
    owned_resources: list[str] = field(default_factory=list)
    is_live: bool = True
    provisioning_evidence_id: Optional[str] = None


@dataclass
class AuthorizationProbe:
    probe_id: str
    actor_persona: str
    target_resource_id: str
    owner_persona: str
    expected_status: int
    probe_category: str  # OWNER_ACCESS | CROSS_TENANT_ACCESS | UNAUTHENTICATED_ACCESS | ADMIN_ACCESS


# Backward compatibility alias
IdentityPersona = IdentityTemplate


class IdentityFixtureManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.templates: dict[str, IdentityTemplate] = self._canonical_templates()
        self.provisioned: dict[str, ProvisionedIdentity] = {}

    def _canonical_templates(self) -> dict[str, IdentityTemplate]:
        return {
            "anonymous": IdentityTemplate(
                persona_name="anonymous",
                role="ANONYMOUS",
                description="Unauthenticated client without session headers",
            ),
            "user_A": IdentityTemplate(
                persona_name="user_A",
                role="USER",
                description="Primary resource owner (Tenant A)",
                required_claims={"tenant_id": "tenant-a"},
                owned_resources=["resource-001"],
            ),
            "user_B": IdentityTemplate(
                persona_name="user_B",
                role="USER",
                description="Isolated secondary user / Attacker (Tenant B)",
                required_claims={"tenant_id": "tenant-b"},
                owned_resources=["resource-002"],
            ),
            "admin": IdentityTemplate(
                persona_name="admin",
                role="ADMIN",
                description="Privileged system operator",
                required_claims={"role": "ADMIN"},
            ),
        }

    def generate_authorization_matrix(self, resource_id: str, owner: str = "user_A") -> list[AuthorizationProbe]:
        """Generate canonical 4-identity authorization probes for a given resource."""
        return [
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-OWNER",
                actor_persona="user_A",
                target_resource_id=resource_id,
                owner_persona=owner,
                expected_status=200,
                probe_category="OWNER_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-BOLA-CROSS-TENANT",
                actor_persona="user_B",
                target_resource_id=resource_id,
                owner_persona=owner,
                expected_status=403,
                probe_category="CROSS_TENANT_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-UNAUTHENTICATED",
                actor_persona="anonymous",
                target_resource_id=resource_id,
                owner_persona=owner,
                expected_status=401,
                probe_category="UNAUTHENTICATED_ACCESS",
            ),
            AuthorizationProbe(
                probe_id=f"PROBE-{resource_id}-ADMIN",
                actor_persona="admin",
                target_resource_id=resource_id,
                owner_persona=owner,
                expected_status=200,
                probe_category="ADMIN_ACCESS",
            ),
        ]

    def load_fixture_template(self) -> dict[str, Any]:
        path = self.root / ".project-graph" / "identity-fixtures.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass

        return {
            "version": "1.0",
            "templates": {k: asdict(v) for k, v in self.templates.items()},
            "provisioned": False,
            "endpoints": {
                "GET /api/resource/{id}": {
                    "owner_persona": "user_A",
                    "attacker_persona": "user_B",
                    "resource_id": "1",
                    "expected_owner_status": 200,
                    "expected_attacker_status": 403,
                }
            },
        }
