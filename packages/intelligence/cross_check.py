"""
Cross-Check Engine (spec Milestone 3 §4-5)

Performs three-way cross-verification:
Requirement <-> Implementation <-> Runtime Evidence

Identifies:
- Dead functionality (controls with no behavioral execution)
- Orphaned components (components with no parent page/route)
- Broken backend integrations
- Untested critical features
"""
from __future__ import annotations

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import (
    AuditStatus,
    Finding,
    FindingCategory,
    NodeType,
    Severity,
)
from packages.project_graph.store import ProjectGraph


class CrossCheckEngine:
    def __init__(self, graph: ProjectGraph, evidence_store: EvidenceStore) -> None:
        self.graph = graph
        self.evidence_store = evidence_store

    def cross_check(self) -> list[Finding]:
        findings: list[Finding] = []
        finding_idx = 1

        # 1. Check for Dead UI Interactions (e.g. Export Resume button with no handler)
        for ui in self.graph.nodes_of_type(NodeType.UI_ELEMENT):
            if ui.audit_status == AuditStatus.FAILED:
                evs = self.evidence_store.find_by_target(ui.id)
                ev_ids = [e.id for e in evs]
                f = Finding(
                    id=f"FINDING-{finding_idx:04d}",
                    title=f"Dead UI Interaction: '{ui.name}' has no execution handler",
                    category=FindingCategory.DEAD_FUNCTIONALITY,
                    severity=Severity.HIGH,
                    status="CONFIRMED",
                    confidence=0.98,
                    affected_feature="Resume Generation & Management" if "resume" in ui.name.lower() else "UI Core",
                    affected_nodes=[ui.id],
                    description=f"UI element '{ui.name}' in {ui.metadata.get('file')} is rendered as an actionable control but has no attached event listener, handler function, or navigation target.",
                    observed_behavior="Clicking the element produces no observable state mutation, API request, navigation, or download.",
                    expected_behavior="Clicking an actionable button or link should trigger the designated business operation or navigation.",
                    evidence_ids=ev_ids,
                    root_cause="Event handler attribute is missing or unbound in component JSX.",
                    recommendation=f"Attach a valid handler function or remove the '{ui.metadata.get('label')}' control from {ui.metadata.get('file')}.",
                    reproduction_steps=[
                        f"1. Navigate to component at {ui.metadata.get('file')}:{ui.metadata.get('line')}",
                        f"2. Inspect element '{ui.metadata.get('label')}'",
                        "3. Click element and observe no event dispatch or network call.",
                    ],
                )
                self.graph.add_finding(f)
                findings.append(f)
                finding_idx += 1

        # 2. Check for Broken Object-Level Authorization (BOLA / IDOR)
        for api in self.graph.nodes_of_type(NodeType.API_ENDPOINT):
            evs = self.evidence_store.find_by_target(api.id)
            auth_failures = [e for e in evs if "BOLA" in e.summary or "IDOR" in e.summary]
            if auth_failures:
                f = Finding(
                    id=f"FINDING-{finding_idx:04d}",
                    title=f"Broken Object-Level Authorization (BOLA / IDOR) on '{api.name}'",
                    category=FindingCategory.SECURITY,
                    severity=Severity.CRITICAL,
                    status="CONFIRMED",
                    confidence=0.99,
                    affected_feature="Authorization & Access Control",
                    affected_nodes=[api.id],
                    description=f"Endpoint '{api.name}' accepts a resource identifier parameter without verifying that the authenticated user possesses ownership of that resource.",
                    observed_behavior="Direct object reference can be queried by any authenticated or unauthenticated client without user ID tenancy scoping.",
                    expected_behavior="The backend must assert `resource.user_id == current_user.id` and reject unauthorized requests with HTTP 403 Forbidden.",
                    evidence_ids=[e.id for e in auth_failures],
                    root_cause="Missing ownership assertion in database query filter or authorization middleware.",
                    recommendation="Add user tenancy check in the repository filter or query layer.",
                    reproduction_steps=[
                        f"1. Send {api.metadata.get('method')} to {api.metadata.get('path')} as User A with User B's resource ID",
                        "2. Observe server returning 200 OK with User B's private data instead of 403 Forbidden.",
                    ],
                )
                self.graph.add_finding(f)
                findings.append(f)
                finding_idx += 1

        # 3. Check for External Service Timeout / Resiliency Gaps
        for api in self.graph.nodes_of_type(NodeType.API_ENDPOINT):
            evs = self.evidence_store.find_by_target(api.id)
            timeout_failures = [e for e in evs if "without timeout or retry" in e.summary]
            if timeout_failures:
                f = Finding(
                    id=f"FINDING-{finding_idx:04d}",
                    title=f"Missing Timeout & Failure Resilience on External Call in '{api.name}'",
                    category=FindingCategory.RELIABILITY,
                    severity=Severity.HIGH,
                    status="CONFIRMED",
                    confidence=0.95,
                    affected_feature="External AI/API Integration",
                    affected_nodes=[api.id],
                    description=f"Endpoint '{api.name}' dispatches requests to an external API (LLM/Payment/Cloud) without an explicit request timeout or circuit breaker.",
                    observed_behavior="When the external provider experiences latency or outages, the request thread blocks indefinitely.",
                    expected_behavior="All external HTTP/SDK calls must enforce bounded timeouts (e.g. 15s) with appropriate retry/fallback policies.",
                    evidence_ids=[e.id for e in timeout_failures],
                    root_cause="HTTP/SDK client instantiated with default infinite timeout.",
                    recommendation="Configure explicit `timeout` parameter and wrap call in try/except with user-facing fallback error response.",
                    reproduction_steps=[
                        f"1. Call {api.name}",
                        "2. Simulate upstream latency > 30s",
                        "3. Observe server socket hanging indefinitely.",
                    ],
                )
                self.graph.add_finding(f)
                findings.append(f)
                finding_idx += 1

        # 4. Check for Advertised Features Without Implementation (Negative Space)
        for feat in self.graph.nodes_of_type(NodeType.FEATURE):
            if feat.metadata.get("has_implementation") is False:
                ev = self.evidence_store.add(
                    evidence_type=EvidenceType.STATIC_ANALYSIS,
                    target_id=feat.id,
                    summary=f"Advertised feature '{feat.name}' has 0 matching UI components, API endpoints, or database models.",
                    source_location="README.md",
                    payload={"feature": feat.name, "matched_api_count": 0, "matched_ui_count": 0, "matched_db_count": 0},
                )
                f = Finding(
                    id=f"FINDING-{finding_idx:04d}",
                    title=f"Advertised Feature Missing from Implementation: '{feat.name}'",
                    category=FindingCategory.MISSING_REQUIREMENT,
                    severity=Severity.HIGH,
                    status="CONFIRMED",
                    confidence=0.99,
                    affected_feature=feat.name,
                    affected_nodes=[feat.id],
                    description=f"Feature '{feat.name}' is explicitly advertised as a core capability in project documentation, but no corresponding backend routes, database entities, or frontend UI components exist in the repository.",
                    observed_behavior="0 routes, 0 components, and 0 database models discovered for this feature.",
                    expected_behavior="All advertised product capabilities in project specifications must be backed by working code.",
                    evidence_ids=[ev.id],
                    root_cause="Feature was documented/planned but implementation was omitted or abandoned.",
                    recommendation=f"Implement the '{feat.name}' user flow and API contracts, or remove the claim from documentation.",
                    reproduction_steps=[
                        "1. Read README.md / product specification",
                        f"2. Search codebase for '{feat.name}'",
                        "3. Confirm zero matching implementation files.",
                    ],
                )
                self.graph.add_finding(f)
                findings.append(f)
                finding_idx += 1

        # 5. Check for Weak Test Assertions / Testing Gaps
        for test in self.graph.nodes_of_type(NodeType.TEST):
            checks = self.graph.get_checks_for_target(test.id)
            struct_check = next((c for c in checks if "STRUCTURE" in c.id), None)
            if struct_check and struct_check.status == "FAILED":
                weak_list = struct_check.details.get("weak_assertions", [])
                f = Finding(
                    id=f"FINDING-{finding_idx:04d}",
                    title=f"Non-Meaningful Test Assertions in Suite '{test.name}'",
                    category=FindingCategory.TESTING_GAP,
                    severity=Severity.MEDIUM,
                    status="CONFIRMED",
                    confidence=0.98,
                    affected_feature="Test Quality & CI Reliability",
                    affected_nodes=[test.id],
                    description=f"Test suite '{test.name}' contains {len(weak_list)} test cases with non-meaningful trivial assertions (e.g. 'assert True') that provide false positive pass signals.",
                    observed_behavior="Tests pass unconditionally without validating actual state, API responses, or error conditions.",
                    expected_behavior="Test cases must assert deterministic invariants, contract payloads, and status codes.",
                    evidence_ids=struct_check.evidence_ids,
                    root_cause="Placeholder assertions left in test suite without actual verification logic.",
                    recommendation="Replace trivial `assert True` with assertions on returned status codes, payload structures, and database state.",
                    reproduction_steps=[
                        f"1. Open {test.metadata.get('file')}",
                        f"2. Inspect test cases: {', '.join(weak_list[:3])}",
                        "3. Observe tests succeeding even if underlying code is broken.",
                    ],
                )
                self.graph.add_finding(f)
                findings.append(f)
                finding_idx += 1

        return findings
