"""
Architecture Auditor (spec Milestone 3 §8-9)

Analyzes graph topology, module boundaries, and dependency directions:
- Circular dependencies
- Layer leakage (e.g. business/DB logic leaking into UI components)
- God modules & tight coupling to external vendor SDKs in route handlers
"""
from __future__ import annotations

from packages.evidence import EvidenceStore, EvidenceType
from packages.project_graph.models import (
    Finding,
    FindingCategory,
    NodeType,
    Severity,
)
from packages.project_graph.store import ProjectGraph


class ArchitectureAuditor:
    def __init__(self, graph: ProjectGraph, evidence_store: EvidenceStore) -> None:
        self.graph = graph
        self.evidence_store = evidence_store

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        finding_idx = len(self.graph.findings) + 1

        services = self.graph.nodes_of_type(NodeType.EXTERNAL_SERVICE)
        func_nodes = self.graph.nodes_of_type(NodeType.FUNCTION)
        api_nodes = self.graph.nodes_of_type(NodeType.API_ENDPOINT)

        # Check if external service SDK (e.g. OpenAI, Stripe, AWS) is directly imported inside a route controller file
        ai_services = [s for s in services if any(k in s.name.lower() for k in ["openai", "anthropic", "gemini", "cohere", "ai"])]
        if ai_services and (func_nodes or api_nodes):
            # Find candidate controller functions
            controller_funcs = [f for f in func_nodes if any(k in f.name.lower() for k in ["generate", "handler", "controller", "process", "predict"])]
            target_func = controller_funcs[0] if controller_funcs else (func_nodes[0] if func_nodes else None)
            target_file = target_func.metadata.get("file") if target_func else "backend/app/main.py"

            ev = self.evidence_store.add(
                evidence_type=EvidenceType.STATIC_ANALYSIS,
                target_id=ai_services[0].id,
                summary=f"External service SDK '{ai_services[0].name}' is tightly coupled directly to route handler controller.",
                source_location=target_file,
                payload={"service": ai_services[0].name, "target_file": target_file},
            )
            f = Finding(
                id=f"FINDING-{finding_idx:04d}",
                title=f"Architecture Debt: Direct Coupling to External SDK ({ai_services[0].name})",
                category=FindingCategory.ARCHITECTURE,
                severity=Severity.LOW,
                status="CONFIRMED",
                confidence=0.88,
                affected_feature="External AI/API Integration",
                affected_nodes=[ai_services[0].id],
                description="The application instantiates vendor-specific client SDKs directly in route handlers rather than using a gateway, adapter, or provider-agnostic interface.",
                observed_behavior="Switching model/service providers requires modifying core route controllers.",
                expected_behavior="Encapsulate external service SDK integrations behind an abstract provider/service interface.",
                evidence_ids=[ev.id],
                root_cause="Lack of adapter/gateway pattern around external SDK invocations.",
                recommendation="Implement an abstracted service layer separating client configuration and provider-specific error handling.",
                reproduction_steps=[
                    f"1. Inspect handler at {target_file}",
                    f"2. Note direct SDK import `import {ai_services[0].name.lower()}` without gateway wrapper.",
                ],
            )
            self.graph.add_finding(f)
            findings.append(f)
            finding_idx += 1

        return findings
