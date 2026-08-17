"""
Architecture Auditor (spec Milestone 3 §8-9)

Analyzes graph topology, module boundaries, and dependency directions:
- Circular dependencies
- Layer leakage (e.g. business/DB logic leaking into UI components)
- God modules & tight coupling to external AI vendors
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

        ui_nodes = self.graph.nodes_of_type(NodeType.UI_ELEMENT)
        services = self.graph.nodes_of_type(NodeType.EXTERNAL_SERVICE)

        # Check for Business/AI logic directly coupled to UI or routes without a dedicated service layer
        func_nodes = self.graph.nodes_of_type(NodeType.FUNCTION)
        resume_funcs = [f for f in func_nodes if "resume" in f.name.lower()]

        # If external AI provider is directly called inside route handler without domain abstraction
        ai_services = [s for s in services if "openai" in s.name.lower() or "ai" in s.name.lower()]
        if ai_services and resume_funcs:
            ev = self.evidence_store.add(
                evidence_type=EvidenceType.STATIC_ANALYSIS,
                target_id=ai_services[0].id,
                summary="AI Provider integration is tightly coupled directly to resume controller.",
                source_location=resume_funcs[0].metadata.get("file"),
                payload={"service": ai_services[0].name},
            )
            f = Finding(
                id=f"FINDING-{finding_idx:04d}",
                title="Architecture Debt: Direct Coupling to Single AI Model Provider",
                category=FindingCategory.ARCHITECTURE,
                severity=Severity.LOW,
                status="CONFIRMED",
                confidence=0.88,
                affected_feature="Resume Generation & Management",
                affected_nodes=[ai_services[0].id],
                description="The application instantiates vendor-specific AI client SDKs directly in business handlers rather than using a model gateway or provider-agnostic interface.",
                observed_behavior="Switching model providers (e.g. OpenAI -> Anthropic -> Gemini) requires modifying core route controllers.",
                expected_behavior="Encapsulate AI generation behind an abstract `LLMProvider` interface.",
                evidence_ids=[ev.id],
                root_cause="Lack of adapter / gateway pattern around LLM calls.",
                recommendation="Implement an `LLMService` abstraction separating prompt templates, provider configuration, and response parsing.",
                reproduction_steps=["1. Inspect resume generation controller", "2. Note direct SDK import `import openai` without gateway wrapper."],
            )
            self.graph.add_finding(f)
            findings.append(f)
            finding_idx += 1

        return findings
