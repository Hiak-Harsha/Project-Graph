"""The bounded agent model for the Production Audit Platform.

Agents are planners and analysts, never an authority to alter an audit result.
They return proposals.  Deterministic executors create evidence, the evidence
gate validates the proposal, and only then can the graph be updated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AgentPhase(str, Enum):
    DISCOVERY = "DISCOVERY"
    VERIFICATION = "VERIFICATION"
    INTELLIGENCE = "INTELLIGENCE"
    GOVERNANCE = "GOVERNANCE"


class AgentOutput(str, Enum):
    INVENTORY = "INVENTORY"
    EXECUTION_PLAN = "EXECUTION_PLAN"
    OBSERVATION_PROPOSAL = "OBSERVATION_PROPOSAL"
    FINDING_PROPOSAL = "FINDING_PROPOSAL"
    VERDICT_PROPOSAL = "VERDICT_PROPOSAL"


@dataclass(frozen=True)
class AgentDefinition:
    id: str
    name: str
    phase: AgentPhase
    purpose: str
    output: AgentOutput
    allowed_evidence: tuple[str, ...]
    may_execute_code: bool = False
    may_mutate_graph: bool = False
    required_inputs: tuple[str, ...] = ()
    handoff_to: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "name": self.name, "phase": self.phase.value,
            "purpose": self.purpose, "output": self.output.value,
            "allowed_evidence": list(self.allowed_evidence), "may_execute_code": self.may_execute_code,
            "may_mutate_graph": self.may_mutate_graph, "required_inputs": list(self.required_inputs),
            "handoff_to": list(self.handoff_to),
        }


@dataclass
class AgentProposal:
    agent_id: str
    output: AgentOutput
    target_ids: list[str]
    summary: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    requires_human_review: bool = False

    def is_evidence_backed(self) -> bool:
        """Only direct observations may be confirmed without human review."""
        return bool(self.evidence_ids) and 0.0 <= self.confidence <= 1.0


class AgentRegistry:
    """Static registry.  It exposes the product's agent boundaries to workers/UI."""

    def __init__(self) -> None:
        self._agents = {agent.id: agent for agent in self._default_agents()}

    def get(self, agent_id: str) -> AgentDefinition:
        return self._agents[agent_id]

    def all(self) -> list[AgentDefinition]:
        return list(self._agents.values())

    def for_phase(self, phase: AgentPhase) -> list[AgentDefinition]:
        return [agent for agent in self._agents.values() if agent.phase == phase]

    def validate_proposal(self, proposal: AgentProposal) -> tuple[bool, str]:
        agent = self._agents.get(proposal.agent_id)
        if not agent:
            return False, "Unknown agent."
        if proposal.output != agent.output:
            return False, "Agent emitted an output outside its declared contract."
        if not proposal.target_ids:
            return False, "Proposal has no graph target."
        if proposal.output in (AgentOutput.OBSERVATION_PROPOSAL, AgentOutput.FINDING_PROPOSAL) and not proposal.is_evidence_backed():
            return False, "Observation or finding proposal lacks evidence IDs or a valid confidence."
        return True, "Proposal satisfies the agent contract; evidence gate review is still required."

    @staticmethod
    def _default_agents() -> tuple[AgentDefinition, ...]:
        return (
            AgentDefinition("AGENT-COORDINATOR", "Audit Coordinator", AgentPhase.GOVERNANCE,
                "Builds dependency-aware plans and schedules bounded work; never writes verdicts.", AgentOutput.EXECUTION_PLAN,
                ("MANIFEST", "CAPABILITY_REPORT"), required_inputs=("project_graph", "audit_checks"), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-DISCOVERY", "Repository Discovery Agent", AgentPhase.DISCOVERY,
                "Reconciles deterministic parsers and proposes missing inventory coverage.", AgentOutput.INVENTORY,
                ("FILE_HASH", "AST", "PACKAGE_MANIFEST"), required_inputs=("repository_snapshot",), handoff_to=("AGENT-CONTRACT-PLANNER",)),
            AgentDefinition("AGENT-CONTRACT-PLANNER", "Verification Contract Planner", AgentPhase.DISCOVERY,
                "Maps discovered targets to explicit, safe execution contracts and preconditions.", AgentOutput.EXECUTION_PLAN,
                ("PROJECT_GRAPH", "ROUTE_SCHEMA", "UI_INVENTORY"), required_inputs=("project_graph",), handoff_to=("AGENT-SANDBOX", "AGENT-EVIDENCE-GATE")),
            AgentDefinition("AGENT-SANDBOX", "Sandbox Supervisor", AgentPhase.VERIFICATION,
                "Boots isolated workers, enforces limits, starts targets and records environment provenance.", AgentOutput.OBSERVATION_PROPOSAL,
                ("SANDBOX_LOG", "PROCESS_EXIT", "HEALTH_CHECK"), may_execute_code=True, required_inputs=("execution_contract",), handoff_to=("AGENT-API-RUNTIME", "AGENT-BROWSER", "AGENT-DB-RUNTIME")),
            AgentDefinition("AGENT-API-RUNTIME", "API Runtime Agent", AgentPhase.VERIFICATION,
                "Executes declared HTTP contracts and records request/response evidence without guessing inputs.", AgentOutput.OBSERVATION_PROPOSAL,
                ("API_RESPONSE", "NETWORK_TRACE"), may_execute_code=True, required_inputs=("api_contract", "healthy_target"), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-BROWSER", "Browser Flow Agent", AgentPhase.VERIFICATION,
                "Executes declared UI flows with Playwright and captures DOM, screenshots, console and network traces.", AgentOutput.OBSERVATION_PROPOSAL,
                ("DOM_INTERACTION", "SCREENSHOT", "NETWORK_TRACE", "BROWSER_TRACE"), may_execute_code=True, required_inputs=("ui_contract", "healthy_target"), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-AUTH", "Identity Boundary Agent", AgentPhase.VERIFICATION,
                "Provisions declared test identities/resources and performs owner-versus-attacker boundaries.", AgentOutput.OBSERVATION_PROPOSAL,
                ("AUTH_BOUNDARY_TEST", "PROVISIONING_LOG"), may_execute_code=True, required_inputs=("identity_fixture", "healthy_target"), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-DB-RUNTIME", "Database Lifecycle Agent", AgentPhase.VERIFICATION,
                "Applies migrations and executes declared CRUD, constraint, transaction and ownership checks.", AgentOutput.OBSERVATION_PROPOSAL,
                ("DATABASE_OBSERVATION", "MIGRATION_LOG", "QUERY_TRACE"), may_execute_code=True, required_inputs=("database_contract",), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-TEST-QUALITY", "Test Quality Agent", AgentPhase.VERIFICATION,
                "Runs the detected project test command and assesses assertion strength and isolation.", AgentOutput.OBSERVATION_PROPOSAL,
                ("TEST_EXECUTION", "COVERAGE_REPORT"), may_execute_code=True, required_inputs=("test_runner_contract",), handoff_to=("AGENT-EVIDENCE-GATE",)),
            AgentDefinition("AGENT-SECURITY", "Adversarial Security Agent", AgentPhase.INTELLIGENCE,
                "Proposes attack hypotheses from graph and verified observations; cannot confirm findings itself.", AgentOutput.FINDING_PROPOSAL,
                ("STATIC_AST_MATCH", "AUTH_BOUNDARY_TEST", "NETWORK_TRACE"), required_inputs=("project_graph", "evidence"), handoff_to=("AGENT-EVIDENCE-GATE", "AGENT-JUDGE")),
            AgentDefinition("AGENT-ARCHITECTURE", "Architecture Agent", AgentPhase.INTELLIGENCE,
                "Finds coupling, boundary and reliability risks from evidence-annotated graph topology.", AgentOutput.FINDING_PROPOSAL,
                ("PROJECT_GRAPH", "STATIC_AST_MATCH", "RUNTIME_TRACE"), required_inputs=("project_graph",), handoff_to=("AGENT-EVIDENCE-GATE", "AGENT-JUDGE")),
            AgentDefinition("AGENT-REQUIREMENTS", "Requirements & Negative-Space Agent", AgentPhase.INTELLIGENCE,
                "Reconciles stated requirements with discovered and executed capability; labels inference clearly.", AgentOutput.FINDING_PROPOSAL,
                ("README", "PROJECT_GRAPH", "RUNTIME_TRACE"), required_inputs=("requirements", "project_graph"), handoff_to=("AGENT-EVIDENCE-GATE", "AGENT-JUDGE")),
            AgentDefinition("AGENT-EVIDENCE-GATE", "Evidence Gatekeeper", AgentPhase.GOVERNANCE,
                "Rejects evidence-free claims, validates provenance, redaction, hashes and claim status.", AgentOutput.OBSERVATION_PROPOSAL,
                ("ALL"), required_inputs=("proposal", "evidence"), handoff_to=("AGENT-JUDGE",)),
            AgentDefinition("AGENT-JUDGE", "Verdict Judge", AgentPhase.GOVERNANCE,
                "Resolves supported conflicts and proposes the release verdict from verified check state.", AgentOutput.VERDICT_PROPOSAL,
                ("EVIDENCE_CLAIM", "CHECK_STATUS", "COMPLETENESS_REPORT"), required_inputs=("findings", "evidence", "completeness")),
        )
