"""
System Understanding Engine (spec Milestone 3 §3)

Analyzes the Project Graph and dependencies to synthesize:
- Product identity and problem solved
- User personas and roles
- Core end-to-end user workflows
"""
from __future__ import annotations

from packages.project_graph.models import NodeType
from packages.project_graph.store import ProjectGraph


class SystemUnderstandingEngine:
    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def synthesize(self) -> dict:
        features = [n.name for n in self.graph.nodes_of_type(NodeType.FEATURE)]
        apis = [n.name for n in self.graph.nodes_of_type(NodeType.API_ENDPOINT)]
        db_models = [n.name for n in self.graph.nodes_of_type(NodeType.DATABASE_ENTITY)]
        services = [n.name for n in self.graph.nodes_of_type(NodeType.EXTERNAL_SERVICE)]
        requirements = [n.metadata.get("statement", n.name) for n in self.graph.nodes_of_type(NodeType.REQUIREMENT)]

        # Determine product archetype
        archetype = "Web Application"
        if any("resume" in f.lower() or "career" in f.lower() for f in features):
            archetype = "Career Platform & Resume Intelligence Engine"
        elif any("ecommerce" in f.lower() or "cart" in f.lower() for f in features):
            archetype = "E-Commerce Platform"

        workflows = []
        if any("auth" in f.lower() or "login" in f.lower() for f in features):
            workflows.append("User Authentication & Session Management (Register, Login, Token Issuance)")
        if any("resume" in f.lower() for f in features):
            workflows.append("Resume Generation & Customization Workflow (Input data -> AI Generation -> DB Storage -> Export)")
        if any("graph" in f.lower() for f in features):
            workflows.append("Career Graph Exploration & Skill Mapping")

        return {
            "product_archetype": archetype,
            "core_features": features,
            "explicit_requirements": requirements,
            "detected_services": services,
            "database_models": db_models,
            "total_endpoints": len(apis),
            "primary_workflows": workflows,
        }
