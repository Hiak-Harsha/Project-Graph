"""
Phase: GRAPH BUILDER (spec Milestone 1 §19)

Synthesizes cross-system relationships across discovered entities:
Requirement -> Feature -> UIElement -> APIEndpoint -> Service/Function -> DatabaseEntity -> Test
"""
from __future__ import annotations

from packages.project_graph.models import EdgeRelationship, GraphEdge, NodeType
from packages.project_graph.store import ProjectGraph


def build_graph_relationships(graph: ProjectGraph) -> list[GraphEdge]:
    edges: list[GraphEdge] = []

    files = {n.metadata.get("path", n.name): n for n in graph.nodes_of_type(NodeType.FILE)}
    features = graph.nodes_of_type(NodeType.FEATURE)
    requirements = graph.nodes_of_type(NodeType.REQUIREMENT)
    ui_elements = graph.nodes_of_type(NodeType.UI_ELEMENT)
    api_endpoints = graph.nodes_of_type(NodeType.API_ENDPOINT)
    functions = graph.nodes_of_type(NodeType.FUNCTION)
    db_entities = graph.nodes_of_type(NodeType.DATABASE_ENTITY)
    tests = graph.nodes_of_type(NodeType.TEST)
    packages = graph.nodes_of_type(NodeType.PACKAGE)
    services = graph.nodes_of_type(NodeType.EXTERNAL_SERVICE)

    # 1. FILE CONTAINS Function/Class/UIElement/API
    for n in (
        graph.nodes_of_type(NodeType.FUNCTION)
        + graph.nodes_of_type(NodeType.CLASS)
        + graph.nodes_of_type(NodeType.UI_ELEMENT)
        + graph.nodes_of_type(NodeType.API_ENDPOINT)
    ):
        file_path = n.metadata.get("file")
        if file_path and file_path in files:
            e = GraphEdge(
                source=files[file_path].id,
                relationship=EdgeRelationship.CONTAINS,
                target=n.id,
                static_evidence=True,
            )
            graph.add_edge(e)
            edges.append(e)

    # 2. UIElement CALLS / HANDLED_BY Function / API
    for ui in ui_elements:
        handler = ui.metadata.get("handler_name")
        label = ui.metadata.get("label", "").lower()
        if handler:
            # Check if there is a function matching the handler
            for func in functions:
                if func.name.lower() == handler.lower():
                    e = GraphEdge(
                        source=ui.id,
                        relationship=EdgeRelationship.HANDLED_BY,
                        target=func.id,
                        static_evidence=True,
                    )
                    graph.add_edge(e)
                    edges.append(e)

        # Match UI to API endpoints (e.g. Generate Resume button -> /api/resume/generate)
        for api in api_endpoints:
            api_path = api.metadata.get("path", "").lower()
            if any(k in label and k in api_path for k in ["resume", "login", "auth", "graph", "export", "profile"]):
                e = GraphEdge(
                    source=ui.id,
                    relationship=EdgeRelationship.CALLS,
                    target=api.id,
                    static_evidence=True,
                    confidence=0.85,
                )
                graph.add_edge(e)
                edges.append(e)

    # 3. FEATURE IMPLEMENTS Requirement / CONTAINS UI & APIs
    for feat in features:
        feat_name_lower = feat.name.lower()
        # Connect to matching requirements
        for req in requirements:
            req_stmt = req.metadata.get("statement", "").lower()
            if any(k in req_stmt and k in feat_name_lower for k in ["auth", "login", "resume", "graph", "recommend"]):
                e = GraphEdge(
                    source=feat.id,
                    relationship=EdgeRelationship.IMPLEMENTS,
                    target=req.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

        # Connect Feature to UI Elements
        for ui in ui_elements:
            ui_file = ui.metadata.get("file", "").lower()
            ui_label = ui.metadata.get("label", "").lower()
            if any(k in feat_name_lower and (k in ui_file or k in ui_label) for k in ["auth", "login", "resume", "graph"]):
                e = GraphEdge(
                    source=feat.id,
                    relationship=EdgeRelationship.CONTAINS,
                    target=ui.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

        # Connect Feature to API Endpoints
        for api in api_endpoints:
            api_path = api.metadata.get("path", "").lower()
            if any(k in feat_name_lower and k in api_path for k in ["auth", "login", "resume", "graph"]):
                e = GraphEdge(
                    source=feat.id,
                    relationship=EdgeRelationship.CONTAINS,
                    target=api.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

    # 4. API Endpoints READS_FROM / WRITES_TO Database Entities
    for api in api_endpoints:
        api_path = api.metadata.get("path", "").lower()
        for db in db_entities:
            model_name = db.metadata.get("model_name", "").lower()
            if model_name in api_path or (model_name + "s") in api_path:
                rel = EdgeRelationship.WRITES_TO if api.metadata.get("method") in ["POST", "PUT", "PATCH", "DELETE"] else EdgeRelationship.READS_FROM
                e = GraphEdge(
                    source=api.id,
                    relationship=rel,
                    target=db.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

    # 5. TEST TESTED_BY Feature / API / Function
    for test in tests:
        test_name = test.name.lower()
        for feat in features:
            if any(k in test_name and k in feat.name.lower() for k in ["auth", "resume", "graph"]):
                e = GraphEdge(
                    source=feat.id,
                    relationship=EdgeRelationship.TESTED_BY,
                    target=test.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

    # 6. EXTERNAL SERVICES DEPENDS_ON
    for svc in services:
        svc_name_lower = svc.name.lower()
        for feat in features:
            if ("openai" in svc_name_lower or "ai" in svc_name_lower) and "resume" in feat.name.lower():
                e = GraphEdge(
                    source=feat.id,
                    relationship=EdgeRelationship.DEPENDS_ON,
                    target=svc.id,
                    static_evidence=True,
                )
                graph.add_edge(e)
                edges.append(e)

    return edges
