"""
Audit Task & Check Obligation Manifest Generator (spec Milestone 1 §8 / P1)

Generates executable AuditCheck contracts and AuditTasks for every discovered entity.
Enforces strict naming discipline:
- Static AST discovery names reflect static proofs (e.g. 'Handler Reference Discovered').
- Runtime names reflect live execution observations (e.g. 'Browser Click Execution').
"""
from __future__ import annotations

from packages.project_graph.models import (
    AuditCheck,
    AuditTask,
    CheckStatus,
    ExecutionTier,
    NodeType,
)
from packages.project_graph.store import ProjectGraph


def build_audit_task_manifest(graph: ProjectGraph) -> list[AuditTask]:
    tasks: list[AuditTask] = []

    # 1. UI Element Checks & Tasks
    for node in graph.nodes_of_type(NodeType.UI_ELEMENT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-HANDLER",
                target_id=node.id,
                name="Handler Reference Discovered",
                description="Verify actionable UI control has an active onClick/onSubmit handler or valid href.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                success_conditions=["Attached event handler function or valid navigation href found in JSX/TSX AST."],
                failure_conditions=["Actionable control has null, missing, or empty handler."],
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-LOADING-STATE",
                target_id=node.id,
                name="Loading State Reference Discovered",
                description="Verify component references loading/spinner/pending state during async operations.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_PATTERN_ANALYZER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-ERROR-STATE",
                target_id=node.id,
                name="Error Handling Reference Discovered",
                description="Verify component references user-facing failure toast/alert/message on error.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_PATTERN_ANALYZER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-CLICK",
                target_id=node.id,
                name="Browser Click Execution",
                description="Execute click in Chromium sandbox and observe DOM state transition, navigation or dispatch.",
                execution_tier=ExecutionTier.RUNTIME_BROWSER,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="PLAYWRIGHT_SANDBOX_DISPATCH",
                capability_requirements=["CONTAINER", "PLAYWRIGHT"],
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-NETWORK-DISPATCH",
                target_id=node.id,
                name="Network Request Triggered",
                description="Observe network trace on click to verify corresponding backend API dispatch.",
                execution_tier=ExecutionTier.RUNTIME_BROWSER,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="PLAYWRIGHT_NETWORK_HAR",
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_UI_INTERACTION",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 2. API Endpoint Checks & Tasks
    for node in graph.nodes_of_type(NodeType.API_ENDPOINT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-ROUTE-REG",
                target_id=node.id,
                name="Route Registration Discovered",
                description="Verify route is declared and attached to active application router.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-AUTH-DECLARED",
                target_id=node.id,
                name="Authentication Dependency Discovered",
                description="Verify route declares required authentication dependencies or access guards.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-BOLA-STATIC",
                target_id=node.id,
                name="Tenancy Scoping Query Discovered",
                description="Verify parameterized endpoints enforce user tenancy scoping in query filters.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_DATAFLOW",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-HTTP-REACHABLE",
                target_id=node.id,
                name="HTTP Reachability Observed",
                description="Issue real HTTP request against live sandbox server and capture status code and latency.",
                execution_tier=ExecutionTier.RUNTIME_HTTP,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="DOCKER_HTTP_CLIENT",
                capability_requirements=["CONTAINER"],
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-BOLA-RUNTIME",
                target_id=node.id,
                name="Multi-Identity Boundary Observed",
                description="Execute cross-tenant object access requests as User A against User B resources.",
                execution_tier=ExecutionTier.RUNTIME_HTTP,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="DOCKER_HTTP_CLIENT",
                capability_requirements=["CONTAINER", "IDENTITY_FIXTURES"],
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_API_ENDPOINT",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 3. Test Suite Checks & Tasks
    for node in graph.nodes_of_type(NodeType.TEST):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-STRUCTURE",
                target_id=node.id,
                name="Test Assertion Quality Statically Verified",
                description="Verify test suite contains deterministic assertions and avoids trivial 'assert True'.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-EXECUTION",
                target_id=node.id,
                name="Test Suite Container Execution",
                description="Execute discovered test runner in container sandbox and verify pass/fail exit code.",
                execution_tier=ExecutionTier.RUNTIME_TEST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="DOCKER_TEST_RUNNER",
                capability_requirements=["CONTAINER"],
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_TEST_SUITE",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 4. Database Entity Checks & Tasks
    for node in graph.nodes_of_type(NodeType.DATABASE_ENTITY):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-SCHEMA",
                target_id=node.id,
                name="Database Schema Model Discovered",
                description="Verify ORM schema model contains valid primary keys, foreign keys, and field types.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_DATABASE_ENTITY",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 5. External Service Checks & Tasks
    for node in graph.nodes_of_type(NodeType.EXTERNAL_SERVICE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TIMEOUT",
                target_id=node.id,
                name="External Client Timeout Discovered",
                description="Verify external client calls specify bounded timeouts to prevent thread blocking.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_EXTERNAL_SERVICE",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 6. Feature Traceability Checks & Tasks
    for node in graph.nodes_of_type(NodeType.FEATURE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TRACEABILITY",
                target_id=node.id,
                name="Feature Code Traceability Discovered",
                description="Verify advertised feature maps to discovered routes, components, or models.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="GRAPH_TOPOLOGY_TRAVERSAL",
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_FEATURE_TRACEABILITY",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 7. Requirement Traceability Checks & Tasks
    for node in graph.nodes_of_type(NodeType.REQUIREMENT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-IMPLEMENTED",
                target_id=node.id,
                name="Requirement Traceability Discovered",
                description="Verify requirement is implemented by active components and passing checks.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="GRAPH_TOPOLOGY_TRAVERSAL",
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_REQUIREMENT",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    return tasks
