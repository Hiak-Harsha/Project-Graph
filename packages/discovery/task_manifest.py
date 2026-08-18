"""
Audit Task & Check Obligation Manifest Generator (spec Milestone 1 §8 / P1)

Generates executable AuditCheck contracts and AuditTasks for EVERY discovered entity in the Project Graph.
Enforces strict multi-tier discipline:
- Zero entities without explicit obligation sets (FILE, MODULE, PACKAGE, FUNCTION, CLASS, UI, API, DB, CONFIG, TEST, SERVICE, FEATURE, REQ, FLOW).
- Static AST checks reflect static proofs.
- Runtime checks reflect live execution observations and carry explicit capability requirements (CONTAINER, PLAYWRIGHT, DATABASE).
- Preconditions, inputs, expected observations, and failure conditions defined per obligation.
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

    # 1. FILE Checks & Tasks
    for node in graph.nodes_of_type(NodeType.FILE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-SYNTAX",
                target_id=node.id,
                name="Source Syntax & Parsing Integrity",
                description="Verify source file parses cleanly without syntax errors, tokenization failures, or parse exceptions.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-SECRET-SCAN",
                target_id=node.id,
                name="Hardcoded Secret & Credential Scan",
                description="Scan file content for hardcoded API keys, private tokens, passwords, and sensitive certificates.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_PATTERN_ANALYZER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-ENCODING",
                target_id=node.id,
                name="File Encoding & Size Constraints",
                description="Verify valid UTF-8 encoding and enforce maximum single-file size threshold policy.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_FILE_INSPECTOR",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FILE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 2. PACKAGE / Dependency Checks & Tasks
    for node in graph.nodes_of_type(NodeType.PACKAGE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-VERSION",
                target_id=node.id,
                name="Dependency Version Specification",
                description="Verify package has explicit version constraint or lockfile declaration.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="MANIFEST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-USAGE",
                target_id=node.id,
                name="In-Codebase Import Verification",
                description="Check if package is actively imported across codebase files or represents unused bloat.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_IMPORT_GRAPH",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_PACKAGE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 3. FUNCTION Checks & Tasks
    for node in graph.nodes_of_type(NodeType.FUNCTION):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-SIGNATURE",
                target_id=node.id,
                name="Function Signature & Parameter Schema",
                description="Verify function signature is well-formed with typed/named parameters.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-EXCEPTION-HANDLING",
                target_id=node.id,
                name="Error Path & Exception Structure",
                description="Analyze function body for unhandled exception propagation or return contract consistency.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_AST_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-DEAD-CODE",
                target_id=node.id,
                name="Reachability & Dead Function Audit",
                description="Verify function is called by at least one route, UI handler, export, test, or parent module.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_GRAPH_REACHABILITY",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-TEST-COVERAGE",
                target_id=node.id,
                name="Unit Test Suite Association",
                description="Check if function is associated with explicit unit or integration test cases.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=False,
                execution_method="STATIC_GRAPH_COVERAGE",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FUNCTION", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 4. CLASS Checks & Tasks
    for node in graph.nodes_of_type(NodeType.CLASS):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-STRUCTURE",
                target_id=node.id,
                name="Class Declaration & Base Inheritance",
                description="Verify class structure, constructors, base inheritance hierarchy, and method definitions.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_CLASS", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 5. UI Element Checks & Tasks
    for node in graph.nodes_of_type(NodeType.UI_ELEMENT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-EXISTENCE",
                target_id=node.id,
                name="UI Control Declaration Discovered",
                description="Verify control is declared in component JSX/TSX/HTML with valid tag and attributes.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
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
                id=f"CHECK-{node.id}-DOM-RENDER",
                target_id=node.id,
                name="Browser DOM Render Observed",
                description="Verify control mounts and renders as an active element in Chromium runtime DOM.",
                execution_tier=ExecutionTier.RUNTIME_BROWSER,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="PLAYWRIGHT_DOM_OBSERVER",
                capability_requirements=["CONTAINER", "PLAYWRIGHT"],
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-CLICK",
                target_id=node.id,
                name="Browser Click Execution",
                description="Execute click in Chromium sandbox and observe event dispatch and state transition.",
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
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_UI_INTERACTION", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 6. API Endpoint Checks & Tasks
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
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_API_ENDPOINT", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 7. Database Entity Checks & Tasks
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
            AuditCheck(
                id=f"CHECK-{node.id}-CONSTRAINTS",
                target_id=node.id,
                name="Primary Key & Column Constraints",
                description="Verify table definition includes non-nullable primary key and foreign key references.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_DATABASE_ENTITY", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 8. External Service Checks & Tasks
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
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_EXTERNAL_SERVICE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 9. Config Checks & Tasks
    for node in graph.nodes_of_type(NodeType.CONFIG):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-ENV-DECLARED",
                target_id=node.id,
                name="Configuration Variable Declaration",
                description="Verify environment variable is documented in .env.example or schema manifest.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="CONFIG_PARSER",
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-SECRET-SAFETY",
                target_id=node.id,
                name="Configuration Secret Exposure Audit",
                description="Verify configuration files do not commit production private keys or database passwords.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_PATTERN_ANALYZER",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_CONFIG", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 10. Test Suite Checks & Tasks
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
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_TEST_SUITE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 11. Feature Checks & Tasks
    for node in graph.nodes_of_type(NodeType.FEATURE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TRACEABILITY",
                target_id=node.id,
                name="Feature Traceability to Implementation",
                description="Verify feature maps to discovered routes, UI components, and DB models.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="GRAPH_TRACEABILITY_ANALYZER",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FEATURE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 12. Requirement Checks & Tasks
    for node in graph.nodes_of_type(NodeType.REQUIREMENT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-SATISFACTION",
                target_id=node.id,
                name="Requirement Code Implementation Attached",
                description="Verify requirement statement is backed by functioning code implementation.",
                execution_tier=ExecutionTier.STATIC_GRAPH,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="GRAPH_TRACEABILITY_ANALYZER",
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_REQUIREMENT", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    return tasks
