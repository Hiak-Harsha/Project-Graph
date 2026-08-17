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
                name="Handler Attached & Valid",
                description="Verify actionable UI control has an active onClick/onSubmit handler or valid href.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-LOADING-STATE",
                target_id=node.id,
                name="Loading State Handled",
                description="Verify component renders loading/spinner/pending feedback during async operations.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=False,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-ERROR-STATE",
                target_id=node.id,
                name="Error State Handled",
                description="Verify component renders user-facing failure toast/alert/message on error.",
                execution_tier=ExecutionTier.STATIC_PATTERN,
                status=CheckStatus.UNVERIFIED,
                required=False,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-CLICK",
                target_id=node.id,
                name="Browser Click Execution",
                description="Execute click in Chromium and observe DOM state transition, navigation or dispatch.",
                execution_tier=ExecutionTier.RUNTIME_BROWSER,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-NETWORK-DISPATCH",
                target_id=node.id,
                name="Network Request Triggered",
                description="Observe network trace on click to verify corresponding backend API dispatch.",
                execution_tier=ExecutionTier.RUNTIME_BROWSER,
                status=CheckStatus.UNVERIFIED,
                required=False,
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
                name="Route Registration Valid",
                description="Verify route is declared and attached to active application router.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-AUTH-DECLARED",
                target_id=node.id,
                name="Authentication Middleware Attached",
                description="Verify route declares required authentication dependencies or access guards.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-BOLA-STATIC",
                target_id=node.id,
                name="BOLA / IDOR Tenancy Guard Static Check",
                description="Verify parameterized endpoints enforce user tenancy scoping in queries.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-HTTP-REACHABLE",
                target_id=node.id,
                name="Dynamic HTTP Endpoint Execution",
                description="Issue real HTTP request against live/test server and capture response code and latency.",
                execution_tier=ExecutionTier.RUNTIME_HTTP,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-BOLA-RUNTIME",
                target_id=node.id,
                name="Multi-User BOLA HTTP Boundary Test",
                description="Execute cross-tenant object access requests as User A against User B resources.",
                execution_tier=ExecutionTier.RUNTIME_HTTP,
                status=CheckStatus.UNVERIFIED,
                required=True,
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
                name="Test Assertion Quality",
                description="Inspect test AST to verify non-trivial assertions (flag empty tests & assert True).",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-EXECUTION",
                target_id=node.id,
                name="Real Test Suite Execution",
                description="Execute test runner inside sandbox and record pass/fail/error status.",
                execution_tier=ExecutionTier.TEST_RUNNER,
                status=CheckStatus.UNVERIFIED,
                required=True,
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
                name="Schema Constraints Declared",
                description="Verify primary keys, non-null constraints, and data types in schema model.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
            AuditCheck(
                id=f"CHECK-{node.id}-SENSITIVE-PROTECT",
                target_id=node.id,
                name="Sensitive Field Protection",
                description="Verify hashed credentials and absence of plaintext sensitive columns.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
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

    # 5. External Services Checks & Tasks
    for node in graph.nodes_of_type(NodeType.EXTERNAL_SERVICE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TIMEOUT",
                target_id=node.id,
                name="External Call Timeout Policy",
                description="Verify client calls specify explicit timeouts and retry/circuit breaker policies.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_EXTERNAL_INTEGRATION",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    # 6. Feature Checks & Tasks
    for node in graph.nodes_of_type(NodeType.FEATURE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TRACEABILITY",
                target_id=node.id,
                name="Feature Traceability to Implementation",
                description="Verify feature traces to active UI elements, API endpoints and DB entities.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
            ),
        ]
        for c in checks:
            graph.add_check(c)

        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_FEATURE_COMPLETENESS",
            target_id=node.id,
            required_checks=[c.name for c in checks],
        )
        graph.add_task(task)
        tasks.append(task)

    return tasks
