"""
Phase: AUDIT TASK MANIFEST (spec Milestone 1 §20 / P3)

"The platform tracks every checkbox programmatically. Not literally relying on an LLM."
Generates deterministic AuditTask DAGs with dependency relationships.
"""
from __future__ import annotations

from packages.project_graph.models import AuditTask, NodeType
from packages.project_graph.store import ProjectGraph

UI_CHECKS = [
    "element_rendered_in_dom",
    "element_visible_and_interactive",
    "handler_attached_and_valid",
    "click_executes_expected_action",
    "network_request_triggered",
    "loading_state_rendered",
    "success_state_handled",
    "failure_state_handled",
    "duplicate_click_throttling",
    "authorization_enforced",
]

API_CHECKS = [
    "endpoint_reachable",
    "authentication_enforced",
    "broken_object_level_authorization_tested",
    "input_validation_enforced",
    "success_response_structure_valid",
    "error_response_structure_valid",
    "timeout_and_failure_resilience",
]

DB_CHECKS = [
    "schema_constraints_enforced",
    "foreign_key_referential_integrity",
    "sensitive_data_protection",
    "index_coverage_on_queried_fields",
]

FEATURE_CHECKS = [
    "feature_end_to_end_operable",
    "requirements_traceability_verified",
    "error_and_edge_case_handling_verified",
    "automated_test_coverage_sufficient",
]

EXTERNAL_SERVICE_CHECKS = [
    "credentials_securely_configured",
    "network_timeout_and_fallback_handled",
    "retry_and_rate_limit_mitigation",
]


def build_audit_task_manifest(graph: ProjectGraph) -> list[AuditTask]:
    tasks: list[AuditTask] = []

    # 1. UI Element Tasks
    for node in graph.nodes_of_type(NodeType.UI_ELEMENT):
        deps = []
        # If UI element belongs to a page or feature, resolve dependencies
        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_UI_INTERACTION",
            target_id=node.id,
            required_checks=list(UI_CHECKS),
            dependencies=deps,
        )
        graph.add_task(task)
        tasks.append(task)

    # 2. API Endpoint Tasks
    for node in graph.nodes_of_type(NodeType.API_ENDPOINT):
        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_API_ENDPOINT",
            target_id=node.id,
            required_checks=list(API_CHECKS),
        )
        graph.add_task(task)
        tasks.append(task)

    # 3. Database Entity Tasks
    for node in graph.nodes_of_type(NodeType.DATABASE_ENTITY):
        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_DATABASE_ENTITY",
            target_id=node.id,
            required_checks=list(DB_CHECKS),
        )
        graph.add_task(task)
        tasks.append(task)

    # 4. External Services Tasks
    for node in graph.nodes_of_type(NodeType.EXTERNAL_SERVICE):
        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_EXTERNAL_INTEGRATION",
            target_id=node.id,
            required_checks=list(EXTERNAL_SERVICE_CHECKS),
        )
        graph.add_task(task)
        tasks.append(task)

    # 5. High-Level Feature Tasks
    for node in graph.nodes_of_type(NodeType.FEATURE):
        task = AuditTask(
            id=f"TASK-{node.id}",
            task_type="VERIFY_FEATURE_COMPLETENESS",
            target_id=node.id,
            required_checks=list(FEATURE_CHECKS),
        )
        graph.add_task(task)
        tasks.append(task)

    return tasks
