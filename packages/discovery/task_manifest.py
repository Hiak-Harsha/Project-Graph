"""
Audit Task & Check Obligation Manifest Generator (spec Milestone 1 §8 / P1)

Generates executable AuditCheck contracts and AuditTasks for EVERY entity in the Audit Universe.
Enforces that 100% of generated checks carry fully specified execution contracts:
- execution_method
- preconditions
- inputs
- expected_observations
- success_conditions
- failure_conditions
- evidence_requirements
- risk_level
- destructive
- timeout
"""
from __future__ import annotations

from packages.project_graph.models import (
    AuditCheck,
    AuditTask,
    CheckStatus,
    EvidenceCapability,
    ExecutionTier,
    NodeType,
)
from packages.project_graph.store import ProjectGraph


def build_audit_task_manifest(graph: ProjectGraph) -> list[AuditTask]:
    tasks: list[AuditTask] = []

    # 1. FILE Checks
    for node in graph.nodes_of_type(NodeType.FILE):
        rel_path = node.metadata.get("path", node.name)
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
                preconditions=["Source file exists on filesystem", "File is readable as UTF-8"],
                inputs={"file_path": rel_path},
                expected_observations=["Valid AST tree produced with 0 syntax errors or tokenization failures"],
                success_conditions=["File parses completely without SyntaxError or parse tree disruption"],
                failure_conditions=["SyntaxError raised during parsing", "Unbalanced token stack or corrupted syntax"],
                evidence_requirements=["STATIC_AST_PARSE_TREE", "SHA256_FILE_HASH"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["Source file content available"],
                inputs={"file_path": rel_path, "pattern_suite": "HIGH_ENTROPY_CREDENTIALS"},
                expected_observations=["0 hardcoded secrets or production private credentials matched in code"],
                success_conditions=["Zero matches for hardcoded private keys or production credentials"],
                failure_conditions=["Found raw API key, bearer token, RSA key, or hardcoded password in source"],
                evidence_requirements=["SECURITY_SCAN_RESULT"],
                timeout=15,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Raw bytes readable"],
                inputs={"file_path": rel_path, "max_size_bytes": 10485760},
                expected_observations=["UTF-8 valid decoding", "File size within bounded limit"],
                success_conditions=["File decodes as valid UTF-8 with size <= 10MB"],
                failure_conditions=["Encoding error on decode or file size exceeds threshold"],
                evidence_requirements=["FILE_METADATA_RECORD"],
                timeout=5,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FILE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 2. PACKAGE Checks
    for node in graph.nodes_of_type(NodeType.PACKAGE):
        pkg_name = node.metadata.get("package_name", node.name)
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
                preconditions=["Manifest file (package.json/requirements.txt/pyproject.toml) present"],
                inputs={"package_name": pkg_name, "manifest": node.metadata.get("source_file")},
                expected_observations=["Explicit semantic version range or pinned hash declaration"],
                success_conditions=["Version constraint explicitly defined in manifest"],
                failure_conditions=["Unpinned wildcard dependency in production scope"],
                evidence_requirements=["DEPENDENCY_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["Source file import graph constructed"],
                inputs={"package_name": pkg_name},
                expected_observations=["At least one module imports this package or it is an active CLI/runtime tooling dependency"],
                success_conditions=["Package symbol found in project import statements"],
                failure_conditions=["Package declared in dependencies but never imported anywhere in codebase"],
                evidence_requirements=["IMPORT_GRAPH_EDGE"],
                timeout=15,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_PACKAGE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 3. FUNCTION Checks
    for node in graph.nodes_of_type(NodeType.FUNCTION):
        func_file = node.metadata.get("file", "")
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
                preconditions=["Source AST tree generated"],
                inputs={"function_name": node.name, "file": func_file},
                expected_observations=["Parameter count matches AST declaration with deterministic args"],
                success_conditions=["Function arguments list and name cleanly parsed"],
                failure_conditions=["Malformed argument list or signature parse failure"],
                evidence_requirements=["AST_SYMBOL_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["Function AST body parsed"],
                inputs={"function_name": node.name, "file": func_file},
                expected_observations=["Deterministic return statements or typed exception propagation"],
                success_conditions=["Function defines return paths or explicit raises"],
                failure_conditions=["Unhandled broad except or swallow without logging"],
                evidence_requirements=["EXCEPTION_GRAPH_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Global relationship call-graph built"],
                inputs={"function_name": node.name, "file": func_file},
                expected_observations=["Inbound caller edge from route, component, test, or module export"],
                success_conditions=["Function has incoming graph edge or export decorator"],
                failure_conditions=["Function is unreachable, uncalled, and unexported (dead code)"],
                evidence_requirements=["GRAPH_REACHABILITY_TRACE"],
                timeout=15,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Test relationship edges mapped"],
                inputs={"function_name": node.name, "file": func_file},
                expected_observations=["Inbound edge from TEST node targeting this function"],
                success_conditions=["Targeted test suite found in graph"],
                failure_conditions=["Function lacks test coverage in discovered suites"],
                evidence_requirements=["TEST_ASSOCIATION_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FUNCTION", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 4. CLASS Checks
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
                preconditions=["Class AST node extracted"],
                inputs={"class_name": node.name, "file": node.metadata.get("file")},
                expected_observations=["Valid class definition with constructor and method table"],
                success_conditions=["Class hierarchy and methods parsed cleanly"],
                failure_conditions=["Inheritance cycle or malformed class body"],
                evidence_requirements=["CLASS_HIERARCHY_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_CLASS", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 5. UI Element Checks
    for node in graph.nodes_of_type(NodeType.UI_ELEMENT):
        u_file = node.metadata.get("file", "")
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
                preconditions=["Component file parsed"],
                inputs={"element_name": node.name, "file": u_file},
                expected_observations=["Valid interactive element tag in render tree"],
                success_conditions=["Element AST node found in component body"],
                failure_conditions=["Missing or unparseable UI element"],
                evidence_requirements=["UI_AST_ELEMENT"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["UI control node discovered"],
                inputs={"element_id": node.id, "file": u_file},
                expected_observations=["Attached event handler function or valid navigation href found in JSX/TSX AST"],
                success_conditions=["Actionable control has valid handler binding or navigation destination"],
                failure_conditions=["Actionable button or link has empty, null, or '#' handler"],
                evidence_requirements=["UI_HANDLER_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Container sandbox healthy", "Application frontend mounted"],
                inputs={"element_label": node.metadata.get("label"), "element_type": node.metadata.get("element_type")},
                expected_observations=["Element selector located in Chromium DOM with visible bounding box"],
                success_conditions=["Element is attached to live DOM tree and visible"],
                failure_conditions=["Element selector not found in live runtime DOM"],
                evidence_requirements=["PLAYWRIGHT_DOM_SNAPSHOT"],
                timeout=30,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L4_RUNTIME_OBSERVED,
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
                preconditions=["Element visible in live browser"],
                inputs={"element_id": node.id, "action": "CLICK"},
                expected_observations=["Click event triggers state change, network dispatch, or navigation"],
                success_conditions=["DOM event successfully dispatched without uncaught browser exceptions"],
                failure_conditions=["Click throws uncaught JS error or crashes renderer"],
                evidence_requirements=["BROWSER_EVENT_LOG", "NETWORK_HAR"],
                timeout=30,
                risk_level="INTERACTIVE",
                destructive=False,
                capability_level=EvidenceCapability.L4_RUNTIME_OBSERVED,
                capability_requirements=["CONTAINER", "PLAYWRIGHT"],
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_UI_INTERACTION", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 6. API Endpoint Checks
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
                preconditions=["Router AST parsed"],
                inputs={"route_name": node.name, "http_method": node.metadata.get("http_method")},
                expected_observations=["Route decorator or router registration attaches handler"],
                success_conditions=["Route declared with valid path and HTTP method"],
                failure_conditions=["Route declaration missing HTTP method or handler function"],
                evidence_requirements=["ROUTE_REGISTRATION_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["Endpoint AST parameters extracted"],
                inputs={"route_name": node.name},
                expected_observations=["Route includes auth guard, Depends(get_current_user), or middleware check"],
                success_conditions=["Authentication dependency declared on sensitive endpoint"],
                failure_conditions=["Protected endpoint lacks authentication dependency"],
                evidence_requirements=["AUTH_DEPENDENCY_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Route handler AST and query dataflow mapped"],
                inputs={"route_name": node.name, "path_params": node.metadata.get("path_params")},
                expected_observations=["Database queries filter by both resource_id AND user_id / owner_id"],
                success_conditions=["Query filter enforces user_id tenancy constraint"],
                failure_conditions=["Parameterized resource query lacks user ownership filter (BOLA vulnerability)"],
                evidence_requirements=["BOLA_STATIC_PROOF"],
                timeout=15,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Sandbox container running and healthy on target port"],
                inputs={"url": node.metadata.get("path"), "method": node.metadata.get("http_method", "GET")},
                expected_observations=["HTTP response with valid status code (200, 401, 403, 404, 422) and latency < 2000ms"],
                success_conditions=["Server responds to HTTP request without 500 internal server error"],
                failure_conditions=["Connection refused, timeout, or uncaught server 500 crash"],
                evidence_requirements=["HTTP_RESPONSE_RECORD"],
                timeout=20,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L4_RUNTIME_OBSERVED,
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
                preconditions=["Multi-user identity fixtures provisioned in database"],
                inputs={"attacker_identity": "USER_B", "target_resource_owner": "USER_A", "endpoint": node.metadata.get("path")},
                expected_observations=["Server rejects unauthorized cross-tenant access with 403 Forbidden or 404 Not Found"],
                success_conditions=["Cross-tenant request denied with 403/404"],
                failure_conditions=["Server returns 200 OK with User A's private data to User B"],
                evidence_requirements=["AUTH_BOUNDARY_TEST"],
                timeout=25,
                risk_level="SECURITY_AUDIT",
                destructive=False,
                capability_level=EvidenceCapability.L6_RUNTIME_ADVERSARIAL_VERIFIED,
                capability_requirements=["CONTAINER", "IDENTITY_FIXTURES"],
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_API_ENDPOINT", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 7. Database Entity & Database Field Checks
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
                preconditions=["Schema/model file parsed"],
                inputs={"model_name": node.name, "fields": node.metadata.get("fields")},
                expected_observations=["Valid ORM model with primary key and non-empty field definitions"],
                success_conditions=["Model definition parsed with typed columns"],
                failure_conditions=["Missing primary key or invalid model definition"],
                evidence_requirements=["DATABASE_SCHEMA_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
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
                preconditions=["Model fields table populated"],
                inputs={"table_name": node.metadata.get("table_name")},
                expected_observations=["At least one primary key field defined"],
                success_conditions=["Primary key constraint present"],
                failure_conditions=["Table defined without primary key"],
                evidence_requirements=["CONSTRAINT_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_DATABASE_ENTITY", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    for node in graph.nodes_of_type(NodeType.DATABASE_FIELD):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-TYPE-INTEGRITY",
                target_id=node.id,
                name="Database Field Type Integrity",
                description="Verify field data type matches standard database types (INTEGER, VARCHAR, BOOLEAN, DATETIME).",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                preconditions=["Field metadata extracted"],
                inputs={"field_name": node.name, "type": node.metadata.get("data_type")},
                expected_observations=["Valid data type assigned"],
                success_conditions=["Field data type is standard and typed"],
                failure_conditions=["Undefined or corrupted column data type"],
                evidence_requirements=["FIELD_TYPE_RECORD"],
                timeout=5,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_DATABASE_FIELD", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 8. Forms & Inputs Checks
    for node in graph.nodes_of_type(NodeType.FORM):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-SUBMIT-BINDING",
                target_id=node.id,
                name="Form Submission Handler Binding",
                description="Verify form has active onSubmit handler or valid action endpoint.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                preconditions=["Form AST node parsed"],
                inputs={"form_name": node.name},
                expected_observations=["onSubmit handler function bound to form"],
                success_conditions=["Form has handler function"],
                failure_conditions=["Form submission lacks action or handler"],
                evidence_requirements=["FORM_BINDING_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FORM", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    for node in graph.nodes_of_type(NodeType.INPUT):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-FIELD-NAME",
                target_id=node.id,
                name="Input Field Name & Form Semantics",
                description="Verify input control has descriptive name attribute or placeholder for accessibility.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                preconditions=["Input control parsed"],
                inputs={"field_name": node.metadata.get("field_name")},
                expected_observations=["Input specifies name, type, and placeholder/aria label"],
                success_conditions=["Input is accessible with identifier or placeholder"],
                failure_conditions=["Anonymous unlabelled input control"],
                evidence_requirements=["INPUT_SEMANTICS_RECORD"],
                timeout=5,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_INPUT", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 9. Pages & Routes Checks
    for node in graph.nodes_of_type(NodeType.PAGE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-MOUNT",
                target_id=node.id,
                name="Page Component Mount & Export",
                description="Verify page file exports a valid default React/Vue component.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                preconditions=["Page file parsed"],
                inputs={"page_name": node.name, "file": node.metadata.get("file")},
                expected_observations=["Default export component present in page file"],
                success_conditions=["Page exports valid root component"],
                failure_conditions=["Page file lacks default component export"],
                evidence_requirements=["PAGE_EXPORT_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_PAGE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    for node in graph.nodes_of_type(NodeType.ROUTE):
        checks = [
            AuditCheck(
                id=f"CHECK-{node.id}-ATTACHMENT",
                target_id=node.id,
                name="Client Route Path Attachment",
                description="Verify route path is attached to router hierarchy.",
                execution_tier=ExecutionTier.STATIC_AST,
                status=CheckStatus.UNVERIFIED,
                required=True,
                execution_method="STATIC_AST_PARSER",
                preconditions=["Router declaration parsed"],
                inputs={"path": node.metadata.get("path")},
                expected_observations=["Route path string parsed with attached element"],
                success_conditions=["Route path string valid"],
                failure_conditions=["Invalid route path string"],
                evidence_requirements=["ROUTE_RECORD"],
                timeout=5,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_ROUTE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

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
                preconditions=["External service client call parsed"],
                inputs={"service_name": node.name},
                expected_observations=["Bounded timeout configured on client request"],
                success_conditions=["Client enforces timeout parameter"],
                failure_conditions=["Unbounded infinite client timeout"],
                evidence_requirements=["TIMEOUT_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_EXTERNAL_SERVICE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    # 10. Configs, Tests, Features, Requirements
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
                preconditions=["Config files scanned"],
                inputs={"variable_name": node.name},
                expected_observations=["Variable declaration parsed"],
                success_conditions=["Config variable parsed"],
                failure_conditions=["Undefined config variable"],
                evidence_requirements=["CONFIG_RECORD"],
                timeout=5,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L1_STATIC_DISCOVERY,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_CONFIG", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

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
                preconditions=["Test file parsed"],
                inputs={"test_suite": node.name},
                expected_observations=["Test functions contain meaningful comparisons and assertions"],
                success_conditions=["Zero trivial assert True passes without real verification"],
                failure_conditions=["Found trivial dummy assertions ('assert True', 'assert 1==1')"],
                evidence_requirements=["TEST_AST_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
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
                preconditions=["Container sandbox healthy"],
                inputs={"test_suite": node.name},
                expected_observations=["Test suite executes inside container with exit code 0"],
                success_conditions=["Tests pass with 0 failures"],
                failure_conditions=["Test failure or test runner execution crash"],
                evidence_requirements=["TEST_EXECUTION_LOG"],
                timeout=60,
                risk_level="SANDBOX_EXECUTION",
                destructive=False,
                capability_level=EvidenceCapability.L3_TEST_OBSERVED,
                capability_requirements=["CONTAINER"],
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_TEST_SUITE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

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
                preconditions=["Graph relationships connected"],
                inputs={"feature_name": node.name},
                expected_observations=["Feature has outgoing CONTAINS/IMPLEMENTS edges to code entities"],
                success_conditions=["Feature backed by code implementation"],
                failure_conditions=["Advertised feature has 0 backing routes, UI components, or logic"],
                evidence_requirements=["FEATURE_TRACEABILITY_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_FEATURE", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

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
                preconditions=["Requirement edges mapped"],
                inputs={"requirement_name": node.name},
                expected_observations=["Implementing code entity verified without critical defects"],
                success_conditions=["Requirement implemented and verified"],
                failure_conditions=["Requirement lacks code implementation or failed audit checks"],
                evidence_requirements=["REQUIREMENT_TRACEABILITY_RECORD"],
                timeout=10,
                risk_level="READ_ONLY",
                destructive=False,
                capability_level=EvidenceCapability.L2_STATIC_ANALYSIS,
            ),
        ]
        for c in checks:
            graph.add_check(c)
        task = AuditTask(id=f"TASK-{node.id}", task_type="VERIFY_REQUIREMENT", target_id=node.id, required_checks=[c.name for c in checks])
        graph.add_task(task)
        tasks.append(task)

    return tasks
