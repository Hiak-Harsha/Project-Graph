# Production Audit Platform — Product and Engineering Specification

## Product promise

Given a pinned repository revision and an approved execution environment, the
platform must reconstruct the system, execute only safe and declared checks,
retain tamper-evident evidence, and explain exactly what is proven, failed,
blocked, unknown, or outside scope. It must never represent discovery, static
inference, a test fixture, or an LLM statement as a runtime fact.

The product is not a generic code-review chatbot. It is an evidence system with
an intelligent audit layer on top.

## Non-negotiable invariants

| ID | Invariant | Enforcement |
|---|---|---|
| P1 | Every discovered entity and applicable check has a terminal or visible waiting state. | Check accounting, required-check gate |
| P2 | A confirmed claim references immutable evidence with provenance and hashes. | Evidence Gatekeeper rejects unsupported claims |
| P3 | Discovery, verification, and interpretation are separate phases. | Typed artifacts and agent contracts |
| P4 | Runtime evidence outranks test, static, and inferred evidence. | Judge evidence hierarchy |
| P5 | Missing capability, credentials, input, or environment is `BLOCKED`/`UNVERIFIED`, never silently passed. | Explicit check lifecycle |
| P6 | No unknown repository executes on the control-plane host. | Ephemeral sandbox, resource and network policy |
| P7 | Secrets are redacted before evidence leaves the sandbox. | Redaction boundary and secret scanning |
| P8 | An audit is reproducible against a repository SHA, environment image, contracts, and tool versions. | Audit manifest and execution provenance |

## Check lifecycle and truth model

`PENDING → RUNNING → PASSED | FAILED | BLOCKED | ERROR | UNVERIFIED | N_A | SKIPPED`

- `PASSED` and `FAILED` require the declared evidence requirements.
- `BLOCKED` means prerequisites were absent or unsafe to satisfy.
- `ERROR` means an attempted execution failed unexpectedly.
- `UNVERIFIED` means no suitable check ran or evidence was insufficient.
- `N_A` means the planner proved the check does not apply.
- `SKIPPED` must record the policy or user decision and never satisfy a required
  production gate by itself.

Each `AuditCheck` must specify execution method, inputs, preconditions,
expected observations, success/failure conditions, timeout, risk class,
destructiveness, and evidence requirements. Entity state is derived from those
checks; it is never hand-written independently.

## Required end-to-end flow

1. Pin repository URL/branch to commit SHA and produce an intake manifest.
2. Build an isolated, ephemeral sandbox; enforce CPU, memory, disk, wall-clock,
   process, filesystem, outbound-network and secret policies.
3. Run deterministic discovery and build an evidence-annotated Project Graph.
4. Generate explicit check obligations and execution contracts.
5. Start target services only inside the sandbox; capture build logs, ports,
   health checks and process exit information.
6. Execute API, browser, identity, database and project-test contracts.
7. Store raw/redacted evidence artifacts and link them to checks and graph edges.
8. Reconcile static and runtime inventories, then run intelligence proposals.
9. Evidence Gatekeeper and Judge resolve only supported claims.
10. Persist the immutable audit bundle and display the release verdict with gaps.

## Product capabilities

### M1 — Discovery and Project Graph

- Repository/commit intake, file inventory, hashes, languages and package managers.
- AST-first parsing for Python, TypeScript/JavaScript (including JSX), then
  framework adapters for React/Next.js, FastAPI, Django, Express, Prisma and
  SQLAlchemy.
- Nodes: files, modules, functions, classes, routes, pages, UI controls, forms,
  inputs, APIs, schemas, database entities/fields/migrations, identities/roles,
  sessions, jobs, queues, events, external endpoints, configuration, tests,
  features, requirements and user flows.
- Edges contain source, relation, target, confidence, discovery method,
  evidence level and evidence IDs. Inferred edges must never masquerade as
  direct static or runtime observations.
- Requirements have provenance: `EXPLICIT`, `DERIVED`, or `INFERRED`.

### M2 — Evidence-backed verification

- API contracts: happy path, invalid/missing/malformed input, auth/role,
  conflict, not-found, timeout and dependency-failure cases where applicable.
- Identity matrix: anonymous, owner, peer tenant, admin, expired/invalid
  credential. BOLA requires provisioned owner and attacker identities plus a
  verified owner-access control; arbitrary tokens are forbidden.
- Browser Lab: render pages at declared routes, inventory DOM, reconcile with
  static UI inventory, execute named user flows, capture screenshots, DOM
  snapshots, console errors, browser trace and network trace.
- Forms: required/invalid/boundary/Unicode/duplicate-submit/loading/success/
  failure/server-validation cases; uploads additionally need MIME, size,
  corrupted file and malicious-name cases.
- Database: migration apply, CRUD, constraints, transactions, ownership,
  cascade behavior and persistence observation in an isolated database.
- Test runner: detect actual framework commands, execute them in sandbox,
  capture output/coverage and assess weak assertions, mocking, isolation and
  error-path coverage.
- External services: distinguish static policy from live verification; lack of
  approved credentials is `BLOCKED`, never `FAILED` or `PASSED`.

### M3 — Intelligence and adversarial review

- Requirement-to-code-to-runtime traceability and negative-space detection.
- Adversarial security/reliability hypotheses, with a separate evidence
  confirmation pass.
- Architecture, dependency, operational-readiness and test-quality analysis.
- Conflict judge that applies the evidence hierarchy and preserves uncertainty.
- Completeness dashboard: discovery, check execution, runtime, evidence,
  requirement and user-flow coverage are separate metrics.

## Agent operating model

The implementation registry is in `packages/orchestration/agent_registry.py`.
The required agents are:

| Agent | Responsibility | May execute code? | May confirm or mutate a verdict? |
|---|---|---:|---:|
| Coordinator | Plans dependencies and schedules bounded work | No | No |
| Discovery | Builds/reconciles deterministic inventory | No | No |
| Contract Planner | Produces explicit, safe execution contracts | No | No |
| Sandbox Supervisor | Starts isolated environments and health checks | Yes | No |
| API Runtime | Executes declared HTTP contracts | Yes | No |
| Browser Flow | Executes Playwright DOM/user-flow contracts | Yes | No |
| Identity Boundary | Provisions test identities and verifies access boundaries | Yes | No |
| Database Lifecycle | Runs migrations and CRUD/constraint contracts | Yes | No |
| Test Quality | Runs the detected project tests and analyzes quality | Yes | No |
| Security Adversary | Proposes exploit hypotheses | No | No |
| Architecture | Proposes architecture/reliability findings | No | No |
| Requirements | Reconciles requirement and implementation evidence | No | No |
| Evidence Gatekeeper | Validates hashes, provenance, redaction and claim support | No | No |
| Judge | Proposes evidence-based verdict | No | No |

An agent returns a typed proposal. It cannot directly mark a check passed,
failed or production-ready. Only deterministic execution plus Evidence Gate
validation can change the canonical audit state. High-risk or destructive
contracts require a human approval policy and run only in disposable fixtures.

## Interfaces and persistence

- REST API: create audit, get audit, graph, checks, evidence artifacts, claims,
  findings, coverage, capability/sandbox status, cancellation and rerun by SHA.
- Dashboard: separate static/runtime evidence, check state, prerequisites,
  redacted artifacts, graph provenance, finding challenge history and cost/time.
- Durable data model: projects, revisions, audit runs, environments, contracts,
  nodes, edges, checks, executions, evidence artifacts, claims, findings,
  approval decisions and append-only event history. Use migrations; never
  drop/recreate an audit database in production.
- Object storage stores raw artifacts; relational storage stores metadata and
  graph edges. Sign evidence hashes and retain retention/redaction policy.

## Delivery roadmap

### Milestone 4 — Sandboxed Runtime Foundation (next)

Create Docker/OCI sandbox workers, dependency install/build/start detection,
health probes, process lifecycle logs and an execution-contract schema. No UI
or API check may be marked runtime-executed until this is present.

The implemented contract schema is illustrated by
`.project-graph/runtime-contract.example.json`. A project opts into execution
by copying it to `runtime-contract.json` and filling in its real, non-secret
start command and health endpoint. The supervisor rejects shell command
strings, invalid ports, unbounded resources and undeclared runtime starts.

`api-contract.example.json` and `browser-contract.example.json` define the
only requests and UI interactions the runtime agents may execute. A contract
must name expected statuses/selectors and observable effects; no route,
payload, selector or identity is inferred at execution time.

### Milestone 5 — Browser Lab and Runtime Reconciliation

Add Playwright image, route inventory, DOM matching, click/form flows, network
and console artifacts, screenshot/trace storage and route/page obligations.

### Milestone 6 — Auth, API and Database Contract Suites

Add fixture provisioning, identity matrix, OpenAPI/framework request contracts,
test DB lifecycle and side-effect cleanup.

### Milestone 7 — Durable control plane

Replace in-memory/latest-audit state and destructive SQLite persistence with
versioned database migrations, queue workers, object storage and audit history.

### Milestone 8 — Intelligence with governance

Add evidence-gated agent proposals, adversarial challenges, human review queues,
evaluation corpus, false-positive tracking and benchmark scorecards.

## Acceptance gates

The platform may claim production-grade auditing only when it can demonstrate:

1. A clean-room sandbox execution of a representative web application.
2. Real browser UI evidence for rendered/clicked controls and observed effects.
3. Real multi-identity authorization evidence with provisioned resources.
4. Real database migration/constraint/CRUD evidence.
5. An immutable audit bundle reproducing all claims against a pinned revision.
6. A benchmark suite measuring recall, precision, evidence validity, coverage,
   false-positive rate and reproducibility across multiple stacks.
