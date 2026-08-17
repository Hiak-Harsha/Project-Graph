# AI Production Engineering Auditor & Project Graph Platform 🚀

[![Production Readiness](https://img.shields.io/badge/Audit%20Readiness-Evidence--Backed-blue.svg)](https://github.com/Hiak-Harsha/Project-Graph)
[![Architecture Invariants](https://img.shields.io/badge/Invariants-P1--P5%20Strict-green.svg)](https://github.com/Hiak-Harsha/Project-Graph)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An autonomous software engineering audit system that reconstructs any software project, understands what it claims to do, verifies what it actually does, and produces an exhaustive, evidence-backed production-readiness assessment without leaving blind spots.

---

## 🌟 The Core Philosophy: Invariants P1–P5

Unlike traditional linting tools or shallow LLM PR reviewers, this platform operates under five strict, mathematically enforced invariants:

- **P1 — Nothing Silently Omitted**: Every discoverable entity (Files, Modules, UI elements/buttons, API routes, DB entities, Features, Requirements, Tests) concludes in `VERIFIED | FAILED | UNVERIFIED | NOT_APPLICABLE`.
- **P2 — Evidence Before Claims**: No finding is valid without an immutable, cryptographic SHA-256 evidence record (Source AST, Runtime DOM mutation, Network trace, DB observation).
- **P3 — Strict Phase Separation**:
  - `M1 DISCOVERY`: *What exists?* (Deterministic AST + Inventory $\to$ Project Graph $\to$ Audit Tasks).
  - `M2 VERIFICATION`: *What actually happens?* (Deterministic execution, DOM interactions, API/Auth tests, Dead control checks).
  - `M3 INTELLIGENCE`: *What does it mean?* (Cross-checking, Missing requirements, Adversarial skepticism, Judge, Completeness proof).
- **P4 — Runtime Truth Beats Assumptions**: Evidence hierarchy: `Runtime Evidence > Integration Tests > Static Source AST > Model Inference`.
- **P5 — Visible Uncertainty**: Untestable surfaces are explicitly flagged as `UNVERIFIED` — never assumed or inflated.

---

## 🏗️ Architecture Overview

```
                      [ GITHUB REPOSITORY / LOCAL CODEBASE ]
                                         │
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │       MILESTONE 1: DISCOVERY ENGINE       │
                   │              "What exists?"               │
                   └─────────────────────┬─────────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │     PROJECT GRAPH     │
                             │  Nodes, Edges & DAG   │
                             └───────────┬───────────┘
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │      MILESTONE 2: VERIFICATION ENGINE     │
                   │          "What actually happens?"         │
                   └─────────────────────┬─────────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │    EVIDENCE VAULT     │
                             │  Immutable SHA-256    │
                             └───────────┬───────────┘
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │      MILESTONE 3: AUDIT INTELLIGENCE      │
                   │           "What does it mean?"            │
                   │                                           │
                   │  • Cross-Check & Missing Requirements     │
                   │  • Adversarial Skepticism Pass            │
                   │  • Judge Engine Conflict Resolution       │
                   │  • P1 Mathematical Completeness Proof     │
                   └─────────────────────┬─────────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │    EXECUTIVE AUDIT    │
                             │    & WEB DASHBOARD    │
                             └───────────────────────┘
```

---

## 📦 Repository Structure

```
Project-Graph/
├── apps/
│   ├── api/
│   │   ├── main.py                     # FastAPI REST API
│   │   └── server.py                   # Zero-dependency HTTP/REST server
│   └── web/
│       ├── index.html                  # Modern Web Dashboard
│       ├── styles.css                  # Dark glassmorphism styling
│       └── app.js                      # Interactive SVG Project Graph & Inspector
├── packages/
│   ├── project_graph/                  # Core Graph Models & SQLite Store
│   │   ├── models.py                   # GraphNode, GraphEdge, AuditTask, Finding
│   │   └── store.py                    # ProjectGraph store & P1 accounting
│   ├── discovery/                      # Milestone 1: Deterministic Parsers
│   │   ├── fingerprint.py              # Stack & infrastructure detector
│   │   ├── file_inventory.py           # SHA-256, LOC, binary flags
│   │   ├── dependency_scan.py          # Package manifest scanner
│   │   ├── code_discovery.py           # Python AST & JS/TS function parsers
│   │   ├── ui_discovery.py             # Buttons, Links, Inputs & handler detector
│   │   ├── api_discovery.py            # Express, FastAPI, Flask route parsers
│   │   ├── database_discovery.py       # Prisma & SQLAlchemy model discovery
│   │   ├── config_discovery.py         # Configs, Env vars, External services
│   │   ├── test_discovery.py           # Test suites & estimated test cases
│   │   ├── feature_discovery.py        # Feature & Requirement clustering
│   │   ├── graph_builder.py            # Cross-system relational edge builder
│   │   └── task_manifest.py            # Deterministic AuditTask manifest generator
│   ├── evidence/                       # Milestone 2: Cryptographic Evidence Vault
│   │   ├── models.py                   # Evidence model + SHA-256 hashing
│   │   └── store.py                    # Immutable evidence store
│   ├── verification/                   # Milestone 2: Deterministic Verifiers
│   │   ├── ui_verifier.py              # Dead button & missing handler verifier
│   │   ├── api_verifier.py             # Endpoint schema & timeout verifier
│   │   ├── auth_verifier.py            # BOLA / IDOR access control verifier
│   │   └── runner.py                   # Task execution orchestrator
│   └── intelligence/                   # Milestone 3: Reasoning & Skepticism
│       ├── system_understanding.py     # Product archetype & workflow synthesis
│       ├── cross_check.py              # Requirement <-> Implementation <-> Runtime
│       ├── missing_requirements.py     # Production requirement discovery
│       ├── architecture_auditor.py     # Modularity & coupling reviewer
│       ├── adversarial_reviewer.py     # Skeptical challenger pass
│       ├── judge.py                    # Evidence hierarchy conflict evaluator
│       ├── completeness_engine.py      # P1 mathematical completeness validator
│       └── verdict_engine.py           # Transparent score & verdict calculator
├── workers/
│   ├── discovery_worker/run.py         # M1 Discovery CLI
│   └── audit_orchestrator.py           # End-to-end audit orchestrator (M1 -> M2 -> M3)
└── tests/
    └── fixtures/sample_career_app/     # Benchmark seed app with planted flaws
```

---

## ⚡ Quick Start

### 1. Launch the Interactive Web Dashboard
Run the built-in, zero-dependency web server:
```powershell
python apps/api/server.py 8080
```
Open **[http://localhost:8080](http://localhost:8080)** in your browser to view:
- Executive Verdict & Readiness Score
- Interactive SVG Project Graph topology
- Filterable Findings with evidence drill-downs
- Audit Tasks Manifest & Execution Checklists
- Immutable Evidence Vault (SHA-256)
- P1 Completeness Matrix

---

### 2. Run the Full Audit via CLI

Audit any local repository:
```powershell
python workers/audit_orchestrator.py --repo tests/fixtures/sample_career_app --out audit_summary.json --db audit_graph.sqlite
```

**Example Output:**
```text
======================================================================
AI PRODUCTION AUDIT PLATFORM — EXECUTIVE AUDIT REPORT
======================================================================
Target Project:     sample_career_app
Product Archetype:  Career Platform & Resume Intelligence Engine
Stack Detected:     FastAPI, React | DB: SQLAlchemy
----------------------------------------------------------------------
EXECUTIVE VERDICT:  NOT PRODUCTION READY (Badge: FAILED)
OVERALL READINESS:  7.3 / 10.0
----------------------------------------------------------------------
DOMAIN SCORES:
  Architecture             [#########-]  9.5/10
  Security                 [###-------]  3.0/10
  Reliability              [##########] 10.0/10
  Testing                  [##########] 10.0/10
  User Experience (UX)     [######----]  6.0/10
  Product Requirements     [#######---]  7.0/10
----------------------------------------------------------------------
AUDIT COVERAGE:     100.0% of discoverable universe resolved
ACCOUNTING CHECK:   68 / 68 entities accounted for (P1 Invariant: PASS)
----------------------------------------------------------------------
CONFIRMED FINDINGS: 2 Critical, 3 High, 1 Medium, 1 Low

TOP PRODUCTION BLOCKERS:
  [CRITICAL] Broken Object-Level Authorization (BOLA / IDOR) on 'GET /api/resume/{id}'
    Evidence: EV-00012
    Impact:   Direct object reference queried without user ID tenancy scoping.
    Fix:      Add user tenancy check in the repository filter or query layer.

  [HIGH] Dead UI Interaction: 'BUTTON: Export Resume' has no execution handler
    Evidence: EV-00001
    Impact:   Clicking element produces no state mutation, request, or download.
    Fix:      Attach a valid handler function or remove the control.
```

---

### 3. Fast Discovery-Only (Milestone 1)

```powershell
python workers/discovery_worker/run.py --repo tests/fixtures/sample_career_app
```

---

## 🧪 Benchmark: Intentionally Flawed Seed Repository

The repository includes a benchmark test app (`tests/fixtures/sample_career_app`) with deliberately planted architectural, security, and UI flaws:

| Planted Flaw | Category | Severity | Detection Result |
|---|---|---|---|
| **Broken Object-Level Authorization (BOLA / IDOR)** on `/api/resume/{id}` | Security | `CRITICAL` | ✅ **CONFIRMED** (`EV-00012`) |
| **Dead "Export Resume" button** with missing handler | Dead Functionality | `HIGH` | ✅ **CONFIRMED** (`EV-00001`) |
| **Dead "Download PDF" link** with dead `href="#"` | Dead Functionality | `HIGH` | ✅ **CONFIRMED** (`EV-00002`) |
| **Missing Rate Limiting** on authentication endpoints | Missing Requirement | `HIGH` | ✅ **CONFIRMED** (`EV-00027`) |
| **Missing File Size & MIME Constraints** on upload route | Missing Requirement | `MEDIUM` | ✅ **CONFIRMED** (`EV-00028`) |
| **Direct AI Vendor Coupling** without Gateway abstraction | Architecture | `LOW` | ✅ **CONFIRMED** (`EV-00029`) |

**Benchmark Score:**
- **Critical Gap Recall:** `100%` (6 / 6 planted flaws identified with reproduction steps).
- **P1 Accounting Invariant:** `PASS` (68 / 68 entities resolved).

---

## 📄 License
MIT License. Developed with Antigravity.
