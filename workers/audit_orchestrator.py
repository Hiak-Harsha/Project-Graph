"""
Audit Orchestrator & CLI Runner (spec Milestone 3 §15)

Coordinates the end-to-end audit pipeline:
1. Discovery (AST, Files, UI, Routes, DB, Tests, Dependencies, Fingerprint, Product Archetype)
2. Task & Check Obligation Manifest Generation (with strict naming discipline)
3. Sandbox Bootstrap & Candidate Contract Detection
4. Deterministic Verification (Static, Real HTTP, Playwright Browser, Test Runners)
5. User Flow & State-Machine Integrity Auditing
6. Adversarial Review & Cross-Checking
7. Completeness Accounting (P1-P8 Invariants)
8. Production 5-State Certification & 7 Release Gates
9. Deterministic Reproducibility Bundle Generation
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.discovery import (
    build_audit_task_manifest,
    build_graph_relationships,
    discover_api_endpoints,
    discover_code_entities,
    discover_configs_and_services,
    discover_database_entities,
    discover_features_and_requirements,
    discover_files,
    discover_tests,
    discover_ui_elements,
    fingerprint_project,
)
from packages.evidence import EvidenceStore, ReproducibilityEngine
from packages.intelligence import (
    AdversarialReviewer,
    ArchitectureAuditor,
    CertificationState,
    CompletenessEngine,
    CrossCheckEngine,
    Judge,
    MissingRequirementsEngine,
    SystemUnderstandingEngine,
    VerdictEngine,
)
from packages.project_graph.store import ProjectGraph
from packages.sandbox import RuntimeBootstrapEngine
from packages.verification import UserFlowEngine, VerificationRunner


def run_full_audit(repo_path: str | Path) -> tuple[ProjectGraph, EvidenceStore, dict]:
    t0 = time.time()
    repo_path = Path(repo_path).resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"Invalid repository path: {repo_path}")

    # Security check: Block root or system directories
    forbidden_roots = [Path("/"), Path("C:\\"), Path("C:/"), Path(r"C:\Windows")]
    if repo_path in forbidden_roots or str(repo_path) in ("/", "C:\\", "C:/"):
        raise PermissionError(f"Scanning system root {repo_path} is prohibited for safety.")

    # Initialize Graph & Evidence Vault
    graph = ProjectGraph()
    evidence_store = EvidenceStore()

    # 1. Project Fingerprinting
    fingerprint = fingerprint_project(repo_path)

    # 2. Discovery Phase
    discover_files(repo_path, graph)
    discover_code_entities(repo_path, graph)
    discover_api_endpoints(repo_path, graph)
    discover_ui_elements(repo_path, graph)
    discover_database_entities(repo_path, graph)
    discover_tests(repo_path, graph)
    discover_configs_and_services(repo_path, graph)
    discover_features_and_requirements(repo_path, graph)
    build_graph_relationships(graph)

    # 3. Product & Architecture Understanding
    understanding_engine = SystemUnderstandingEngine(graph)
    product_understanding = understanding_engine.analyze(fingerprint)

    # 4. Generate Check Obligations & Tasks
    build_audit_task_manifest(graph)

    # 5. Runtime Bootstrap Candidate Detection
    bootstrap_engine = RuntimeBootstrapEngine(repo_path)
    candidate_contract = bootstrap_engine.detect_candidate()

    # 6. Verification Execution Phase
    verifier = VerificationRunner(repo_path, graph, evidence_store)
    verification_stats = verifier.run_all()

    # 7. User Flow & State-Machine Auditing
    flow_engine = UserFlowEngine(graph)
    user_flows = flow_engine.discover_and_audit_flows()

    # 8. Intelligence & Adversarial Review
    missing_reqs_engine = MissingRequirementsEngine(graph, evidence_store)
    missing_reqs = missing_reqs_engine.analyze()

    cross_check_engine = CrossCheckEngine(graph, evidence_store)
    cross_check_engine.cross_check()

    arch_auditor = ArchitectureAuditor(graph, evidence_store)
    arch_findings = arch_auditor.audit()

    adversarial_reviewer = AdversarialReviewer(graph, evidence_store)
    adversarial_stats = adversarial_reviewer.review()

    # 9. Judge Conflict Resolution
    judge = Judge(graph, evidence_store)
    judge.resolve_conflicts()

    # 10. Completeness Verification (P1-P8 Invariants)
    completeness_engine = CompletenessEngine(graph)
    coverage_report = completeness_engine.evaluate_coverage()

    # 11. Production 5-State Certification & 7-Gate Evaluation
    verdict_engine = VerdictEngine(graph)
    verdict = verdict_engine.compute_verdict()

    # 12. Reproducibility Manifest
    repro_engine = ReproducibilityEngine(evidence_store)
    repro_manifest = repro_engine.generate_manifest(
        audit_id=f"AUDIT-{int(time.time())}",
        repo_path=str(repo_path),
        commit_sha="HEAD",
        certification_state=verdict["certification_state"],
        runtime_contract_payload=json.dumps(candidate_contract.to_runtime_contract()) if candidate_contract else "",
    )

    elapsed = round(time.time() - t0, 3)

    summary = {
        "repo_path": str(repo_path),
        "fingerprint": fingerprint.to_dict(),
        "product_understanding": product_understanding,
        "entity_counts": graph.counts_by_type(),
        "status_counts": graph.status_counts(),
        "verification_stats": verification_stats,
        "adversarial_stats": adversarial_stats,
        "candidate_runtime_contract": candidate_contract.to_dict() if candidate_contract else None,
        "user_flows": [f.to_dict() for f in user_flows],
        "completeness": coverage_report,
        "verdict": verdict,
        "reproducibility": repro_manifest.to_dict(),
        "evidence_records": evidence_store.to_dict_list(),
        "claims": evidence_store.claims_to_dict_list(),
        "findings": [f.to_dict() for f in graph.findings.values()],
        "elapsed_seconds": elapsed,
    }

    graph.metadata = summary
    return graph, evidence_store, summary


def print_audit_report(summary: dict) -> None:
    v = summary["verdict"]
    c = summary["completeness"]
    fp = summary["fingerprint"]
    prod = summary["product_understanding"]
    checks = c.get("check_obligations", {})
    gates = v.get("production_gates", [])

    print("=" * 75)
    print("AI PRODUCTION ENGINEERING AUDIT PLATFORM — CERTIFICATION REPORT")
    print("=" * 75)
    print(f"Target Project:        {summary['repo_path']}")
    print(f"Product Archetype:     {prod['product_archetype']}")
    print(f"Stack Detected:        {', '.join(fp['frameworks']) or 'Node/Python'} | DB: {', '.join(fp['databases']) or 'PostgreSQL'}")
    print("-" * 75)
    print(f"CERTIFICATION STATE:   {v['certification_state']}")
    print(f"EXECUTIVE VERDICT:     {v['verdict_status']} (Badge: {v['status_badge']})")
    print(f"STATEMENT:             {v['summary_statement']}")
    print(f"READINESS SCORE:       {v['overall_score']} / 10.0")
    print("-" * 75)
    print("THE 7 PRODUCTION RELEASE GATES:")
    for gate in gates:
        status_symbol = "[PASS]" if gate["passed"] else "[FAIL]"
        print(f"  {status_symbol:<7} {gate['name']:<35} : {gate['details']}")
    print("-" * 75)
    print("DOMAIN READINESS SCORES:")
    for domain, score in v["domain_scores"].items():
        filled = int(score)
        bar = "#" * filled + "-" * (10 - filled)
        print(f"  {domain:<24} [{bar}] {score:>4}/10")
    print("-" * 75)
    print(f"CHECK OBLIGATIONS:     {checks.get('total', 0)} Total ({checks.get('passed', 0)} Passed, {checks.get('failed', 0)} Failed, {checks.get('unverified', 0)} Unverified, {checks.get('blocked', 0)} Blocked)")
    print(f"MULTI-TIER COVERAGE:   Static AST: {checks.get('static_coverage_pct', 100)}% | Dynamic Runtime: {checks.get('runtime_coverage_pct', 0)}%")
    print(f"P1 ACCOUNTING:         {c['terminal_entities'] + c['unverified_entities']} / {c['discovered_entities']} entities accounted for (P1 Invariant: {'PASS' if c['complete_accounting'] else 'FAIL'})")
    print("-" * 75)
    print(f"CONFIRMED FINDINGS:    {v['findings_summary']['critical']} Critical, {v['findings_summary']['high']} High, {v['findings_summary']['medium']} Medium, {v['findings_summary']['low']} Low")
    print("\nTOP PRODUCTION BLOCKERS:")
    for b in v["top_blockers"]:
        print(f"  [{b['severity']}] {b['title']}")
        print(f"    Evidence: {', '.join(b['evidence_ids'])}")
        print(f"    Impact:   {b['observed_behavior']}")
        print(f"    Fix:      {b['recommendation']}\n")
    print(f"Total Audit Execution Time: {summary['elapsed_seconds']}s")
    print("=" * 75)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Production Engineering Auditor")
    parser.add_argument("--repo", required=True, help="Path to local repository to audit")
    parser.add_argument("--out", default=None, help="Save JSON report to file")
    parser.add_argument("--db", default=None, help="Persist Project Graph to SQLite")
    args = parser.parse_args()

    try:
        graph, evidence_store, summary = run_full_audit(args.repo)
        print_audit_report(summary)

        if args.out:
            out_p = Path(args.out)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(f"\nAudit Summary saved to {args.out}")

        if args.db:
            db_p = Path(args.db)
            graph.persist(db_p, evidence_store)
            print(f"Project Graph & Evidence Vault persisted to {args.db}")

    except Exception as e:
        print(f"\n[ERROR] Audit execution failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
