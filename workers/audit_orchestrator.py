#!/usr/bin/env python3
"""
Full Autonomous Audit Orchestrator (Milestones 1 -> 2 -> 3)

Pipeline:
1. Discovery (M1) -> Project Graph + Task Manifest
2. Verification (M2) -> Deterministic Execution + Evidence Store
3. Intelligence (M3) -> Adversarial Review + Completeness + Verdict
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Add repo root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.discovery import (
    build_audit_task_manifest,
    build_graph_relationships,
    discover_api_endpoints,
    discover_code_entities,
    discover_configs_and_services,
    discover_database_entities,
    discover_dependencies,
    discover_features_and_requirements,
    discover_files,
    discover_tests,
    discover_ui_elements,
    fingerprint_project,
)
from packages.evidence import EvidenceStore, reset_evidence_counter
from packages.intelligence import (
    AdversarialReviewer,
    ArchitectureAuditor,
    CompletenessEngine,
    CrossCheckEngine,
    Judge,
    MissingRequirementsEngine,
    SystemUnderstandingEngine,
    VerdictEngine,
)
from packages.project_graph.models import reset_id_counters
from packages.project_graph.store import ProjectGraph
from packages.verification import VerificationRunner


def run_full_audit(repo_path: Path) -> tuple[ProjectGraph, EvidenceStore, dict]:
    t0 = time.time()
    reset_id_counters()
    reset_evidence_counter()

    graph = ProjectGraph()
    evidence_store = EvidenceStore()

    # =========================================================================
    # PHASE 1: MILESTONE 1 — PROJECT DISCOVERY ENGINE ("What exists?")
    # =========================================================================
    fingerprint = fingerprint_project(repo_path)
    discover_files(repo_path, graph)
    discover_dependencies(repo_path, graph)
    discover_code_entities(repo_path, graph)
    discover_ui_elements(repo_path, graph)
    discover_api_endpoints(repo_path, graph)
    discover_database_entities(repo_path, graph)
    discover_configs_and_services(repo_path, graph)
    discover_tests(repo_path, graph)
    discover_features_and_requirements(repo_path, graph)
    build_graph_relationships(graph)
    build_audit_task_manifest(graph)

    # =========================================================================
    # PHASE 2: MILESTONE 2 — VERIFICATION ENGINE ("What actually happens?")
    # =========================================================================
    verification_runner = VerificationRunner(repo_path, graph, evidence_store)
    verification_stats = verification_runner.run_all()

    # =========================================================================
    # PHASE 3: MILESTONE 3 — AUDIT INTELLIGENCE ("What does it mean?")
    # =========================================================================
    understanding_engine = SystemUnderstandingEngine(graph)
    product_understanding = understanding_engine.synthesize()

    cross_check_engine = CrossCheckEngine(graph, evidence_store)
    cross_check_engine.cross_check()

    missing_req_engine = MissingRequirementsEngine(graph, evidence_store)
    missing_req_engine.discover_missing_requirements()

    arch_auditor = ArchitectureAuditor(graph, evidence_store)
    arch_auditor.audit()

    # Adversarial review & skepticism
    adversarial_reviewer = AdversarialReviewer(graph, evidence_store)
    adversarial_stats = adversarial_reviewer.review_all()

    # Judge conflict resolution
    judge = Judge(graph, evidence_store)
    judge.resolve_conflicts()

    # Completeness verification (P1 invariant)
    completeness_engine = CompletenessEngine(graph)
    coverage_report = completeness_engine.evaluate_coverage()

    # Production verdict
    verdict_engine = VerdictEngine(graph)
    verdict = verdict_engine.compute_verdict()

    elapsed = round(time.time() - t0, 3)

    summary = {
        "repo_path": str(repo_path),
        "fingerprint": fingerprint.to_dict(),
        "product_understanding": product_understanding,
        "entity_counts": graph.counts_by_type(),
        "status_counts": graph.status_counts(),
        "verification_stats": verification_stats,
        "adversarial_stats": adversarial_stats,
        "completeness": coverage_report,
        "verdict": verdict,
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

    print("=" * 70)
    print("AI PRODUCTION AUDIT PLATFORM — EXECUTIVE AUDIT REPORT")
    print("=" * 70)
    print(f"Target Project:     {summary['repo_path']}")
    print(f"Product Archetype:  {prod['product_archetype']}")
    print(f"Stack Detected:     {', '.join(fp['frameworks']) or 'Node/Python'} | DB: {', '.join(fp['databases']) or 'PostgreSQL'}")
    print("-" * 70)
    print(f"EXECUTIVE VERDICT:  {v['verdict_status']} (Badge: {v['status_badge']})")
    print(f"OVERALL READINESS:  {v['overall_score']} / 10.0")
    if v.get("gate_failures"):
        print("PRODUCTION BLOCKER GATES:")
        for gf in v["gate_failures"]:
            print(f"  [X] {gf}")
    print("-" * 70)
    print("DOMAIN SCORES:")
    for domain, score in v["domain_scores"].items():
        filled = int(score)
        bar = "#" * filled + "-" * (10 - filled)
        print(f"  {domain:<24} [{bar}] {score:>4}/10")
    print("-" * 70)
    print(f"CHECK OBLIGATIONS:  {checks.get('total', 0)} Total ({checks.get('passed', 0)} Passed, {checks.get('failed', 0)} Failed, {checks.get('unverified', 0)} Unverified, {checks.get('blocked', 0)} Blocked, {checks.get('errors', 0)} Errors)")
    print(f"MULTI-TIER COVERAGE: Static AST: {checks.get('static_coverage_pct', 100)}% | Dynamic Runtime: {checks.get('runtime_coverage_pct', 0)}%")
    print(f"P1 ACCOUNTING:      {c['terminal_entities'] + c['unverified_entities']} / {c['discovered_entities']} entities accounted for (P1 Invariant: {'PASS' if c['complete_accounting'] else 'FAIL'})")
    print("-" * 70)
    print(f"CONFIRMED FINDINGS: {v['findings_summary']['critical']} Critical, {v['findings_summary']['high']} High, {v['findings_summary']['medium']} Medium, {v['findings_summary']['low']} Low")
    print("\nTOP PRODUCTION BLOCKERS:")
    for b in v["top_blockers"]:
        print(f"  [{b['severity']}] {b['title']}")
        print(f"    Evidence: {', '.join(b['evidence_ids'])}")
        print(f"    Impact:   {b['observed_behavior']}")
        print(f"    Fix:      {b['recommendation']}\n")
    print(f"Total Audit Execution Time: {summary['elapsed_seconds']}s")
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Production Engineering Auditor")
    parser.add_argument("--repo", required=True, help="Path to local repository to audit")
    parser.add_argument("--out", default=None, help="Save JSON report to file")
    parser.add_argument("--db", default=None, help="Persist Project Graph to SQLite")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"Error: path {repo_path} does not exist", file=sys.stderr)
        sys.exit(1)

    graph, evidence_store, summary = run_full_audit(repo_path)
    print_audit_report(summary)

    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2))
        print(f"\nFull audit artifact saved to {args.out}")

    if args.db:
        graph.persist(args.db, evidence_store)
        print(f"Project Graph & Evidence Vault persisted to {args.db}")


if __name__ == "__main__":
    main()
