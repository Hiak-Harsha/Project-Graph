#!/usr/bin/env python3
"""
Milestone 1 vertical slice entrypoint.

    python workers/discovery_worker/run.py --repo <path> [--out report.json] [--db graph.sqlite]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

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
from packages.project_graph.models import reset_id_counters
from packages.project_graph.store import ProjectGraph


def run_discovery(repo_path: Path) -> tuple[ProjectGraph, dict]:
    reset_id_counters()
    graph = ProjectGraph()

    t0 = time.time()
    fingerprint = fingerprint_project(repo_path)
    files = discover_files(repo_path, graph)
    deps = discover_dependencies(repo_path, graph)
    code = discover_code_entities(repo_path, graph)
    ui = discover_ui_elements(repo_path, graph)
    apis = discover_api_endpoints(repo_path, graph)
    db = discover_database_entities(repo_path, graph)
    configs, services = discover_configs_and_services(repo_path, graph)
    tests = discover_tests(repo_path, graph)
    features, requirements = discover_features_and_requirements(repo_path, graph)
    edges = build_graph_relationships(graph)
    tasks = build_audit_task_manifest(graph)
    elapsed = time.time() - t0

    summary = {
        "repo_path": str(repo_path),
        "fingerprint": fingerprint.to_dict(),
        "entity_counts": graph.counts_by_type(),
        "total_entities_discovered": len(graph.nodes),
        "total_relationships_mapped": len(graph.edges),
        "total_audit_tasks_created": len(graph.audit_tasks),
        "phase_counts": {
            "files": len(files),
            "dependencies": len(deps),
            "code_entities": len(code),
            "ui_elements": len(ui),
            "api_endpoints": len(apis),
            "database_entities": len(db),
            "configs": len(configs),
            "external_services": len(services),
            "tests": len(tests),
            "features": len(features),
            "requirements": len(requirements),
        },
        "completeness": graph.completeness_report(),
        "elapsed_seconds": round(elapsed, 3),
    }
    return graph, summary


def print_report(summary: dict) -> None:
    fp = summary["fingerprint"]
    print("=" * 65)
    print("PROJECT DISCOVERY REPORT (Milestone 1)")
    print("=" * 65)
    print(f"Repo:        {summary['repo_path']}")
    print(f"Languages:   {', '.join(fp['languages']) or '(none detected)'}")
    print(f"Frameworks:  {', '.join(fp['frameworks']) or '(none detected)'}")
    print(f"Databases:   {', '.join(fp['databases']) or '(none detected)'}")
    print(f"Infra:       {', '.join(fp['infrastructure']) or '(none detected)'}")
    print("-" * 65)
    for entity_type, count in sorted(summary["entity_counts"].items()):
        print(f"  {entity_type:<22} {count}")
    print("-" * 65)
    print(f"TOTAL ENTITIES DISCOVERED  : {summary['total_entities_discovered']}")
    print(f"TOTAL RELATIONSHIPS MAPPED : {summary['total_relationships_mapped']}")
    print(f"TOTAL AUDIT TASKS CREATED  : {summary['total_audit_tasks_created']}")
    c = summary["completeness"]
    print(f"COMPLETENESS CHECK         : "
          f"{c['terminal_entities'] + c['unverified_entities']}/{c['discovered_entities']} accounted for "
          f"({'PASS' if c['complete_accounting'] else 'INVARIANT VIOLATED'})")
    print(f"Elapsed: {summary['elapsed_seconds']}s")
    print("=" * 65)


def main() -> None:
    parser = argparse.ArgumentParser(description="Milestone 1: Project Discovery Engine")
    parser.add_argument("--repo", required=True, help="Path to a local repository to scan")
    parser.add_argument("--out", default=None, help="Write JSON summary to this path")
    parser.add_argument("--db", default=None, help="Persist the Project Graph to this SQLite file")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"error: repo path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    graph, summary = run_discovery(repo_path)
    print_report(summary)

    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2))
        print(f"\nSummary written to {args.out}")

    if args.db:
        graph.persist(args.db)
        print(f"Project Graph persisted to {args.db}")


if __name__ == "__main__":
    main()
