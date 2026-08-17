"""
FastAPI Server for AI Production Audit Platform
Exposes audit orchestration, Project Graph explorer, Evidence inspector,
and serves the modern web dashboard.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import sys
ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from workers.audit_orchestrator import run_full_audit

app = FastAPI(
    title="AI Production Audit Platform API",
    description="Autonomous, evidence-backed software production-readiness auditor",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory latest audit cache
LATEST_GRAPH = None
LATEST_EVIDENCE_STORE = None
LATEST_SUMMARY = None

WEB_DIR = ROOT_DIR / "apps" / "web"
FIXTURE_DEFAULT_REPO = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"


class RunAuditRequest(BaseModel):
    repo_path: Optional[str] = None


@app.on_event("startup")
def startup_audit():
    global LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY
    if FIXTURE_DEFAULT_REPO.exists():
        LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY = run_full_audit(FIXTURE_DEFAULT_REPO)


@app.post("/api/audits/run")
def trigger_audit(req: RunAuditRequest):
    global LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY
    target_path = Path(req.repo_path) if req.repo_path else FIXTURE_DEFAULT_REPO
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Repository path does not exist: {target_path}")

    LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY = run_full_audit(target_path)
    return LATEST_SUMMARY


@app.get("/api/audits/latest")
def get_latest_audit():
    if not LATEST_SUMMARY:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return LATEST_SUMMARY


@app.get("/api/audits/graph")
def get_graph():
    if not LATEST_GRAPH:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return {
        "nodes": [n.to_dict() for n in LATEST_GRAPH.nodes.values()],
        "edges": [e.to_dict() for e in LATEST_GRAPH.edges],
        "counts": LATEST_GRAPH.counts_by_type(),
    }


@app.get("/api/audits/findings")
def get_findings():
    if not LATEST_GRAPH:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return [f.to_dict() for f in LATEST_GRAPH.findings.values()]


@app.get("/api/audits/tasks")
def get_tasks():
    if not LATEST_GRAPH:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return [t.to_dict() for t in LATEST_GRAPH.audit_tasks.values()]


@app.get("/api/audits/evidence")
def get_evidence():
    if not LATEST_EVIDENCE_STORE:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return LATEST_EVIDENCE_STORE.to_dict_list()


@app.get("/api/audits/coverage")
def get_coverage():
    if not LATEST_SUMMARY:
        raise HTTPException(status_code=404, detail="No audit has been run yet.")
    return LATEST_SUMMARY.get("completeness", {})


# Mount static assets for web UI
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.get("/")
def serve_index():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "AI Production Audit Platform API Active"}
