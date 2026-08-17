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

FORBIDDEN_SYSTEM_PATHS = {
    "/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin",
    "c:\\", "c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\users",
}


def validate_safe_repo_path(raw_path: str) -> tuple[bool, Optional[Path], str]:
    if not raw_path:
        return True, FIXTURE_DEFAULT_REPO, ""

    try:
        resolved = Path(raw_path).resolve()
    except Exception as e:
        return False, None, f"Invalid path syntax: {e}"

    resolved_str = str(resolved).lower().rstrip("/\\")
    if resolved_str in FORBIDDEN_SYSTEM_PATHS or resolved == resolved.parent:
        return False, None, "Access to root or system directory is blocked for security."

    if not resolved.exists() or not resolved.is_dir():
        return False, None, f"Repository directory does not exist or is not a folder: {resolved}"

    return True, resolved, ""


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
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
    is_valid, target_path, err = validate_safe_repo_path(req.repo_path)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

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
