"""
Canonical FastAPI Server for AI Production Engineering Auditor.
Provides:
- Multi-project intake & content-addressed revision management
- Isolated audit run execution & SQLite/JSON persistence
- Project Graph explorer & Evidence Vault inspection APIs
- Interactive Web Dashboard static serving
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.intake import ProjectRegistry, SourceType
from packages.orchestration import AgentRegistry
from workers.audit_orchestrator import run_full_audit

app = FastAPI(
    title="Project Graph Production Auditor API",
    description="Autonomous, evidence-backed production engineering auditor for any software repository",
    version="2.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_REGISTRY = ProjectRegistry()
AGENT_REGISTRY = AgentRegistry()
WEB_DIR = ROOT_DIR / "apps" / "web"

FORBIDDEN_SYSTEM_PATHS = {
    "/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin", "/home", "/users",
    "c:\\", "c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\users",
    "c:/", "c:/windows", "c:/program files", "c:/program files (x86)", "c:/users",
}


def validate_safe_repo_path(raw_path: str) -> tuple[bool, Optional[Path], str]:
    if not raw_path:
        default_p = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"
        return True, default_p, ""

    clean_raw = str(raw_path).strip().lower().replace("/", "\\")
    clean_posix = str(raw_path).strip().lower().replace("\\", "/")

    if clean_posix in ("/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin", "/home", "/users") or \
       clean_posix.startswith(("/etc/", "/proc/", "/sys/", "/dev/", "/root/")) or \
       clean_raw in ("c:\\", "c:", "c:\\windows", "c:\\users", "c:\\users\\", "c:\\program files") or \
       clean_raw.startswith(("c:\\windows\\", "c:\\program files\\")):
        return False, None, "Access to root or system directory is blocked for security."

    try:
        resolved = Path(raw_path).resolve()
    except Exception as e:
        return False, None, f"Invalid path syntax: {e}"

    if str(resolved).lower().rstrip("/\\") in FORBIDDEN_SYSTEM_PATHS or resolved == resolved.parent:
        return False, None, "Access to root or system directory is blocked for security."

    if not resolved.exists() or not resolved.is_dir():
        return False, None, f"Repository directory does not exist or is not a folder: {resolved}"

    return True, resolved, ""


# Pydantic Request Models
class CreateProjectRequest(BaseModel):
    name: str
    source_type: str = "LOCAL_DIRECTORY"
    source_location: str
    is_benchmark: bool = False


class RunDirectAuditRequest(BaseModel):
    repo_path: Optional[str] = None


@app.on_event("startup")
def startup_init():
    # Register default benchmarks if present
    career_fixture = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"
    if career_fixture.exists():
        p1 = PROJECT_REGISTRY.register_project(
            name="Career Platform Benchmark",
            source_type=SourceType.LOCAL_DIRECTORY,
            source_location=career_fixture,
            is_benchmark=True,
        )
        PROJECT_REGISTRY.run_audit_for_project(p1.project_id)

    acme_fixture = ROOT_DIR / "benchmarks" / "acme_notes"
    if acme_fixture.exists():
        p2 = PROJECT_REGISTRY.register_project(
            name="Acme Notes CRUD Benchmark",
            source_type=SourceType.LOCAL_DIRECTORY,
            source_location=acme_fixture,
            is_benchmark=True,
        )
        PROJECT_REGISTRY.run_audit_for_project(p2.project_id)


# Project Intake Endpoints
@app.get("/api/projects")
def list_projects():
    return {
        "projects": [p.to_dict() for p in PROJECT_REGISTRY.projects.values()],
        "audit_runs": [a.to_dict() for a in PROJECT_REGISTRY.audit_runs.values()],
    }


@app.post("/api/projects")
def create_project(req: CreateProjectRequest):
    is_valid, resolved_path, err = validate_safe_repo_path(req.source_location)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    project = PROJECT_REGISTRY.register_project(
        name=req.name,
        source_type=req.source_type,
        source_location=resolved_path,
        is_benchmark=req.is_benchmark,
    )
    # Auto-run initial audit
    audit_record = PROJECT_REGISTRY.run_audit_for_project(project.project_id)
    return {
        "project": project.to_dict(),
        "audit": audit_record.to_dict(),
    }


@app.post("/api/projects/{project_id}/audits")
def trigger_project_audit(project_id: str):
    if project_id not in PROJECT_REGISTRY.projects:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")

    record = PROJECT_REGISTRY.run_audit_for_project(project_id)
    return record.to_dict()


@app.get("/api/projects/{project_id}/audits/{audit_id}")
def get_project_audit(project_id: str, audit_id: str):
    if audit_id not in PROJECT_REGISTRY.audit_runs:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")
    record = PROJECT_REGISTRY.audit_runs[audit_id]
    return record.to_dict()


@app.get("/api/projects/{project_id}/audits/{audit_id}/graph")
def get_project_audit_graph(project_id: str, audit_id: str):
    if audit_id not in PROJECT_REGISTRY.audit_graphs:
        raise HTTPException(status_code=404, detail=f"Audit graph '{audit_id}' not found.")
    graph = PROJECT_REGISTRY.audit_graphs[audit_id]
    return graph.to_dict()


@app.get("/api/projects/{project_id}/audits/{audit_id}/evidence")
def get_project_audit_evidence(project_id: str, audit_id: str):
    if audit_id not in PROJECT_REGISTRY.audit_evidence_stores:
        raise HTTPException(status_code=404, detail=f"Audit evidence store '{audit_id}' not found.")
    store = PROJECT_REGISTRY.audit_evidence_stores[audit_id]
    return store.to_dict()


# Direct Compatibility Endpoints
@app.post("/api/audits/run")
def run_direct_audit(req: RunDirectAuditRequest):
    is_valid, target_path, err = validate_safe_repo_path(req.repo_path or "")
    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    project_name = target_path.name.replace("_", " ").title()
    project = PROJECT_REGISTRY.register_project(
        name=project_name,
        source_type=SourceType.LOCAL_DIRECTORY,
        source_location=target_path,
        is_benchmark=False,
    )
    record = PROJECT_REGISTRY.run_audit_for_project(project.project_id)
    return record.summary


@app.get("/api/audits/latest")
def get_latest_audit():
    if not PROJECT_REGISTRY.audit_runs:
        raise HTTPException(status_code=404, detail="No audit runs available.")
    latest_id = list(PROJECT_REGISTRY.audit_runs.keys())[-1]
    return PROJECT_REGISTRY.audit_runs[latest_id].summary


@app.get("/api/graph")
def get_latest_graph():
    if not PROJECT_REGISTRY.audit_graphs:
        raise HTTPException(status_code=404, detail="No graph available.")
    latest_id = list(PROJECT_REGISTRY.audit_graphs.keys())[-1]
    return PROJECT_REGISTRY.audit_graphs[latest_id].to_dict()


@app.get("/api/evidence")
def get_latest_evidence():
    if not PROJECT_REGISTRY.audit_evidence_stores:
        raise HTTPException(status_code=404, detail="No evidence store available.")
    latest_id = list(PROJECT_REGISTRY.audit_evidence_stores.keys())[-1]
    return PROJECT_REGISTRY.audit_evidence_stores[latest_id].to_dict()


@app.get("/api/agents")
def get_agents():
    return {
        "agents": [a.to_dict() for a in AGENT_REGISTRY.all()],
        "proposals": [p.to_dict() for p in AGENT_REGISTRY.get_proposals()],
    }


# Static Web Serving
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(str(WEB_DIR / "index.html"))

    @app.get("/{full_path:path}")
    def serve_static(full_path: str):
        target = WEB_DIR / full_path
        if target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(WEB_DIR / "index.html"))
