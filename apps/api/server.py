"""
Launcher & REST API Server for AI Production Audit Platform.
Runs canonical FastAPI + Uvicorn if installed, or zero-dependency stdlib HTTPServer.
"""
from __future__ import annotations

import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.intake import ProjectRegistry, SourceType
from packages.orchestration import AgentRegistry
from workers.audit_orchestrator import run_full_audit

WEB_DIR = ROOT_DIR / "apps" / "web"
FIXTURE_DEFAULT_REPO = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"
PROJECT_REGISTRY = ProjectRegistry()
AGENT_REGISTRY = AgentRegistry()

FORBIDDEN_SYSTEM_PATHS = {
    "/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin", "/home", "/users",
    "c:\\", "c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\users",
    "c:/", "c:/windows", "c:/program files", "c:/program files (x86)", "c:/users",
}


def validate_safe_repo_path(raw_path: str) -> tuple[bool, Optional[Path], str]:
    if not raw_path:
        return True, FIXTURE_DEFAULT_REPO, ""

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


class ZeroDependencyHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/projects":
            self._send_json({
                "projects": [p.to_dict() for p in PROJECT_REGISTRY.projects.values()],
                "audit_runs": [a.to_dict() for a in PROJECT_REGISTRY.audit_runs.values()],
            })
        elif path == "/api/audits/latest" or path == "/api/audits/summary":
            if not PROJECT_REGISTRY.audit_runs:
                if FIXTURE_DEFAULT_REPO.exists():
                    p = PROJECT_REGISTRY.register_project("Career Platform Benchmark", SourceType.LOCAL_DIRECTORY, FIXTURE_DEFAULT_REPO, is_benchmark=True)
                    PROJECT_REGISTRY.run_audit_for_project(p.project_id)
            latest_id = list(PROJECT_REGISTRY.audit_runs.keys())[-1] if PROJECT_REGISTRY.audit_runs else None
            if latest_id:
                self._send_json(PROJECT_REGISTRY.audit_runs[latest_id].summary)
            else:
                self._send_json({"error": "No audit data"}, 404)
        elif path == "/api/graph" or path == "/api/audits/graph":
            latest_id = list(PROJECT_REGISTRY.audit_graphs.keys())[-1] if PROJECT_REGISTRY.audit_graphs else None
            if latest_id:
                self._send_json(PROJECT_REGISTRY.audit_graphs[latest_id].to_dict())
            else:
                self._send_json({"error": "No graph data"}, 404)
        elif path == "/api/evidence" or path == "/api/audits/evidence":
            latest_id = list(PROJECT_REGISTRY.audit_evidence_stores.keys())[-1] if PROJECT_REGISTRY.audit_evidence_stores else None
            if latest_id:
                self._send_json(PROJECT_REGISTRY.audit_evidence_stores[latest_id].to_dict())
            else:
                self._send_json({"error": "No evidence data"}, 404)
        elif path == "/api/agents":
            self._send_json({
                "agents": [a.to_dict() for a in AGENT_REGISTRY.all()],
                "proposals": [p.to_dict() for p in AGENT_REGISTRY.get_proposals()],
            })
        else:
            # Serve Static Web UI
            rel_path = path.lstrip("/")
            file_path = WEB_DIR / (rel_path if rel_path and rel_path != "static" else "index.html")
            if rel_path.startswith("static/"):
                file_path = WEB_DIR / rel_path[7:]

            if not file_path.exists() or file_path.is_dir():
                file_path = WEB_DIR / "index.html"

            if file_path.exists() and file_path.is_file():
                mime, _ = mimetypes.guess_type(str(file_path))
                mime = mime or "application/octet-stream"
                content = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json({"error": "Not Found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body = {}

        if path == "/api/projects":
            name = body.get("name", "Unnamed Project")
            src_type = body.get("source_type", "LOCAL_DIRECTORY")
            src_loc = body.get("source_location", "")
            is_valid, resolved_p, err = validate_safe_repo_path(src_loc)
            if not is_valid:
                self._send_json({"error": err}, 400)
                return
            prj = PROJECT_REGISTRY.register_project(name, src_type, resolved_p)
            audit = PROJECT_REGISTRY.run_audit_for_project(prj.project_id)
            self._send_json({"project": prj.to_dict(), "audit": audit.to_dict()}, 200)
        elif path.startswith("/api/projects/") and path.endswith("/audits"):
            parts = path.strip("/").split("/")
            prj_id = parts[2]
            if prj_id in PROJECT_REGISTRY.projects:
                audit = PROJECT_REGISTRY.run_audit_for_project(prj_id)
                self._send_json(audit.to_dict(), 200)
            else:
                self._send_json({"error": f"Project '{prj_id}' not found"}, 404)
        elif path in ("/api/audits/run", "/api/audits/re-audit"):
            target_repo = body.get("repo_path", "")
            is_valid, resolved_p, err = validate_safe_repo_path(target_repo)
            if not is_valid:
                self._send_json({"error": err}, 400)
                return
            prj_name = resolved_p.name.replace("_", " ").title()
            prj = PROJECT_REGISTRY.register_project(prj_name, SourceType.LOCAL_DIRECTORY, resolved_p)
            audit = PROJECT_REGISTRY.run_audit_for_project(prj.project_id)
            self._send_json(audit.summary, 200)
        else:
            self._send_json({"error": "Unknown POST endpoint"}, 404)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    try:
        import uvicorn
        from apps.api.main import app as fastapi_app
        print(f"Starting Project Graph Canonical FastAPI on http://0.0.0.0:{port}")
        uvicorn.run(fastapi_app, host="0.0.0.0", port=port)
    except ImportError:
        print(f"Starting Project Graph Standalone HTTP Server on http://0.0.0.0:{port}")
        server = HTTPServer(("0.0.0.0", port), ZeroDependencyHandler)
        server.serve_forever()
