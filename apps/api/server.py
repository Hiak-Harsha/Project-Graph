"""
Standalone HTTP & REST API Server for AI Production Audit Platform.
Built on Python's standard library (zero external dependencies required)
with full JSON API + Multi-Project Intake + Static Web Dashboard support.
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
sys.path.insert(0, str(ROOT_DIR))

from packages.intake import ProjectRegistry, SourceType
from packages.orchestration import AgentRegistry

WEB_DIR = ROOT_DIR / "apps" / "web"
FIXTURE_DEFAULT_REPO = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"

PROJECT_REGISTRY = ProjectRegistry()
AGENT_REGISTRY = AgentRegistry()
INITIALIZED_BENCHMARK = False


def ensure_initial_setup() -> None:
    global INITIALIZED_BENCHMARK
    if not INITIALIZED_BENCHMARK and FIXTURE_DEFAULT_REPO.exists():
        prj = PROJECT_REGISTRY.register_project(
            name="Career Platform Benchmark",
            source_type=SourceType.LOCAL_DIRECTORY,
            source_location=FIXTURE_DEFAULT_REPO,
            is_benchmark=True,
        )
        PROJECT_REGISTRY.run_audit_for_project(prj.project_id)
        INITIALIZED_BENCHMARK = True


FORBIDDEN_SYSTEM_PATHS = {
    "/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin",
    "c:\\", "c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\users",
    "c:/", "c:/windows", "c:/program files", "c:/program files (x86)", "c:/users",
}


def validate_safe_repo_path(raw_path: str) -> tuple[bool, Optional[Path], str]:
    if not raw_path:
        return True, FIXTURE_DEFAULT_REPO, ""

    clean_raw = str(raw_path).strip().lower().replace("/", "\\")
    clean_posix = str(raw_path).strip().lower().replace("\\", "/")

    # Cross-platform check before resolve()
    if clean_posix in ("/", "/etc", "/proc", "/sys", "/dev", "/root", "/var", "/usr", "/bin", "/sbin", "/home", "/users") or \
       clean_posix.startswith(("/etc/", "/proc/", "/sys/", "/dev/", "/root/")) or \
       clean_raw in ("c:\\", "c:", "c:\\windows", "c:\\users", "c:\\users\\", "c:\\program files") or \
       clean_raw.startswith(("c:\\windows", "\\\\", "..")):
        return False, None, "Access to root or system directory is blocked for security."

    try:
        resolved = Path(raw_path).resolve()
    except Exception as e:
        return False, None, f"Invalid path syntax: {e}"

    if not resolved.exists():
        return False, None, f"Target file/folder does not exist: {resolved}"

    return True, resolved, ""


class AuditRequestHandler(BaseHTTPRequestHandler):
    def send_json(self, data: dict | list, status_code: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def send_static(self, file_path: Path) -> None:
        if not file_path.exists() or not file_path.is_file():
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        content_type, _ = mimetypes.guess_type(str(file_path))
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        ensure_initial_setup()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # Static assets
        if path in ("/", "/index.html"):
            self.send_static(WEB_DIR / "index.html")
            return
        elif path.startswith("/static/"):
            rel_file = path.replace("/static/", "")
            self.send_static(WEB_DIR / rel_file)
            return

        # Multi-Project APIs
        if path == "/api/projects":
            self.send_json(PROJECT_REGISTRY.list_projects())
            return

        # Latest Audit summary
        latest_audit = PROJECT_REGISTRY.get_latest_audit()

        if path == "/api/audits/latest":
            self.send_json(latest_audit.summary if latest_audit else {})
            return
        elif path == "/api/audits/graph":
            if latest_audit and latest_audit.audit_id in PROJECT_REGISTRY.audit_graphs:
                g = PROJECT_REGISTRY.audit_graphs[latest_audit.audit_id]
                self.send_json({
                    "nodes": [n.to_dict() for n in g.nodes.values()],
                    "edges": [e.to_dict() for e in g.edges],
                    "counts": g.counts_by_type(),
                })
            else:
                self.send_json({"nodes": [], "edges": [], "counts": {}})
            return
        elif path == "/api/audits/checks":
            if latest_audit and latest_audit.audit_id in PROJECT_REGISTRY.audit_graphs:
                g = PROJECT_REGISTRY.audit_graphs[latest_audit.audit_id]
                self.send_json([c.to_dict() for c in g.audit_checks.values()])
            else:
                self.send_json([])
            return
        elif path == "/api/audits/evidence":
            if latest_audit and latest_audit.audit_id in PROJECT_REGISTRY.audit_evidence_stores:
                ev = PROJECT_REGISTRY.audit_evidence_stores[latest_audit.audit_id]
                self.send_json(ev.to_dict_list())
            else:
                self.send_json([])
            return
        elif path.startswith("/api/audits/"):
            audit_id = path.replace("/api/audits/", "")
            audit = PROJECT_REGISTRY.audit_runs.get(audit_id)
            if audit:
                self.send_json(audit.summary)
            else:
                self.send_json({"error": "Audit not found"}, status_code=404)
            return
        elif path == "/api/platform/agents":
            self.send_json([agent.to_dict() for agent in AGENT_REGISTRY.all()])
            return
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        ensure_initial_setup()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {}

        if path == "/api/projects":
            # Register a new project and immediately audit it
            name = data.get("name", "Custom Project")
            src_type_str = data.get("source_type", "LOCAL_DIRECTORY")
            raw_path = data.get("source_location", "")

            is_valid, target_path, err_msg = validate_safe_repo_path(raw_path)
            if not is_valid:
                self.send_json({"error": err_msg}, status_code=400)
                return

            try:
                src_type = SourceType(src_type_str)
            except Exception:
                src_type = SourceType.LOCAL_DIRECTORY

            prj = PROJECT_REGISTRY.register_project(
                name=name,
                source_type=src_type,
                source_location=target_path,
                is_benchmark=False,
            )
            audit_run = PROJECT_REGISTRY.run_audit_for_project(prj.project_id)
            self.send_json({
                "project": prj.to_dict(),
                "audit": audit_run.to_dict(),
            })
            return

        elif path.startswith("/api/projects/") and path.endswith("/audits"):
            parts = path.split("/")
            project_id = parts[3]
            try:
                audit_run = PROJECT_REGISTRY.run_audit_for_project(project_id)
                self.send_json(audit_run.to_dict())
            except Exception as e:
                self.send_json({"error": str(e)}, status_code=400)
            return

        elif path == "/api/audits/run":
            raw_path = data.get("repo_path")
            is_valid, target_repo, err_msg = validate_safe_repo_path(raw_path)
            if not is_valid:
                self.send_json({"error": err_msg}, status_code=400)
                return

            prj_name = target_repo.name if target_repo else "Audited Project"
            prj = PROJECT_REGISTRY.register_project(
                name=prj_name,
                source_type=SourceType.LOCAL_DIRECTORY,
                source_location=target_repo,
                is_benchmark=False,
            )
            audit_run = PROJECT_REGISTRY.run_audit_for_project(prj.project_id)
            self.send_json(audit_run.summary)
            return

        else:
            self.send_response(404)
            self.end_headers()


def run_server(port: int = 8080) -> None:
    ensure_initial_setup()
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, AuditRequestHandler)
    print(f"[*] AI Production Audit Platform Dashboard running at http://127.0.0.1:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
