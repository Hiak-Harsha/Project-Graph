"""
Standalone HTTP & REST API Server for AI Production Audit Platform.
Built on Python's standard library (zero external dependencies required)
with full JSON API + Static Web Dashboard support.
"""
from __future__ import annotations

import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from workers.audit_orchestrator import run_full_audit

WEB_DIR = ROOT_DIR / "apps" / "web"
FIXTURE_DEFAULT_REPO = ROOT_DIR / "tests" / "fixtures" / "sample_career_app"

LATEST_GRAPH = None
LATEST_EVIDENCE_STORE = None
LATEST_SUMMARY = None


def ensure_audit_run():
    global LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY
    if LATEST_SUMMARY is None and FIXTURE_DEFAULT_REPO.exists():
        LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY = run_full_audit(FIXTURE_DEFAULT_REPO)


class AuditRequestHandler(BaseHTTPRequestHandler):
    def send_json(self, data: dict | list, status_code: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
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
        ensure_audit_run()
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_static(WEB_DIR / "index.html")
        elif path.startswith("/static/"):
            rel_file = path.replace("/static/", "")
            self.send_static(WEB_DIR / rel_file)
        elif path == "/api/audits/latest":
            self.send_json(LATEST_SUMMARY)
        elif path == "/api/audits/graph":
            self.send_json({
                "nodes": [n.to_dict() for n in LATEST_GRAPH.nodes.values()],
                "edges": [e.to_dict() for e in LATEST_GRAPH.edges],
                "counts": LATEST_GRAPH.counts_by_type(),
            })
        elif path == "/api/audits/findings":
            self.send_json([f.to_dict() for f in LATEST_GRAPH.findings.values()])
        elif path == "/api/audits/tasks":
            self.send_json([t.to_dict() for t in LATEST_GRAPH.audit_tasks.values()])
        elif path == "/api/audits/evidence":
            self.send_json(LATEST_EVIDENCE_STORE.to_dict_list())
        elif path == "/api/audits/coverage":
            self.send_json(LATEST_SUMMARY.get("completeness", {}))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        global LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY
        parsed = urlparse(self.path)
        if parsed.path == "/api/audits/run":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                data = {}

            target_repo = Path(data.get("repo_path", str(FIXTURE_DEFAULT_REPO)))
            if not target_repo.exists():
                self.send_json({"error": f"Path not found: {target_repo}"}, status_code=400)
                return

            LATEST_GRAPH, LATEST_EVIDENCE_STORE, LATEST_SUMMARY = run_full_audit(target_repo)
            self.send_json(LATEST_SUMMARY)
        else:
            self.send_response(404)
            self.end_headers()


def run_server(port: int = 8080) -> None:
    ensure_audit_run()
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, AuditRequestHandler)
    print(f"[*] AI Production Audit Platform Dashboard running at http://127.0.0.1:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
