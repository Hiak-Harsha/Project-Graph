"""
Runtime Bootstrap & Candidate Contract Synthesizer (spec Milestone 2 §1-3)

Inspects repository manifests (package.json, pyproject.toml, requirements.txt, Dockerfile)
and synthesizes a candidate RuntimeContract for policy review and sandbox startup.
Never executes arbitrary commands without approval or verified contract declaration.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class RuntimeContractCandidate:
    source: str
    detected_frameworks: list[str] = field(default_factory=list)
    build_commands: list[list[str]] = field(default_factory=list)
    start_command: list[str] = field(default_factory=list)
    port: int = 8000
    healthcheck_path: str = "/health"
    environment: dict[str, str] = field(default_factory=dict)
    database_type: Optional[str] = None
    requires_approval: bool = True
    confidence: float = 0.90

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_runtime_contract(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "image": "python:3.11-slim" if any("python" in f.lower() or "fastapi" in f.lower() or "flask" in f.lower() for f in self.detected_frameworks) else "node:20-alpine",
            "port": self.port,
            "healthcheck_path": self.healthcheck_path,
            "startup_timeout_seconds": 30,
            "build_commands": self.build_commands,
            "start_command": self.start_command,
            "environment": self.environment,
            "resource_limits": {
                "cpu": "1.0",
                "memory": "512m",
                "pids": 64,
            },
        }


class RuntimeBootstrapEngine:
    def __init__(self, root: Path) -> None:
        self.root = root

    def detect_candidate(self) -> Optional[RuntimeContractCandidate]:
        frameworks: list[str] = []
        build_cmds: list[list[str]] = []
        start_cmd: list[str] = []
        port = 8000
        health_path = "/health"
        env = {"ENVIRONMENT": "audit_sandbox", "PORT": "8000"}
        db_type = None

        # 1. Python Inspection (FastAPI / Flask / Django)
        req_files = list(self.root.rglob("requirements*.txt"))
        pyproject_files = list(self.root.rglob("pyproject.toml"))

        if req_files or pyproject_files:
            content = ""
            for rf in req_files:
                content += rf.read_text(encoding="utf-8", errors="ignore") + "\n"
            for pf in pyproject_files:
                content += pf.read_text(encoding="utf-8", errors="ignore") + "\n"

            content_lower = content.lower()
            if "fastapi" in content_lower:
                frameworks.append("FastAPI")
                # Look for main.py entrypoint
                main_file = None
                for p in self.root.rglob("main.py"):
                    if "tests" not in str(p) and "node_modules" not in str(p):
                        main_file = p.relative_to(self.root)
                        break
                module_path = str(main_file).replace("\\", "/").replace(".py", "").replace("/", ".") if main_file else "app.main"
                build_cmds.append(["pip", "install", "--no-cache-dir", "-r", "requirements.txt"])
                start_cmd = ["uvicorn", f"{module_path}:app", "--host", "0.0.0.0", "--port", "8000"]
                port = 8000
            elif "flask" in content_lower:
                frameworks.append("Flask")
                build_cmds.append(["pip", "install", "-r", "requirements.txt"])
                start_cmd = ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]
                port = 5000
            elif "django" in content_lower:
                frameworks.append("Django")
                build_cmds.append(["pip", "install", "-r", "requirements.txt"])
                start_cmd = ["python", "manage.py", "runserver", "0.0.0.0:8000"]
                port = 8000

            if "sqlalchemy" in content_lower or "sqlite" in content_lower:
                db_type = "SQLite"
            elif "psycopg2" in content_lower or "asyncpg" in content_lower:
                db_type = "PostgreSQL"

        # 2. Node.js Inspection (Express / Next.js / React)
        pkg_files = list(self.root.rglob("package.json"))
        for pkg_json in pkg_files:
            if "node_modules" in str(pkg_json):
                continue
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                scripts = data.get("scripts", {})

                if "next" in deps:
                    frameworks.append("Next.js")
                    if not start_cmd:
                        build_cmds.append(["npm", "install"])
                        start_cmd = ["npm", "run", "dev", "--", "--port", "3000", "--hostname", "0.0.0.0"]
                        port = 3000
                elif "express" in deps:
                    frameworks.append("Express")
                    if not start_cmd:
                        build_cmds.append(["npm", "install"])
                        start_cmd = ["npm", "start"] if "start" in scripts else ["node", "server.js"]
                        port = 3000
                elif "react" in deps:
                    frameworks.append("React")
                    if not start_cmd:
                        build_cmds.append(["npm", "install"])
                        start_cmd = ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
                        port = 5173

                if "prisma" in deps or "@prisma/client" in deps:
                    db_type = "Prisma"
            except Exception:
                pass

        if not start_cmd:
            return None

        return RuntimeContractCandidate(
            source=str(self.root),
            detected_frameworks=frameworks,
            build_commands=build_cmds,
            start_command=start_cmd,
            port=port,
            healthcheck_path=health_path,
            environment=env,
            database_type=db_type,
            requires_approval=True,
            confidence=0.92,
        )

    def write_candidate_contract(self, dest_path: Optional[Path] = None) -> Optional[Path]:
        candidate = self.detect_candidate()
        if not candidate:
            return None

        target = dest_path or (self.root / ".project-graph" / "runtime-contract.candidate.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(candidate.to_runtime_contract(), indent=2), encoding="utf-8")
        return target
