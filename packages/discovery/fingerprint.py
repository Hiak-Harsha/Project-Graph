"""
Phase: PROJECT FINGERPRINTING (spec Milestone 1 §4)

Deterministic signal-file and dependency marker detection before deep AST parsing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


SIGNAL_FILES = {
    "package.json": "node",
    "requirements.txt": "python-pip",
    "pyproject.toml": "python-poetry",
    "Pipfile": "python-pipenv",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "Dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    ".github/workflows": "github-actions",
}

FRAMEWORK_DEP_MARKERS = {
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "@angular/core": "Angular",
    "express": "Express",
    "fastapi": "FastAPI",
    "django": "Django",
    "flask": "Flask",
    "@nestjs/core": "NestJS",
}

DB_DEP_MARKERS = {
    "pg": "PostgreSQL",
    "psycopg2": "PostgreSQL",
    "mysql": "MySQL",
    "mongoose": "MongoDB",
    "prisma": "Prisma ORM",
    "@prisma/client": "Prisma ORM",
    "sqlalchemy": "SQLAlchemy",
    "sequelize": "Sequelize",
    "sqlite3": "SQLite",
}

EXT_LANGUAGE = {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".py": "Python",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".sql": "SQL",
    ".prisma": "Prisma",
}


@dataclass
class Fingerprint:
    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    databases: set[str] = field(default_factory=set)
    infrastructure: set[str] = field(default_factory=set)
    package_managers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "databases": sorted(self.databases),
            "infrastructure": sorted(self.infrastructure),
            "package_managers": sorted(self.package_managers),
        }


def fingerprint_project(root: Path) -> Fingerprint:
    fp = Fingerprint()

    for signal, label in SIGNAL_FILES.items():
        if (root / signal).exists():
            if label in (
                "node",
                "python-pip",
                "python-poetry",
                "python-pipenv",
                "java-maven",
                "java-gradle",
                "go",
                "rust",
            ):
                fp.package_managers.add(label)
            else:
                fp.infrastructure.add(label)

    for path in root.rglob("*"):
        if path.is_file() and path.suffix in EXT_LANGUAGE:
            fp.languages.add(EXT_LANGUAGE[path.suffix])

    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for dep in deps:
                if dep in FRAMEWORK_DEP_MARKERS:
                    fp.frameworks.add(FRAMEWORK_DEP_MARKERS[dep])
                if dep in DB_DEP_MARKERS:
                    fp.databases.add(DB_DEP_MARKERS[dep])
        except (json.JSONDecodeError, OSError):
            pass

    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                name = line.strip().split("==")[0].split(">=")[0].strip().lower()
                if name in FRAMEWORK_DEP_MARKERS:
                    fp.frameworks.add(FRAMEWORK_DEP_MARKERS[name])
                if name in DB_DEP_MARKERS:
                    fp.databases.add(DB_DEP_MARKERS[name])
        except OSError:
            pass

    return fp
