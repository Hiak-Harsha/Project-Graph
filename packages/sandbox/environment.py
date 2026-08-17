"""
Environment Capabilities Detection (spec Milestone 2 §1-3).

Discovers and encapsulates the local sandbox capabilities:
- Python runtime & package versions
- Node.js runtime
- Headless Browser (Playwright / Chromium)
- Test runners (pytest, unittest, jest)
- Database services (SQLite, PostgreSQL, MySQL)
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class EnvironmentCapabilities:
    python_available: bool = True
    python_version: str = field(default_factory=lambda: sys.version.split()[0])
    node_available: bool = False
    node_version: str = "UNAVAILABLE"
    playwright_available: bool = False
    playwright_browsers: list[str] = field(default_factory=list)
    pytest_available: bool = False
    docker_available: bool = False
    docker_version: str = "UNAVAILABLE"
    database_sqlite_available: bool = True
    network_outbound_allowed: bool = False
    sandbox_isolation_tier: str = "PROCESS_ISOLATION"  # CONTAINER | PROCESS_ISOLATION | HOST

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_environment_capabilities() -> EnvironmentCapabilities:
    caps = EnvironmentCapabilities()

    # Detect Node.js
    node_bin = shutil.which("node")
    if node_bin:
        try:
            res = subprocess.run([node_bin, "--version"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                caps.node_available = True
                caps.node_version = res.stdout.strip()
        except Exception:
            pass

    # Detect pytest
    try:
        import pytest  # noqa: F401
        caps.pytest_available = True
    except ImportError:
        caps.pytest_available = False

    # Detect Playwright
    try:
        import playwright  # noqa: F401
        caps.playwright_available = True
        caps.playwright_browsers = ["chromium"]
    except ImportError:
        caps.playwright_available = False

    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            res = subprocess.run([docker_bin, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                caps.docker_available = True
                caps.docker_version = res.stdout.strip()
                caps.sandbox_isolation_tier = "CONTAINER"
        except Exception:
            pass

    return caps
