"""
Sandboxed Process Manager for safe subprocess execution, timeout bounding, and teardown.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ManagedProcess:
    name: str
    cmd: list[str]
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 15
    process: Optional[subprocess.Popen] = None
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    duration_seconds: float = 0.0

    def run_synchronous(self) -> tuple[int, str, str, float]:
        t0 = time.time()
        merged_env = os.environ.copy()
        merged_env.update(self.env)

        try:
            p = subprocess.run(
                self.cmd,
                cwd=str(self.cwd),
                env=merged_env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            self.duration_seconds = round(time.time() - t0, 3)
            self.returncode = p.returncode
            self.stdout = p.stdout
            self.stderr = p.stderr
            return p.returncode, p.stdout, p.stderr, self.duration_seconds
        except subprocess.TimeoutExpired as e:
            self.duration_seconds = round(time.time() - t0, 3)
            self.returncode = -1
            self.stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            self.stderr = f"Process timed out after {self.timeout_seconds}s"
            return -1, self.stdout, self.stderr, self.duration_seconds
        except Exception as ex:
            self.duration_seconds = round(time.time() - t0, 3)
            self.returncode = -1
            self.stderr = str(ex)
            return -1, "", str(ex), self.duration_seconds


class ProcessManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._active_processes: list[subprocess.Popen] = []

    def execute_command(
        self,
        cmd: list[str],
        cwd: Optional[Path] = None,
        env: Optional[dict[str, str]] = None,
        timeout: int = 20,
    ) -> tuple[int, str, str, float]:
        proc = ManagedProcess(
            name=" ".join(cmd),
            cmd=cmd,
            cwd=cwd or self.root,
            env=env or {},
            timeout_seconds=timeout,
        )
        return proc.run_synchronous()

    def teardown_all(self) -> None:
        for p in self._active_processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self._active_processes.clear()
