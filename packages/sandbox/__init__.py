"""
Sandbox and Execution Environment subsystem for isolated, safe process management.
"""
from .environment import EnvironmentCapabilities, detect_environment_capabilities
from .process_manager import ProcessManager, ManagedProcess

__all__ = [
    "EnvironmentCapabilities",
    "detect_environment_capabilities",
    "ProcessManager",
    "ManagedProcess",
]
