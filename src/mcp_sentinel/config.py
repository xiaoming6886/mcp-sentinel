"""CLI configuration and command models."""

from __future__ import annotations
from mcp_sentinel.core.types import LifecyclePhase, Severity


PHASE_MAP: dict[str, LifecyclePhase] = {
    "creation": LifecyclePhase.CREATION,
    "deployment": LifecyclePhase.DEPLOYMENT,
    "runtime": LifecyclePhase.RUNTIME,
    "maintenance": LifecyclePhase.MAINTENANCE,
}

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

OUTPUT_FORMATS = ("console", "json", "html", "pdf", "sarif")

DEFAULT_FAIL_ON = Severity.HIGH
DEFAULT_SEVERITY = Severity.LOW
