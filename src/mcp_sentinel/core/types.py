from __future__ import annotations
import enum
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LifecyclePhase(enum.Enum):
    CREATION = "creation"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True)
class Location:
    file: Path | None = None
    line: int | None = None
    column: int | None = None
    tool_name: str | None = None
    snippet: str | None = None


@dataclass(frozen=True)
class OWASPMapping:
    llm_top10: tuple[str, ...] = ()
    agentic_top10: tuple[str, ...] = ()


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    phase: LifecyclePhase
    location: Location
    remediation: str
    owasp: OWASPMapping
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolDef:
    name: str
    description: str = ""
    server_name: str = ""


@dataclass
class MCPManifest:
    server_name: str = ""
    server_version: str = ""
    tools: list[ToolDef] = field(default_factory=list)


@dataclass
class ScanStats:
    files_scanned: int = 0
    tools_inspected: int = 0
    rules_executed: int = 0
    findings_by_severity: dict[str, int] = field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
    )


@dataclass
class ScanResult:
    target: str
    scan_mode: str = "auto"
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    duration_seconds: float = 0.0
    sentinel_version: str = ""
    timestamp: str = field(
        default_factory=lambda: time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
    )


@dataclass
class ScanTarget:
    path: str
    mode: str = "auto"
    phase_filter: LifecyclePhase | None = None
    severity_filter: Severity = Severity.LOW
    output_format: str = "console"
    output_file: Path | None = None
    fail_on: Severity = Severity.HIGH
    baseline_path: Path | None = None


@dataclass
class ScanContext:
    target: ScanTarget
    source_files: dict[Path, Any] = field(default_factory=dict)
    manifest: MCPManifest | None = None
    manifests: list[MCPManifest] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    baseline: dict | None = None

    @property
    def has_source(self) -> bool:
        return len(self.source_files) > 0

    @property
    def has_manifest(self) -> bool:
        return self.manifest is not None or len(self.manifests) > 0

    @property
    def has_config(self) -> bool:
        return len(self.config) > 0
