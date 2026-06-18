"""MCS-R003: Tool Chain Abuse — detect dangerous tool capability combinations
that could be chained by an attacker through the LLM."""

from __future__ import annotations
import enum
from typing import TYPE_CHECKING

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    Finding,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Capability classification
# ---------------------------------------------------------------------------


class Capability(enum.Enum):
    READ_EXTERNAL = "READ_EXTERNAL"
    READ_FILE = "READ_FILE"
    WRITE_FILE = "WRITE_FILE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"


# Keywords in tool name or description that hint at a capability
CAPABILITY_KEYWORDS: dict[Capability, list[str]] = {
    Capability.READ_EXTERNAL: [
        "fetch", "http", "url", "api", "request", "download",
        "scrape", "crawl", "web", "curl", "wget", "rest",
    ],
    Capability.READ_FILE: [
        "read", "file", "open", "cat", "head", "tail", "load",
        "parse", "csv", "json read", "yaml read", "xml read",
    ],
    Capability.WRITE_FILE: [
        "write", "save", "create", "delete", "remove", "rm ",
        "mkdir", "touch", "output", "dump", "export",
    ],
    Capability.EXECUTE: [
        "exec", "run", "shell", "command", "bash", "cmd",
        "subprocess", "script", "eval", "system", "popen",
        "os.system", "spawn",
    ],
    Capability.NETWORK: [
        "socket", "bind", "listen", "connect", "port",
        "tcp", "udp", "server", "proxy", "tunnel", "ssh",
    ],
    Capability.DATABASE: [
        "sql", "query", "db", "database", "cursor", "table",
        "insert", "update", "select", "mongo", "redis",
        "postgres", "mysql", "sqlite",
    ],
}

# (capability_a, capability_b) → severity and finding title
DANGEROUS_COMBOS: dict[tuple[Capability, Capability], tuple[Severity, str]] = {
    (Capability.READ_EXTERNAL, Capability.EXECUTE): (
        Severity.CRITICAL,
        "READ_EXTERNAL + EXECUTE: external data could be directly executed",
    ),
    (Capability.WRITE_FILE, Capability.EXECUTE): (
        Severity.HIGH,
        "WRITE_FILE + EXECUTE: written files could be executed",
    ),
    (Capability.READ_FILE, Capability.NETWORK): (
        Severity.HIGH,
        "READ_FILE + NETWORK: sensitive files could be exfiltrated over network",
    ),
    (Capability.READ_EXTERNAL, Capability.WRITE_FILE): (
        Severity.HIGH,
        "READ_EXTERNAL + WRITE_FILE: remote content written to disk without validation",
    ),
    (Capability.DATABASE, Capability.NETWORK): (
        Severity.HIGH,
        "DATABASE + NETWORK: query results could be exfiltrated",
    ),
    (Capability.READ_EXTERNAL, Capability.DATABASE): (
        Severity.MEDIUM,
        "READ_EXTERNAL + DATABASE: unsanitized external data injected into queries",
    ),
}


def _classify_tool(tool) -> set[Capability]:
    """Classify a single tool by analysing its name and description."""
    lower = f"{tool.name} {tool.description}".lower()
    caps: set[Capability] = set()
    for cap, keywords in CAPABILITY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            caps.add(cap)
    return caps


def _server_has_capability(server_caps: dict[str, set[Capability]], server: str, cap: Capability) -> bool:
    """Return True if *server* has at least one tool with *cap*."""
    return cap in server_caps.get(server, set())


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@register_rule("MCS-R003", LifecyclePhase.RUNTIME, Severity.HIGH, "Tool Chain Abuse")
class R003ToolChainAbuse(BaseRule):
    """Detect dangerous combinations of tool capabilities within a single MCP
    server that could be chained by an attacker to escalate privileges."""

    requirement_mode = "any"

    RULE_ID = "MCS-R003"
    PHASE = LifecyclePhase.RUNTIME
    DEFAULT_SEVERITY = Severity.HIGH
    TITLE = "Tool Chain Abuse"

    @property
    def requires_source(self) -> bool:
        return False

    @property
    def requires_manifest(self) -> bool:
        return True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for manifest in ctx.manifests:
            server_caps: set[Capability] = set()
            tool_details: dict[str, set[Capability]] = {}

            for tool in manifest.tools:
                caps = _classify_tool(tool)
                if caps:
                    tool_details[tool.name] = caps
                    server_caps.update(caps)

            if len(server_caps) < 2:
                continue

            # Build server-level capability dict for combo check
            server_cap_dict = {manifest.server_name: server_caps}

            for (cap_a, cap_b), (sev, combo_desc) in DANGEROUS_COMBOS.items():
                has_a = cap_a in server_caps
                has_b = cap_b in server_caps

                if has_a and has_b:
                    # Find which tools provide each capability
                    tools_a = [n for n, c in tool_details.items() if cap_a in c]
                    tools_b = [n for n, c in tool_details.items() if cap_b in c]

                    findings.append(
                        self._make_finding(
                            description=(
                                f"Server '{manifest.server_name}' has dangerous capability "
                                f"combination: {combo_desc}. "
                                f"Tools providing {cap_a.value}: {', '.join(tools_a)}. "
                                f"Tools providing {cap_b.value}: {', '.join(tools_b)}."
                            ),
                            location=Location(
                                tool_name=", ".join(tools_a + tools_b),
                            ),
                            remediation=(
                                f"Restrict the {cap_a.value} and {cap_b.value} capabilities "
                                f"to different servers, or add strong safeguards between them."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM06",),
                                agentic_top10=("ASI02",),
                            ),
                            severity=sev,
                            confidence=Confidence.MEDIUM,
                            metadata={
                                "capabilities": [cap_a.value, cap_b.value],
                                "tools_a": tools_a,
                                "tools_b": tools_b,
                            },
                        )
                    )

        return findings
