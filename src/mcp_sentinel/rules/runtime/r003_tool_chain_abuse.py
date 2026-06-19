"""MCS-R003: Tool Chain Abuse — detect dangerous tool capability combinations
both within a single server (manifest) and across source code (call graph)."""

from __future__ import annotations
import ast, enum
from pathlib import Path
from collections import deque

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence, Finding, LifecyclePhase, Location, OWASPMapping, ScanContext, Severity,
)
from mcp_sentinel.rules._base import BaseRule


class Capability(enum.Enum):
    READ_EXTERNAL = "READ_EXTERNAL"
    READ_FILE = "READ_FILE"
    WRITE_FILE = "WRITE_FILE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"


CAPABILITY_KEYWORDS: dict[Capability, list[str]] = {
    Capability.READ_EXTERNAL: ["fetch", "http", "url", "api", "request", "download", "scrape", "crawl", "web", "curl", "wget", "rest"],
    Capability.READ_FILE: ["read", "file", "open", "cat", "head", "tail", "load", "parse", "csv", "json", "yaml", "xml"],
    Capability.WRITE_FILE: ["write", "save", "create", "delete", "remove", "mkdir", "touch", "output", "dump", "export"],
    Capability.EXECUTE: ["exec", "run", "shell", "command", "bash", "cmd", "subprocess", "script", "eval", "system", "popen", "spawn"],
    Capability.NETWORK: ["socket", "bind", "listen", "connect", "port", "tcp", "udp", "server", "proxy", "tunnel", "ssh"],
    Capability.DATABASE: ["sql", "query", "db", "database", "cursor", "table", "insert", "update", "select", "mongo", "redis", "postgres", "mysql", "sqlite"],
}

DANGEROUS_COMBOS: dict[tuple[Capability, Capability], tuple[Severity, str]] = {
    (Capability.READ_EXTERNAL, Capability.EXECUTE): (Severity.CRITICAL, "READ_EXTERNAL + EXECUTE: external data could be directly executed"),
    (Capability.WRITE_FILE, Capability.EXECUTE): (Severity.HIGH, "WRITE_FILE + EXECUTE: written files could be executed"),
    (Capability.READ_FILE, Capability.NETWORK): (Severity.HIGH, "READ_FILE + NETWORK: sensitive files could be exfiltrated"),
    (Capability.READ_EXTERNAL, Capability.WRITE_FILE): (Severity.HIGH, "READ_EXTERNAL + WRITE_FILE: remote content written to disk"),
    (Capability.DATABASE, Capability.NETWORK): (Severity.HIGH, "DATABASE + NETWORK: query results could be exfiltrated"),
    (Capability.READ_EXTERNAL, Capability.DATABASE): (Severity.MEDIUM, "READ_EXTERNAL + DATABASE: unsanitized external data injected into queries"),
}


def _classify_name(name: str) -> set[Capability]:
    """Classify a function or tool name by keyword matching."""
    lower = name.lower()
    caps: set[Capability] = set()
    for cap, keywords in CAPABILITY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            caps.add(cap)
    return caps


def _classify_tool(tool) -> set[Capability]:
    return _classify_name(f"{tool.name} {tool.description}")


def _resolve_call_name(node: ast.expr) -> str:
    """Resolve a function call name from AST."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _resolve_call_name(node.func)
    return ""


def _build_call_graph(source_files: dict[Path, object]) -> tuple[dict[str, set[str]], dict[str, set[Capability]]]:
    """Build a cross-file call graph from parsed AST modules.

    Returns: (func_calls: func_name → {called_funcs}, func_caps: func_name → {capabilities})
    """
    func_calls: dict[str, set[str]] = {}
    func_caps: dict[str, set[Capability]] = {}

    for filepath, tree in source_files.items():
        if tree is None:
            continue
        if not isinstance(tree, ast.Module):
            continue
        try:
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    fname = node.name
                    if fname not in func_calls:
                        func_calls[fname] = set()
                        func_caps[fname] = _classify_name(fname)

                    # Find all calls within this function
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            called = _resolve_call_name(child.func)
                            if called:
                                func_calls[fname].add(called)
        except Exception:
            pass

    return func_calls, func_caps


def _find_capability_paths(
    func_calls: dict[str, set[str]],
    func_caps: dict[str, set[Capability]],
    max_depth: int = 4,
) -> list[tuple[list[str], Capability, Capability, int]]:
    """BFS to find paths between different capability categories.

    Returns: list of (path_funcs, cap_start, cap_end, depth)
    """
    results: list[tuple[list[str], Capability, Capability, int]] = []

    for start_func, start_caps in func_caps.items():
        if not start_caps:
            continue
        visited: set[str] = {start_func}
        queue: deque[tuple[str, list[str], int]] = deque([(start_func, [start_func], 0)])

        while queue:
            current, path, depth = queue.popleft()
            if depth > max_depth:
                continue

            current_caps = func_caps.get(current, set())
            callees = func_calls.get(current, set())

            for callee in callees:
                if callee in visited:
                    continue
                visited.add(callee)
                new_path = path + [callee]
                callee_caps = func_caps.get(callee, set())

                for sc in start_caps:
                    for cc in callee_caps:
                        if sc != cc:
                            combo = (sc, cc)
                            reverse = (cc, sc)
                            if combo in DANGEROUS_COMBOS or reverse in DANGEROUS_COMBOS:
                                results.append((new_path, sc, cc, len(new_path) - 1))
                                # also check via DANGEROUS_COMBOS normalization
                            else:
                                pass  # not a dangerous combo

                queue.append((callee, new_path, depth + 1))

    return results


@register_rule("MCS-R003", LifecyclePhase.RUNTIME, Severity.HIGH, "Tool Chain Abuse")
class R003ToolChainAbuse(BaseRule):
    """Detect dangerous capability combinations via manifest + cross-file call graph."""

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

        # ── Manifest-based detection (existing) ──
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
            for (cap_a, cap_b), (sev, desc) in DANGEROUS_COMBOS.items():
                if cap_a in server_caps and cap_b in server_caps:
                    tools_a = [n for n, c in tool_details.items() if cap_a in c]
                    tools_b = [n for n, c in tool_details.items() if cap_b in c]
                    findings.append(self._make_finding(
                        description=f"Server '{manifest.server_name}' combo: {desc}. Tools: {', '.join(tools_a + tools_b)}",
                        location=Location(tool_name=", ".join(tools_a + tools_b)),
                        remediation=f"Split {cap_a.value} and {cap_b.value} across different servers.",
                        owasp=OWASPMapping(llm_top10=("LLM06",), agentic_top10=("ASI02",)),
                        severity=sev, confidence=Confidence.MEDIUM,
                        metadata={"capabilities": [cap_a.value, cap_b.value], "tools_a": tools_a, "tools_b": tools_b},
                    ))

        # ── Cross-file call graph detection (new) ──
        if ctx.has_source and len(ctx.source_files) > 0:
            func_calls, func_caps = _build_call_graph(ctx.source_files)
            paths = _find_capability_paths(func_calls, func_caps, max_depth=4)

            seen = set()
            for path_funcs, cap_a, cap_b, depth in paths:
                key = (cap_a.value, cap_b.value, tuple(path_funcs))
                if key in seen:
                    continue
                seen.add(key)

                sev = Severity.HIGH if depth >= 2 else Severity.MEDIUM
                combo_desc = f"{cap_a.value} → {cap_b.value} chain ({depth} hops)"
                chain = " → ".join(path_funcs)

                findings.append(self._make_finding(
                    description=f"Cross-file capability chain detected: {combo_desc}. Call path: {chain}",
                    location=Location(file=Path("call_graph"), snippet=chain),
                    remediation=f"Restrict {cap_a.value} and {cap_b.value} to separate modules, or add explicit authorization checks between them.",
                    owasp=OWASPMapping(llm_top10=("LLM06",), agentic_top10=("ASI02",)),
                    severity=sev, confidence=Confidence.MEDIUM,
                    metadata={"capabilities": [cap_a.value, cap_b.value], "path": path_funcs, "depth": depth},
                ))

        return findings
