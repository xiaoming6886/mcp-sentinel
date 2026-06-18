"""MCS-R005: Sandbox Escape Risk — detect code patterns that could allow an
MCP server to escape its execution sandbox."""

from __future__ import annotations
import ast
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
from mcp_sentinel.utils.ast_helpers import parse_file

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_IMPORTS: set[str] = {
    "ctypes",
    "cffi",
    "_ctypes",
    "_cffi_backend",
}

DANGEROUS_CALLS: dict[str, str] = {
    "os.kill": "Process signalling capability (os.kill)",
    "os.setuid": "Privilege escalation via setuid",
    "os.setgid": "Privilege escalation via setgid",
    "os.seteuid": "Privilege escalation via seteuid",
    "os.setegid": "Privilege escalation via setegid",
    "os.setreuid": "Privilege escalation via setreuid",
    "os.setregid": "Privilege escalation via setregid",
    "os.setsid": "Session leadership (os.setsid)",
    "os.fork": "Process forking (os.fork)",
    "os.execv": "Process replacement via exec",
    "os.execve": "Process replacement via exec",
    "os.execl": "Process replacement via exec",
    "signal.signal": "Signal handler registration",
    "signal.alarm": "Signal-based timer (signal.alarm)",
    "socket.bind": "Network binding (socket.bind)",
    "ctypes.CDLL": "Native library loading (ctypes.CDLL)",
    "ctypes.WinDLL": "Native library loading (ctypes.WinDLL)",
}

SENSITIVE_PATHS: set[str] = {
    "/proc",
    "/sys",
    "/dev",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32",
}

UNRESTRICTED_SUBPROCESS: set[str] = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
}


def _resolve_call_name(func_node: ast.expr) -> str:
    """Resolve a dotted call name like ``os.kill`` or ``socket.bind``."""
    if isinstance(func_node, ast.Attribute):
        obj = _resolve_call_name(func_node.value)
        return f"{obj}.{func_node.attr}" if obj else func_node.attr
    if isinstance(func_node, ast.Name):
        return func_node.id
    return ""


def _has_kwarg(call_node: ast.Call, kwarg_name: str) -> bool:
    """Return True if *call_node* includes a keyword argument *kwarg_name*."""
    for kw in call_node.keywords:
        if kw.arg == kwarg_name:
            return True
    return False


def _has_string_arg(call_node: ast.Call, substr: str) -> bool:
    """Return True if any positional/keyword arg is a string containing *substr*."""
    for arg in call_node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if substr in arg.value:
                return True
    for kw in call_node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            if substr in kw.value.value:
                return True
    return False


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@register_rule("MCS-R005", LifecyclePhase.RUNTIME, Severity.CRITICAL, "Sandbox Escape Risk")
class R005SandboxEscape(BaseRule):
    """Detect code patterns that could allow an MCP server process to break
    out of its sandbox: native code loading, process manipulation, unrestricted
    subprocess execution, raw socket binding, and access to sensitive system
    paths."""

    requirement_mode = "any"

    RULE_ID = "MCS-R005"
    PHASE = LifecyclePhase.RUNTIME
    DEFAULT_SEVERITY = Severity.CRITICAL
    TITLE = "Sandbox Escape Risk"

    @property
    def requires_source(self) -> bool:
        return True

    @property
    def requires_manifest(self) -> bool:
        return False

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for filepath in ctx.source_files:
            try:
                tree = parse_file(filepath)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            findings.extend(self._check_dangerous_imports(tree, filepath))
            findings.extend(self._check_dangerous_calls(tree, filepath))
            findings.extend(self._check_sensitive_paths(tree, filepath))
            findings.extend(self._check_unrestricted_subprocess(tree, filepath))
            findings.extend(self._check_wildcard_socket_bind(tree, filepath))

        return findings

    # ------------------------------------------------------------------
    # Individual check methods
    # ------------------------------------------------------------------

    def _check_dangerous_imports(self, tree: ast.Module, filepath) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in DANGEROUS_IMPORTS:
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Import of '{alias.name}' enables native code execution "
                                    f"or foreign function interface — sandbox escape risk."
                                ),
                                location=Location(
                                    file=filepath,
                                    line=node.lineno,
                                    snippet=f"import {alias.name}",
                                ),
                                remediation=(
                                    f"Remove the '{alias.name}' import or restrict its usage "
                                    f"with OS-level sandboxing (seccomp, AppArmor, Windows "
                                    f"integrity levels)."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM06",),
                                    agentic_top10=("ASI05",),
                                ),
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module in DANGEROUS_IMPORTS:
                    names = ", ".join(a.name for a in node.names)
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Import from '{node.module}' ({names}) enables native code "
                                f"execution — sandbox escape risk."
                            ),
                            location=Location(
                                file=filepath,
                                line=node.lineno,
                                snippet=f"from {node.module} import {names}",
                            ),
                            remediation=(
                                f"Remove imports from '{node.module}' or restrict with "
                                f"OS-level sandboxing."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM06",),
                                agentic_top10=("ASI05",),
                            ),
                        )
                    )
        return findings

    def _check_dangerous_calls(self, tree: ast.Module, filepath) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _resolve_call_name(node.func)
                if call_name in DANGEROUS_CALLS:
                    reason = DANGEROUS_CALLS[call_name]
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Call to {call_name}() — {reason}. "
                                f"This could allow sandbox escape or privilege escalation."
                            ),
                            location=Location(
                                file=filepath,
                                line=node.lineno,
                            ),
                            remediation=(
                                f"Remove the {call_name}() call or guard it with strict "
                                f"capability checks. Consider using OS-level seccomp filters "
                                f"to block the underlying syscall."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM06",),
                                agentic_top10=("ASI05",),
                            ),
                        )
                    )
        return findings

    def _check_sensitive_paths(self, tree: ast.Module, filepath) -> list[Finding]:
        # Skip detection rule files — they contain pattern strings, not actual code
        if "rules" in str(filepath).replace("\\", "/").split("/"):
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for sensitive in SENSITIVE_PATHS:
                    if _has_string_arg(node, sensitive):
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Access to sensitive path '{sensitive}' detected. "
                                    f"This may allow reading or modifying system state."
                                ),
                                location=Location(
                                    file=filepath,
                                    line=node.lineno,
                                ),
                                remediation=(
                                    f"Block access to '{sensitive}' and similar system paths. "
                                    f"Restrict file I/O to a designated sandbox directory."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM06",),
                                    agentic_top10=("ASI05",),
                                ),
                                confidence=Confidence.MEDIUM,
                            )
                        )
        return findings

    def _check_unrestricted_subprocess(self, tree: ast.Module, filepath) -> list[Finding]:
        # Connectors legitimately spawn MCP server subprocesses
        if "connectors" in str(filepath).replace("\\", "/"):
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _resolve_call_name(node.func)
                if call_name in UNRESTRICTED_SUBPROCESS:
                    has_cwd = _has_kwarg(node, "cwd")
                    has_env = _has_kwarg(node, "env")

                    if call_name == "os.system":
                        # os.system always runs in inherited environment
                        has_cwd = has_env = False

                    if not has_cwd or not has_env:
                        missing = []
                        if not has_cwd:
                            missing.append("cwd")
                        if not has_env:
                            missing.append("env")
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Unrestricted {call_name}() call — missing "
                                    f"{', '.join(missing)} restriction. This allows the "
                                    f"subprocess to inherit the parent environment and "
                                    f"working directory."
                                ),
                                location=Location(
                                    file=filepath,
                                    line=node.lineno,
                                ),
                                remediation=(
                                    f"Always pass explicit cwd= and env= arguments to "
                                    f"{call_name}() to restrict the subprocess execution "
                                    f"context."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM06",),
                                    agentic_top10=("ASI05",),
                                ),
                                confidence=Confidence.MEDIUM,
                            )
                        )
        return findings

    def _check_wildcard_socket_bind(self, tree: ast.Module, filepath) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _resolve_call_name(node.func)
                if call_name == "socket.bind" and node.args:
                    first_arg = node.args[0]
                    # Check for ('0.0.0.0', port) tuple
                    if isinstance(first_arg, ast.Tuple) and first_arg.elts:
                        host = first_arg.elts[0]
                        if isinstance(host, ast.Constant) and host.value == "0.0.0.0":
                            findings.append(
                                self._make_finding(
                                    description=(
                                        f"socket.bind('0.0.0.0', ...) binds to all network "
                                        f"interfaces — may expose the server to the network "
                                        f"unnecessarily."
                                    ),
                                    location=Location(
                                        file=filepath,
                                        line=node.lineno,
                                    ),
                                    remediation=(
                                        "Bind to '127.0.0.1' (localhost) instead of "
                                        "'0.0.0.0' unless external access is explicitly "
                                        "required and firewalled."
                                    ),
                                    owasp=OWASPMapping(
                                        llm_top10=("LLM06",),
                                        agentic_top10=("ASI05",),
                                    ),
                                )
                            )
        return findings
