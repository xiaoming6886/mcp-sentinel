"""MCS-C005: Command Injection / Backdoor Detection.

Performs AST-level inspection of source files for dangerous patterns:
- subprocess invocations with shell=True or dynamic command strings
- eval/exec with non-literal arguments
- base64 decode + exec chains
- Suspicious import chains (ctypes foreign code execution)
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule


# ─── Suspicious Imports ──────────────────────────────────────────────────

_SUSPICIOUS_IMPORTS = {
    "ctypes": "Foreign function library — can call arbitrary native code",
    "cffi": "C Foreign Function Interface — same risk as ctypes",
    "os": "Not inherently malicious but enables: os.system(), os.popen()",
}


# ─── AST Visitor ──────────────────────────────────────────────────────────

class _CommandInjectionVisitor(ast.NodeVisitor):
    """Walk an AST and collect dangerous call/import patterns."""

    def __init__(self, file_path: Path, source_lines: list[str] | None = None):
        self.file_path = file_path
        self.source_lines = source_lines or []
        self.findings: list[dict] = []
        self._base64_seen: bool = False
        self._eval_seen: bool = False
        self._exec_seen: bool = False
        self._ctypes_seen: bool = False
        self._cffi_seen: bool = False

    # ── Imports ──────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in _SUSPICIOUS_IMPORTS:
                self.findings.append({
                    "type": "suspicious_import",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": f"import {alias.name} — {_SUSPICIOUS_IMPORTS[base_mod]}",
                })
            if base_mod == "ctypes":
                self._ctypes_seen = True
            if base_mod == "cffi":
                self._cffi_seen = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in _SUSPICIOUS_IMPORTS:
                names = ", ".join(a.name for a in node.names)
                self.findings.append({
                    "type": "suspicious_import",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": f"from {node.module} import {names} — {_SUSPICIOUS_IMPORTS[base_mod]}",
                })
            if base_mod == "ctypes":
                self._ctypes_seen = True
            if base_mod == "cffi":
                self._cffi_seen = True
        self.generic_visit(node)

    # ── Dangerous Calls ──────────────────────────────────────────────────

    def _is_literal(self, node: ast.expr | None) -> bool:
        """Check if *node* is a safely-safe literal (constant, or simple ops on constants)."""
        if node is None:
            return True
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self._is_literal(elt) for elt in node.elts)
        # f-strings are NOT literals from a security standpoint
        if isinstance(node, ast.JoinedStr):
            return False
        if isinstance(node, ast.BinOp):
            return self._is_literal(node.left) and self._is_literal(node.right)
        if isinstance(node, ast.UnaryOp):
            return self._is_literal(node.operand)
        return False

    def _is_subprocess_danger(self, node: ast.Call) -> dict | None:
        """Check a call for subprocess.run/call/Popen with dangerous args."""
        func = node.func
        func_name = ""
        if isinstance(func, ast.Attribute):
            func_name = func.attr
            if not (isinstance(func.value, ast.Name) and func.value.id == "subprocess"):
                # Only flag direct subprocess.* calls
                return None
        elif isinstance(func, ast.Name):
            func_name = func.id
        else:
            return None

        if func_name not in ("run", "call", "Popen", "check_call", "check_output"):
            return None

        # Check keyword args for shell=True
        for kw in node.keywords:
            if kw.arg == "shell" and self._is_truthy(kw.value):
                return {
                    "type": "shell_true",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": f"subprocess.{func_name}(..., shell=True)",
                }

        # Check for f-string / dynamic args
        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                return {
                    "type": "fstring_args",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": f"subprocess.{func_name}(f-string, ...) — dynamic command",
                }
            if isinstance(first_arg, (ast.BinOp, ast.Call)):
                return {
                    "type": "dynamic_args",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": f"subprocess.{func_name}(dynamic-arg, ...) — non-static command",
                }

        return None

    def _is_truthy(self, node: ast.expr) -> bool:
        """Conservative truthiness check."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        # Non-constant: assume True (conservative)
        return True

    def visit_Call(self, node: ast.Call) -> None:
        # --- eval / exec detection ---
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "eval":
                self._eval_seen = True
                self._check_eval_exec(node, "eval")
            elif func.id == "exec":
                self._exec_seen = True
                self._check_eval_exec(node, "exec")
        elif isinstance(func, ast.Attribute):
            # base64.b64decode(...)
            if isinstance(func.value, ast.Name) and func.value.id == "base64":
                if func.attr in ("b64decode", "standard_b64decode", "urlsafe_b64decode", "decodebytes", "decodestring"):
                    self._base64_seen = True
            # os.system / os.popen
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                if func.attr in ("system", "popen"):
                    self.findings.append({
                        "type": "os_system",
                        "line": node.lineno,
                        "col": node.col_offset,
                        "detail": f"os.{func.attr}(...) — OS command execution",
                    })

        # --- subprocess danger ---
        subproc_hit = self._is_subprocess_danger(node)
        if subproc_hit:
            self.findings.append(subproc_hit)

        self.generic_visit(node)

    def _check_eval_exec(self, node: ast.Call, func_name: str) -> None:
        """Check if eval/exec args are non-literal."""
        if node.args and not self._is_literal(node.args[0]):
            self.findings.append({
                "type": f"{func_name}_nonliteral",
                "line": node.lineno,
                "col": node.col_offset,
                "detail": f"{func_name}(non-literal) — dynamic code execution",
            })


def _get_ast_from_value(value: Any) -> ast.Module | None:
    """Try to extract an AST module from the source_files dict value."""
    if isinstance(value, ast.Module):
        return value
    if isinstance(value, ast.AST):
        return value  # type: ignore[return-value]
    if isinstance(value, str):
        try:
            return ast.parse(value)
        except SyntaxError:
            return None
    return None


@register_rule("MCS-C005", LifecyclePhase.CREATION, Severity.CRITICAL, "Command Injection/Backdoor")
class CommandInjectionRule(BaseRule):
    """AST-level detection of command injection, dynamic code execution, and backdoors."""

    requires_source = True

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        if not ctx.source_files:
            return findings

        for file_path, source_value in ctx.source_files.items():
            tree = _get_ast_from_value(source_value)
            if tree is None:
                continue

            visitor = _CommandInjectionVisitor(file_path)
            visitor.visit(tree)

            for hit in visitor.findings:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Dangerous pattern in {file_path.name}:{hit['line']} — {hit['detail']}"
                        ),
                        location=Location(
                            file=file_path,
                            line=hit["line"],
                            column=hit.get("col"),
                            snippet=hit["detail"],
                        ),
                        remediation=self._build_remediation(hit),
                        owasp=OWASPMapping(
                            llm_top10=("LLM05",),
                            agentic_top10=("ASI05",),
                        ),
                        confidence=self._confidence_for(hit),
                    )
                )

            # Cross-pattern: base64 decode followed by exec
            if visitor._base64_seen and (visitor._exec_seen or visitor._eval_seen):
                findings.append(
                    self._make_finding(
                        description=(
                            f"Combined base64 decode + exec/eval pattern detected in "
                            f"{file_path.name}. This is a classic obfuscation technique "
                            f"used in malware and backdoors."
                        ),
                        location=Location(
                            file=file_path,
                            snippet="base64.b64decode + exec/eval detected in same file",
                        ),
                        remediation=(
                            "Remove the base64-decode-then-execute pattern. "
                            "This is a well-known anti-detection technique that "
                            "almost never has legitimate use in MCP server code."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM05",),
                            agentic_top10=("ASI05",),
                        ),
                        confidence=Confidence.HIGH,
                    )
                )

            if visitor._ctypes_seen:
                findings.append(
                    self._make_finding(
                        description=(
                            f"ctypes import detected in {file_path.name}. "
                            f"ctypes enables arbitrary native code execution "
                            f"and is uncommon in MCP server code."
                        ),
                        location=Location(
                            file=file_path,
                            snippet="import ctypes — enables arbitrary native code execution",
                        ),
                        remediation=(
                            "Remove ctypes usage unless there is a clearly documented "
                            "and justified need. Most MCP servers should not require "
                            "native code invocation."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM05",),
                            agentic_top10=("ASI05",),
                        ),
                        confidence=Confidence.MEDIUM,
                        severity=Severity.HIGH,
                    )
                )

            if visitor._cffi_seen:
                findings.append(
                    self._make_finding(
                        description=(
                            f"cffi import detected in {file_path.name}. "
                            f"Like ctypes, cffi enables arbitrary native code execution."
                        ),
                        location=Location(
                            file=file_path,
                            snippet="import cffi — enables arbitrary native code execution",
                        ),
                        remediation=(
                            "Remove cffi usage unless there is a clearly documented "
                            "and justified need."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM05",),
                            agentic_top10=("ASI05",),
                        ),
                        confidence=Confidence.MEDIUM,
                        severity=Severity.HIGH,
                    )
                )

        return findings

    def _confidence_for(self, hit: dict) -> Confidence:
        hit_type = hit.get("type", "")
        if hit_type in ("shell_true", "eval_nonliteral", "exec_nonliteral"):
            return Confidence.HIGH
        if hit_type in ("fstring_args", "os_system"):
            return Confidence.HIGH
        return Confidence.MEDIUM

    def _build_remediation(self, hit: dict) -> str:
        hit_type = hit.get("type", "")
        detail = hit.get("detail", "")
        if hit_type == "shell_true":
            return (
                "Avoid shell=True in subprocess calls. Use argument lists "
                "instead of shell strings, or remove shell=True if not required."
            )
        if hit_type == "fstring_args":
            return (
                "Do not construct shell commands with f-strings or dynamic input. "
                "Pass command arguments as a list to subprocess.run()."
            )
        if hit_type == "dynamic_args":
            return (
                "Avoid dynamically constructed commands. Use static argument "
                "lists for subprocess invocations."
            )
        if hit_type in ("eval_nonliteral", "exec_nonliteral"):
            return (
                "Replace eval()/exec() with safe alternatives (e.g., ast.literal_eval "
                "for data parsing). Dynamic code execution is rarely justified in "
                "MCP server code."
            )
        if hit_type == "os_system":
            return (
                "Replace os.system()/os.popen() with subprocess.run() using "
                "argument lists and shell=False for safer execution."
            )
        if hit_type == "suspicious_import":
            return (
                f"Review this import for necessity. If the module is needed, "
                f"document its purpose and restrict its usage scope."
            )
        return f"Review: {detail}"
