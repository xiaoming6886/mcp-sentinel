"""MCS-C006: Installer Integrity Detection.

Inspects Python packaging files (setup.py, pyproject.toml) for:
- Dangerous module-level calls in setup.py (os.system, requests.get, eval, exec, etc.)
- Custom build hooks / backends in pyproject.toml that could execute arbitrary code
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


# ─── Dangerous Call Names ────────────────────────────────────────────────

_DANGEROUS_CALLS: dict[str, str] = {
    "system": "os.system() — shell command execution",
    "popen": "os.popen() — shell command execution",
    "get": "requests.get() / urllib.request.urlopen() — network fetch during install",
    "urlretrieve": "urllib.request.urlretrieve() — downloads file during install",
    "eval": "eval() — dynamic code execution",
    "exec": "exec() — dynamic code execution",
    "compile": "compile() — dynamic code compilation (often paired with exec)",
    "__import__": "__import__() — dynamic import of arbitrary modules",
}

_BAD_MODULE_PATTERNS: dict[str, set[str]] = {
    "os": {"system", "popen"},
    "subprocess": {"run", "call", "Popen", "check_call", "check_output"},
    "requests": {"get", "post", "put"},
    "urllib.request": {"urlopen", "urlretrieve"},
    "builtins": {"eval", "exec", "compile", "__import__"},
}

# ─── AST Visitor for setup.py ────────────────────────────────────────────

class _SetupPyVisitor(ast.NodeVisitor):
    """Walk setup.py AST at module level (not inside functions/classes)."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: list[dict] = []
        self._depth: int = 0
        self._in_callable: bool = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Skip function bodies — we only care about module-level code
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Skip class bodies
        pass

    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        # Only recurse into args of top-level calls (not into nested function defs)
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)

    def _check_call(self, node: ast.Call) -> None:
        func = node.func
        # Direct name call: eval(), exec(), etc.
        if isinstance(func, ast.Name):
            if func.id in _DANGEROUS_CALLS:
                self.findings.append({
                    "type": f"direct_{func.id}",
                    "line": node.lineno,
                    "col": node.col_offset,
                    "detail": _DANGEROUS_CALLS.get(func.id, func.id),
                })

        # Attribute call: os.system(), requests.get(), etc.
        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                module = func.value.id
                method = func.attr
                if module in _BAD_MODULE_PATTERNS and method in _BAD_MODULE_PATTERNS[module]:
                    self.findings.append({
                        "type": f"{module}_{method}",
                        "line": node.lineno,
                        "col": node.col_offset,
                        "detail": f"{module}.{method}() — potentially dangerous in setup.py",
                    })

        # Nested attribute: urllib.request.urlretrieve()
        elif isinstance(func, ast.Attribute):
            pass  # Already handled above


# ─── Helper: parse TOML build-system section ─────────────────────────────

def _check_pyproject_toml(content: str, file_path: Path) -> list[dict]:
    """Lightweight TOML inspection for custom build hooks.

    Falls back to regex heuristics if tomli/tomllib is unavailable.
    """
    findings: list[dict] = []
    try:
        # Python 3.11+ has tomllib
        import tomllib  # type: ignore[import-not-found]
        data = tomllib.loads(content)
        findings.extend(_check_build_system(data, file_path))
        findings.extend(_check_tool_hooks(data, file_path))
    except Exception:
        # Fallback: regex heuristics
        findings.extend(_regex_check_pyproject(content, file_path))
    return findings


def _check_build_system(data: dict, file_path: Path) -> list[dict]:
    findings: list[dict] = []
    build_system = data.get("build-system", {})
    if not isinstance(build_system, dict):
        return findings

    backend = build_system.get("build-backend", "")
    if isinstance(backend, str) and backend:
        known_backends = {
            "setuptools.build_meta",
            "setuptools.build_meta:__legacy__",
            "poetry.core.masonry.api",
            "poetry.masonry.api",
            "flit_core.buildapi",
            "flit.buildapi",
            "hatchling.build",
            "pdm.backend",
            "maturin",
            "mesonpy",
            "scikit_build_core.build",
        }
        if backend not in known_backends:
            findings.append({
                "type": "unknown_backend",
                "line": None,
                "col": None,
                "detail": f"Unknown build backend: '{backend}'. Custom backends can execute arbitrary code.",
                "file": str(file_path),
            })

    # Check build-system requires for unusual packages
    requires = build_system.get("requires", [])
    suspicious_reqs = {"ctypes", "cffi", "requests", "urllib3"}
    if isinstance(requires, list):
        for req in requires:
            req_name = req.split(">")[0].split("<")[0].split("=")[0].split("!")[0].split("[")[0].strip()
            if req_name.lower() in suspicious_reqs:
                findings.append({
                    "type": "suspicious_build_dep",
                    "line": None,
                    "col": None,
                    "detail": f"Suspicious build dependency: '{req}' — may be used for data exfiltration during build",
                    "file": str(file_path),
                })

    return findings


def _check_tool_hooks(data: dict, file_path: Path) -> list[dict]:
    """Check [tool.*] sections for script hooks that execute during build."""
    findings: list[dict] = []
    hooks_section = data.get("tool", {}).get("poetry", {}).get("scripts", {})
    if isinstance(hooks_section, dict):
        for script_name, script_cmd in hooks_section.items():
            if isinstance(script_cmd, str) and any(
                keyword in script_cmd.lower()
                for keyword in ("curl", "wget", "eval", "exec", "bash -c", "sh -c")
            ):
                findings.append({
                    "type": "suspicious_script",
                    "line": None,
                    "col": None,
                    "detail": f"Poetry script '{script_name}' contains suspicious command: {script_cmd[:100]}",
                    "file": str(file_path),
                })
    return findings


def _regex_check_pyproject(content: str, file_path: Path) -> list[dict]:
    """Regex-based fallback when TOML parsing fails."""
    import re
    findings: list[dict] = []

    # Check for non-standard build-backend
    backend_match = re.search(
        r'build-backend\s*=\s*["\']([^"\']+)["\']',
        content,
    )
    if backend_match:
        backend = backend_match.group(1)
        known = {
            "setuptools.build_meta", "poetry.core.masonry.api",
            "flit_core.buildapi", "hatchling.build", "pdm.backend",
        }
        if backend not in known:
            findings.append({
                "type": "unknown_backend",
                "detail": f"Custom build backend: '{backend}' — may execute arbitrary code",
                "file": str(file_path),
            })

    return findings


def _get_ast_from_value(value: Any) -> ast.Module | None:
    """Extract an AST Module from a source_files value."""
    if isinstance(value, ast.Module):
        return value
    if isinstance(value, str):
        try:
            return ast.parse(value)
        except SyntaxError:
            return None
    return None


@register_rule("MCS-C006", LifecyclePhase.CREATION, Severity.HIGH, "Installer Integrity")
class InstallerIntegrityRule(BaseRule):
    """Detect malicious code in Python packaging files."""

    requires_source = True

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        for file_path, source_value in ctx.source_files.items():
            name_lower = file_path.name.lower()

            if name_lower == "setup.py":
                tree = _get_ast_from_value(source_value)
                if tree is None:
                    continue

                visitor = _SetupPyVisitor(file_path)
                visitor.visit(tree)

                for hit in visitor.findings:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Dangerous call in {file_path.name}:{hit['line']} — "
                                f"{hit['detail']}. Code in setup.py executes at "
                                f"install time with user privileges."
                            ),
                            location=Location(
                                file=file_path,
                                line=hit.get("line"),
                                column=hit.get("col"),
                                snippet=hit["detail"],
                            ),
                            remediation=(
                                "Remove dangerous calls from setup.py. Installation "
                                "scripts should never execute arbitrary commands, "
                                "download files, or evaluate dynamic code. Use "
                                "declarative configuration instead."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            confidence=Confidence.HIGH,
                        )
                    )

            elif name_lower == "pyproject.toml":
                content = source_value if isinstance(source_value, str) else str(source_value)
                if not isinstance(content, str) or not content.strip():
                    continue

                toml_findings = _check_pyproject_toml(content, file_path)
                for hit in toml_findings:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Issue in {file_path.name}: {hit['detail']}"
                            ),
                            location=Location(
                                file=file_path,
                                snippet=hit["detail"],
                            ),
                            remediation=(
                                "Use only well-known, trusted build backends "
                                "(setuptools, poetry-core, flit-core, hatchling, pdm-backend). "
                                "Remove custom build hooks that execute arbitrary commands."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            confidence=self._confidence_for(hit),
                        )
                    )

        return findings

    def _confidence_for(self, hit: dict) -> Confidence:
        hit_type = hit.get("type", "")
        if hit_type in ("suspicious_script", "unknown_backend"):
            return Confidence.MEDIUM
        if hit_type == "suspicious_build_dep":
            return Confidence.LOW
        return Confidence.HIGH
