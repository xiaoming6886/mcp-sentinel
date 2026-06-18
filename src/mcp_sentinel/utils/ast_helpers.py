"""AST helper utilities for MCP Sentinel."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import Any


def parse_file(path: Path) -> ast.Module:
    """Parse a Python source file into an AST module."""
    source = path.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(path))


def find_calls(tree: ast.AST, func_names: set[str]) -> list[ast.Call]:
    """Find all function calls matching the given function names."""
    results: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolve_name(node.func)
            if name in func_names:
                results.append(node)
    return results


def find_imports(tree: ast.AST, module_names: set[str]) -> list[ast.Import | ast.ImportFrom]:
    """Find imports of specified module names."""
    results: list[ast.Import | ast.ImportFrom] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in module_names:
                    results.append(node)
        elif isinstance(node, ast.ImportFrom):
            if node.module in module_names:
                results.append(node)
    return results


def find_decorated_functions(tree: ast.AST, decorator_names: set[str]) -> list[ast.FunctionDef]:
    """Find functions decorated with the given decorator names."""
    results: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                name = _resolve_name(decorator)
                if name in decorator_names:
                    results.append(node)
                    break
    return results


def _resolve_name(node: ast.expr) -> str:
    """Resolve a name from an AST expression node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
