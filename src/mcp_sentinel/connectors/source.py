"""Source connector for MCP Sentinel — analyzes local MCP server code."""

from __future__ import annotations
from pathlib import Path
import ast
from mcp_sentinel.utils.ast_helpers import parse_file, find_calls, find_imports


class SourceConnector:
    """Analyze local MCP server source code for static security patterns."""

    @staticmethod
    def collect_files(dir_path: Path) -> list[Path]:
        """Collect all Python source files from a directory tree."""
        files = []
        ignored = {"venv", ".venv", "__pycache__", ".git", "node_modules", ".tox"}
        for py_file in dir_path.rglob("*.py"):
            if any(p in ignored for p in py_file.parts):
                continue
            files.append(py_file)
        return files

    @staticmethod
    def parse_all(files: list[Path]) -> dict[Path, ast.Module]:
        """Parse all Python source files into AST modules."""
        parsed = {}
        for f in files:
            try:
                parsed[f] = parse_file(f)
            except SyntaxError:
                pass
        return parsed
