"""AST analyzer for MCP Sentinel — walks Python source for security patterns."""

from __future__ import annotations
import ast
from pathlib import Path
from mcp_sentinel.utils.ast_helpers import parse_file, find_calls, find_imports


class StaticAnalyzer:
    """Analyze Python source code via AST for security-relevant patterns."""

    DANGEROUS_FUNCS = {
        "eval", "exec", "compile", "__import__",
        "os.system", "os.popen", "os.kill",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "ctypes.CDLL", "ctypes.cdll.LoadLibrary",
        "pickle.loads", "pickle.load",
    }

    NETWORK_FUNCS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "httpx.get", "httpx.post",
        "urllib.request.urlopen", "urllib.request.urlretrieve",
        "socket.socket", "socket.bind", "socket.connect",
    }

    SUSPICIOUS_IMPORTS = {
        "ctypes", "cffi", "subprocess", "socket", "http.server",
        "socketserver", "pickle", "marshal",
    }

    def __init__(self):
        self._parsed: dict[Path, ast.Module] = {}

    def parse_directory(self, dir_path: Path) -> dict[Path, ast.Module]:
        """Parse all .py files in a directory tree into AST modules."""
        for py_file in dir_path.rglob("*.py"):
            if self._is_ignored(py_file):
                continue
            try:
                self._parsed[py_file] = parse_file(py_file)
            except SyntaxError:
                pass
        return self._parsed

    def find_dangerous_calls(self) -> list[tuple[Path, ast.Call]]:
        """Find all calls to dangerous functions."""
        results = []
        for path, tree in self._parsed.items():
            for call in find_calls(tree, self.DANGEROUS_FUNCS):
                results.append((path, call))
        return results

    def find_network_calls(self) -> list[tuple[Path, ast.Call]]:
        """Find all calls that perform network operations."""
        results = []
        for path, tree in self._parsed.items():
            for call in find_calls(tree, self.NETWORK_FUNCS):
                results.append((path, call))
        return results

    def find_suspicious_imports(self) -> list[tuple[Path, ast.AST]]:
        """Find imports of security-sensitive modules."""
        results = []
        for path, tree in self._parsed.items():
            for imp in find_imports(tree, self.SUSPICIOUS_IMPORTS):
                results.append((path, imp))
        return results

    def get_function_source(self, node: ast.FunctionDef) -> str | None:
        """Extract source lines of a function definition from its AST node."""
        if hasattr(node, "end_lineno") and hasattr(node, "lineno"):
            fn = node.name
            return f"def {fn}(...) at line {node.lineno}-{node.end_lineno}"
        return str(node.name) if hasattr(node, "name") else None

    @staticmethod
    def _is_ignored(path: Path) -> bool:
        ignored = {"venv", ".venv", "__pycache__", ".git", "node_modules", ".tox", "dist", "build"}
        return any(p in ignored for p in path.parts)
