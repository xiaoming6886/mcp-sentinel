"""ScanContext builder for MCP Sentinel."""

from __future__ import annotations
from pathlib import Path
from typing import Any
from mcp_sentinel.core.types import ScanContext, ScanTarget, MCPManifest


def build_context(target: ScanTarget) -> ScanContext:
    """Build a ScanContext from a ScanTarget by resolving the scan mode.

    Supports: local directories/files, stdio://, http(s)://, config files.
    """
    ctx = ScanContext(target=target)
    target_str = target.path

    # Load baseline if specified
    if target.baseline_path and target.baseline_path.exists():
        try:
            import json
            ctx.baseline = json.loads(target.baseline_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            import sys
            print(f"[WARN] Failed to load baseline: {e}", file=sys.stderr)

    # === Dynamic scan: stdio:// MCP server ===
    if target_str.startswith("stdio://"):
        command_part = target_str[len("stdio://"):]
        parts = command_part.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        try:
            from mcp_sentinel.connectors.stdio import StdioConnector
            connector = StdioConnector(command, args)
            ctx.manifest = connector.connect()
            if ctx.manifest:
                ctx.manifests.append(ctx.manifest)
        except Exception as e:
            import sys
            print(f"[WARN] Stdio connection failed: {e}", file=sys.stderr)
        return ctx

    # === Dynamic scan: http(s):// MCP server ===
    if target_str.startswith("http://") or target_str.startswith("https://"):
        try:
            from mcp_sentinel.connectors.sse import SSEConnector
            connector = SSEConnector(target_str)
            ctx.manifest = connector.connect()
            if ctx.manifest:
                ctx.manifests.append(ctx.manifest)
        except Exception as e:
            import sys
            print(f"[WARN] SSE connection failed: {e}", file=sys.stderr)
        return ctx

    # === Static scan: local path ===
    target_path = Path(target_str)

    if not target_path.exists():
        import sys
        print(f"[WARN] Target not found: {target_str}", file=sys.stderr)
        return ctx

    if target_path.is_dir():
        from mcp_sentinel.connectors.source import SourceConnector
        from mcp_sentinel.analyzers.static import StaticAnalyzer

        files = SourceConnector.collect_files(target_path)
        parsed = StaticAnalyzer().parse_directory(target_path)
        for py_file in files:
            if _is_ignored(py_file):
                continue
            ctx.source_files[py_file] = parsed.get(py_file)

        # Also load MCP client config if present
        _load_config_files(target_path, ctx)

    elif target_path.suffix == ".py":
        from mcp_sentinel.analyzers.static import StaticAnalyzer
        try:
            analyzer = StaticAnalyzer()
            analyzer.parse_directory(target_path.parent)
            ctx.source_files = {k: v for k, v in analyzer._parsed.items()
                               if k == target_path or k.parent == target_path.parent}
        except Exception:
            ctx.source_files[target_path] = None

    elif target_path.suffix in (".json", ".jsonc"):
        _load_json_config(target_path, ctx)

    return ctx


def _load_config_files(dir_path: Path, ctx: ScanContext) -> None:
    """Load MCP client config files from a directory."""
    import json
    for pattern in ("*.json", "*.jsonc"):
        for config_file in dir_path.glob(pattern):
            try:
                text = config_file.read_text(encoding="utf-8")
                # Try to parse as MCP config (has mcpServers key)
                data = json.loads(text.split("//")[0] if "//" in text else text)
                if "mcpServers" in data:
                    ctx.config = data
                    break
            except Exception:
                pass


def _load_json_config(path: Path, ctx: ScanContext) -> None:
    """Load a single JSON/JSONC config file."""
    import json
    try:
        text = path.read_text(encoding="utf-8")
        ctx.config = json.loads(text)
    except Exception:
        pass


def _is_ignored(path: Path) -> bool:
    """Check if a path should be ignored (venv, __pycache__, .git, etc.)."""
    parts = path.parts
    ignored = {"venv", ".venv", "__pycache__", ".git", "node_modules", ".tox", "dist", "build"}
    return any(p in ignored or p.startswith(".") for p in parts if p != ".")
