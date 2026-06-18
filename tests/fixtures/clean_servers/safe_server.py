"""Clean MCP server — reference implementation with no vulnerabilities.

This server follows all security best practices:
- No hardcoded credentials (uses environment variables)
- Proper input validation
- Sandbox-aware (restricted filesystem access)
- Neutral, factual tool descriptions
- No hidden unicode or injection patterns
"""

import os
from pathlib import Path

# Configuration from environment (never hardcoded)
API_KEY = os.environ.get("API_KEY", "")
ALLOWED_DIR = Path(os.environ.get("ALLOWED_DIR", "/tmp"))

# --- Tool definitions (safe, neutral descriptions) ---

def read_file(path: str) -> str:
    """Read the contents of a file at the specified path."""
    resolved = (ALLOWED_DIR / path).resolve()
    if not resolved.is_relative_to(ALLOWED_DIR):
        raise ValueError(f"Access denied: {path}")
    return resolved.read_text()


def list_files(directory: str = ".") -> list[str]:
    """List files in the specified directory."""
    resolved = (ALLOWED_DIR / directory).resolve()
    if not resolved.is_relative_to(ALLOWED_DIR):
        raise ValueError(f"Access denied: {directory}")
    return [str(p.relative_to(resolved)) for p in resolved.iterdir()]


def search_files(pattern: str) -> list[str]:
    """Search for files matching a glob pattern."""
    return [str(p) for p in ALLOWED_DIR.glob(pattern) if p.is_file()]
