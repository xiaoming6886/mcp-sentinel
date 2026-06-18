# Contributing to MCP Sentinel

Thanks for helping make MCP more secure!

## Quick Start

```bash
git clone https://github.com/YOUR_USER/mcp-sentinel.git
cd mcp-sentinel
pip install -e ".[dev]"
pytest
```

## Development

- **Add a detection rule**: Create a new file in `src/mcp_sentinel/rules/<phase>/`, extend `BaseRule`, and use the `@register_rule` decorator. See existing rules for patterns.
- **Run tests**: `pytest` — 27 tests should pass in <1s.
- **Lint**: `ruff check src/ && mypy src/`

## Pull Requests

1. Add tests for new rules or bug fixes
2. Ensure all existing tests still pass
3. Run `ruff check src/` and `mypy src/`
4. Reference the paper section if adding a new threat type (arXiv:2503.23278)

## Code Style

- Python 3.11+ with type hints
- Docstrings for public classes and methods
- Follow existing patterns in `rules/creation/` for rule structure

## Reporting Security Issues

Please do NOT open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for responsible disclosure.
