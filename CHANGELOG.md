# Changelog

## [0.1.0] — 2026-06-18

### Added
- 17 detection rules across 4 MCP lifecycle phases (creation, deployment, runtime, maintenance)
- Static code analysis via Python AST traversal
- Dynamic runtime scanning via MCP stdio connector
- 5 output formats: console (Rich), JSON, HTML, PDF (weasyprint), SARIF 2.1.0
- CLI tool (`mcp-sentinel scan`, `baseline`, `diff`, `list-rules`, `version`)
- Docker one-command deployment
- 27 test cases (24 unit + 3 integration)
- OWASP LLM Top 10 and Agentic Top 10 mapping
- Based on HUST Security PRIDE research (arXiv:2503.23278)

### Verified
- Successfully scanned MCP Python SDK (23K+ stars) — 16 findings including `shell=True` injection vectors
