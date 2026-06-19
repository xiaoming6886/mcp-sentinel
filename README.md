# MCP Sentinel

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2503.23278-b31b1b.svg)](https://arxiv.org/abs/2503.23278)

[English](#english) | [中文](#中文)

> **MCP ecosystem security scanner** — lightweight, open-source, developer-first. Think sqlmap/nmap for MCP.

MCP Sentinel covers **4 lifecycle phases** (Creation → Deployment → Runtime → Maintenance) and detects **17 threat types**, based on the first MCP security paper by HUST Security PRIDE (arXiv:2503.23278).

---

<a name="english"></a>
## Quick Start

```bash
pip install mcp-sentinel
# or Docker
docker compose up

# Scan
mcp-sentinel scan ./my-mcp-server -o console
mcp-scan ./my-mcp-server -o json -f report.json
```

## Detection — 17 Rules

| # | Rule ID | Threat | Phase | Severity |
|---|---------|-------|-------|----------|
| 1 | MCS-C001 | Namespace Typosquatting | Creation | HIGH |
| 2 | MCS-C002 | Tool Name Conflict | Creation | MEDIUM |
| 3 | MCS-C003 | Preference Manipulation | Creation | HIGH |
| 4 | MCS-C004 | Tool Poisoning | Creation | CRITICAL |
| 5 | MCS-C005 | Command Injection / Backdoor | Creation | CRITICAL |
| 6 | MCS-C006 | Installer Integrity | Creation | HIGH |
| 7 | MCS-D001 | Credential Exposure | Deployment | CRITICAL |
| 8 | MCS-D002 | Sandbox Misconfiguration | Deployment | HIGH |
| 9 | MCS-D003 | Untrusted Source | Deployment | MEDIUM |
| 10 | MCS-R001 | Indirect Prompt Injection | Runtime | CRITICAL |
| 11 | MCS-R002 | Cross-Server Shadowing | Runtime | HIGH |
| 12 | MCS-R003 | Tool Chain Abuse | Runtime | HIGH |
| 13 | MCS-R004 | Unauthorized Access | Runtime | HIGH |
| 14 | MCS-R005 | Sandbox Escape Risk | Runtime | CRITICAL |
| 15 | MCS-M001 | Vulnerable Version Rollback | Maintenance | MEDIUM |
| 16 | MCS-M002 | Privilege Persistence | Maintenance | MEDIUM |
| 17 | MCS-M003 | Configuration Drift | Maintenance | LOW |

## CLI

```bash
mcp-sentinel scan <TARGET>       # Scan an MCP server
  --phase <phase>                # Filter by lifecycle phase
  --severity <level>             # Minimum severity
  -o <console|json|html|pdf|sarif>
  -f <output_file>
  --fail-on <level>              # Exit 1 if findings >= level

mcp-sentinel baseline <TARGET>   # Create baseline snapshot
mcp-sentinel diff <BASE> <TGT>   # Compare against baseline
mcp-sentinel list-rules          # List all rules
mcp-sentinel version
```

Alias: `mcp-scan` = `mcp-sentinel`

## Real-World Results

Scanned the official **MCP Python SDK** ([23K+ stars, 190M+ downloads](https://github.com/modelcontextprotocol/python-sdk)):

```
Files: 109 | Rules: 7 | Findings: 16 | Duration: 2.0s

[CRITICAL] MCS-C005  Command Injection
  cli/cli.py:48 — subprocess.run(..., shell=True)

[CRITICAL] MCS-R005  Sandbox Escape Risk
  cli/cli.py:278 — subprocess.run() without cwd/env restriction

[CRITICAL] MCS-R001  Indirect Prompt Injection
  server/fastmcp/types.py — to_image_content() returns raw data to LLM

[HIGH] MCS-R004  Unauthorized Access
  cli/claude.py — Path() without traversal check
```

## Output Formats

| Format | Use |
|--------|-----|
| Console | Rich-colored terminal output |
| JSON | Machine-readable, CI/CD |
| HTML | Browser view with CSS |
| PDF | Formal report |
| SARIF 2.1.0 | GitHub Code Scanning |

## References

## Known Limitations

- **M003 Configuration Drift**: full drift detection requires a baseline snapshot (use `mcp-sentinel baseline` + `mcp-sentinel diff`).

## References

- HUST Security PRIDE: [arXiv:2503.23278](https://arxiv.org/abs/2503.23278)
- OWASP LLM Top 10 (2025) & Agentic Top 10
- SARIF 2.1.0

---

<a name="中文"></a>
## 快速开始

```bash
pip install mcp-sentinel
# 或 Docker
docker compose up

mcp-sentinel scan ./my-mcp-server -o console
```

## 检测能力 — 17 条规则

| # | 规则 ID | 威胁类型 | 阶段 | 严重度 |
|---|---------|---------|------|--------|
| 1 | MCS-C001 | 命名空间仿冒 | 创建 | HIGH |
| 2 | MCS-C002 | 工具名冲突 | 创建 | MEDIUM |
| 3 | MCS-C003 | 偏好操纵 | 创建 | HIGH |
| 4 | MCS-C004 | 工具投毒 | 创建 | CRITICAL |
| 5 | MCS-C005 | 代码注入/后门 | 创建 | CRITICAL |
| 6 | MCS-C006 | 安装程序完整性 | 创建 | HIGH |
| 7 | MCS-D001 | 凭证明文存储 | 部署 | CRITICAL |
| 8 | MCS-D002 | 沙箱配置缺陷 | 部署 | HIGH |
| 9 | MCS-D003 | 安装来源不可信 | 部署 | MEDIUM |
| 10 | MCS-R001 | 间接 Prompt 注入 | 运行 | CRITICAL |
| 11 | MCS-R002 | 跨服务器阴影攻击 | 运行 | HIGH |
| 12 | MCS-R003 | 工具链滥用 | 运行 | HIGH |
| 13 | MCS-R004 | 未授权访问 | 运行 | HIGH |
| 14 | MCS-R005 | 沙箱逃逸风险 | 运行 | CRITICAL |
| 15 | MCS-M001 | 易受攻击版本回退 | 维护 | MEDIUM |
| 16 | MCS-M002 | 更新后权限持久化 | 维护 | MEDIUM |
| 17 | MCS-M003 | 配置漂移 | 维护 | LOW |

## CLI 命令

```bash
mcp-sentinel scan <TARGET>       # 扫描 MCP Server
  --phase <phase>                # 按阶段过滤
  --severity <level>             # 最低严重度
  -o <console|json|html|pdf|sarif>
  -f <output_file>
  --fail-on <level>              # 发现时 exit 1

mcp-sentinel baseline <TARGET>   # 创建基线快照
mcp-sentinel diff <BASE> <TGT>   # 基线对比
mcp-sentinel list-rules          # 列出所有规则
mcp-sentinel version
```

别名：`mcp-scan` = `mcp-sentinel`

## 真实扫描结果

对官方 **MCP Python SDK**（[23K+ stars, 1.9 亿下载](https://github.com/modelcontextprotocol/python-sdk)）的扫描结果：

```
文件: 109 | 规则: 7 | 发现: 16 | 耗时: 2.0s

[CRITICAL] MCS-C005  代码注入
  cli/cli.py:48 — subprocess.run(..., shell=True)

[CRITICAL] MCS-R005  沙箱逃逸风险
  cli/cli.py:278 — subprocess.run() 无 cwd/env 限制

[CRITICAL] MCS-R001  间接 Prompt 注入
  server/fastmcp/types.py — to_image_content() 返回未净化数据

[HIGH] MCS-R004  未授权访问
  cli/claude.py — Path() 无路径穿越检查
```

## 参考

- 华中科技大学 Security PRIDE: [arXiv:2503.23278](https://arxiv.org/abs/2503.23278)
- OWASP LLM Top 10 (2025) / Agentic Top 10
- SARIF 2.1.0

---

**License**: MIT
