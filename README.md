# MCP Sentinel

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2503.23278-b31b1b.svg)](https://arxiv.org/abs/2503.23278)

> **MCP 生态的安全扫描工具** — 类似 sqlmap/nmap，轻量、开源、开发者标配。

MCP Sentinel 覆盖 MCP Server 生命周期的 **4 个阶段**（创建→部署→运行→维护），检测 **17 种威胁类型**，基于华中科技大学 Security PRIDE 团队的首篇 MCP 安全论文（arXiv:2503.23278）。

---

## 快速开始

```bash
# 安装
pip install mcp-sentinel

# 或 Docker（推荐）
docker compose up

# 扫描
mcp-sentinel scan ./my-mcp-server -o console
mcp-scan ./my-mcp-server -o json -f report.json
```

---

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

---

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
mcp-sentinel version             # 版本信息
```

别名：`mcp-scan` = `mcp-sentinel`

---

## 输出格式

| 格式 | 用途 |
|------|------|
| Console | 终端彩色输出（Rich） |
| JSON | 机器可读，CI/CD 集成 |
| HTML | 浏览器查看，自带 CSS |
| PDF | 正式报告 |
| SARIF 2.1.0 | GitHub Code Scanning 上传 |

---

## 项目结构

```
mcp-sentinel/
├── src/mcp_sentinel/
│   ├── cli.py              # CLI 入口
│   ├── core/               # 引擎、注册表、类型
│   ├── rules/              # 17 条检测规则
│   ├── analyzers/          # AST/配置/清单分析器
│   ├── connectors/         # STDIO/SSE/源码连接器
│   ├── reporters/          # 5 种输出格式
│   └── utils/              # AST/相似度/熵/hash/OWASP
├── tests/                  # 测试 + PoC 漏洞服务器
├── data/                   # 已知 MCP 服务器白名单
├── Dockerfile
└── docker-compose.yml
```

---

## 参考

- HUST Security PRIDE: [arXiv:2503.23278](https://arxiv.org/abs/2503.23278)
- OWASP LLM Top 10 (2025)
- OWASP Agentic Top 10
- SARIF 2.1.0 Specification

---

**License**: MIT
