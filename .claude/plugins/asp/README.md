# ASP Platform Claude Code Plugin

Agentic SOC Platform 的 Claude Code 集成插件。

## 安装和配置

### 1. 配置 MCP 服务器地址

编辑 `.claude/asp.local.md` 文件，设置你的 MCP 服务器 URL：

```yaml
---
ASP_MCP_URL: "http://localhost:7001/a670db8a1d2811f1/sse"
---
```

### 2. 启动 MCP 服务器

```bash
python PLUGINS/MCP/mcpserver.py
```

服务器启动后会显示 MCP URL，将其复制到 `asp.local.md` 配置文件中。

### 3. 加载插件

在 Claude Code 中，插件会自动从 `.claude/plugins/` 目录加载。

如果插件没有自动加载，可以尝试：
- 重启 Claude Code
- 检查插件目录结构是否正确
- 查看 Claude Code 日志确认插件加载状态

## 可用命令

### /asp-case <id>
查询安全案例详情

```bash
/asp-case C-2024-001
/asp-case 2101ff98-f52e-4f38-b107-fe53f7f77b5c
```

### /asp-case-list
列出安全案例

```bash
/asp-case-list
/asp-case-list status=New
/asp-case-list severity=High limit=20
```

### /asp-case-create
创建新的安全案例

```bash
/asp-case-create title="Suspicious Login Activity" severity=High description="Multiple failed login attempts detected"
```

### /asp-case-update
更新现有案例

```bash
/asp-case-update C-2024-001 status="In Progress"
/asp-case-update C-2024-001 severity=Critical title="Updated Title"
```

## SOC Analyst Agent

当你提到以下关键词时，SOC Analyst Agent 会自动激活：
- 安全事件
- 案例分析
- SOC
- 威胁分析
- incident
- threat
- security case

示例：
```
请帮我分析案例 C-2024-001 的安全威胁
```

## Case Analysis Skill

使用 `/case-analysis` 技能进行深度分析：
```
/case-analysis C-2024-001
```

## MCP 工具

插件通过 MCP 协议提供以下工具，可以在对话中直接使用：

- `get_case_by_case_id(case_id)` - 通过 case ID 查询案例
- `get_case_by_rowid(rowid)` - 通过 rowid 查询案例
- `list_cases(status, severity, limit)` - 列出案例
- `create_case(title, severity, description, status)` - 创建案例
- `update_case(case_id, title, severity, status, description)` - 更新案例

## 测试插件

### 测试 MCP 连接

在 Claude Code 中输入：
```
请使用 list_cases 工具列出所有案例
```

如果 MCP 连接正常，Claude 会调用工具并返回案例列表。

### 测试命令

```
/asp-case-list
```

### 测试 Agent

```
请分析最近的安全事件
```

## 故障排查

### 插件未加载
- 检查 `.claude/plugins/asp/plugin.json` 是否存在
- 确认目录结构正确
- 重启 Claude Code

### MCP 连接失败
- 确认 MCP 服务器正在运行
- 检查 `.claude/asp.local.md` 中的 URL 是否正确
- 确认端口 7001 未被占用
- 查看 MCP 服务器日志

### 工具调用失败
- 确认 Django 环境已正确配置
- 检查数据库连接
- 查看 MCP 服务器错误日志

## 目录结构

```
.claude/
├── asp.local.md                    # MCP 服务器配置
└── plugins/
    └── asp/
        ├── plugin.json             # 插件清单
        ├── .mcp.json               # MCP 配置
        ├── commands/               # 命令定义
        │   ├── asp-case.md
        │   ├── asp-case-list.md
        │   ├── asp-case-create.md
        │   └── asp-case-update.md
        ├── agents/                 # Agent 定义
        │   └── soc-analyst.md
        ├── skills/                 # Skill 定义
        │   └── case-analysis.md
        └── hooks/                  # Hook 脚本
            ├── case-context.sh     # Linux/Mac
            └── case-context.ps1    # Windows
```

## 开发和扩展

### 添加新的 MCP 工具

1. 在 `PLUGINS/MCP/llmfunc.py` 中定义函数
2. 在 `PLUGINS/MCP/mcpserver.py` 中注册工具
3. 重启 MCP 服务器

### 添加新命令

在 `.claude/plugins/asp/commands/` 目录创建新的 `.md` 文件：

```markdown
---
name: your-command
description: Command description
args:
  - name: arg1
    description: Argument description
    required: true
---

Command implementation...
```

### 添加新 Agent

在 `.claude/plugins/asp/agents/` 目录创建新的 `.md` 文件。

## 版本信息

- Version: 0.1.0
- Author: ASP Team
- License: MIT
