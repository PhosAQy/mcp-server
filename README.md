# @demox-site/mcp-server

[![npm version](https://badge.fury.io/js/%40demox-site%2Fmcp-server.svg)](https://www.npmjs.com/package/@demox-site/mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Demox MCP Server - 通过 AI 部署静态网站到 Demox 平台

## 📖 目录

- [什么是 MCP？](#什么是-mcp)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [配置步骤](#配置步骤)
- [可用工具](#可用工具)
- [使用示例](#使用示例)
- [常见问题](#常见问题)
- [技术支持](#技术支持)

---

## 什么是 MCP？

MCP (Model Context Protocol) 是 AI 助手与工具之间的标准化协议，允许 AI 工具（如 Claude Code、Cursor）安全地调用外部服务。

## 功能特性

- 🚀 **一键部署**: 部署静态网站到 Demox 平台
- 📦 **自动打包**: 支持直接传入目录，自动打包成 ZIP
- ☁️ **云存储上传**: 使用 CloudBase Storage，支持大文件（最大 500MB）
- 🔐 **自动登录**: Token 过期时自动触发登录流程
- 💻 **AI 集成**: 与 Claude Code、Cursor 等 MCP 客户端无缝集成
- 📋 **网站管理**: 查看、删除、管理已部署的网站

---

## 快速开始

### 安装 MCP Server

**在 AI 工具配置中使用 npx（推荐）**

无需安装，直接在配置文件中使用：

```json
{
  "mcpServers": {
    "demox": {
      "command": "npx",
      "args": ["-y", "@demox-site/mcp-server"]
    }
  }
}
```

配置后重启 AI 工具，首次使用时会自动打开浏览器登录。

---

## 配置步骤

### 1. 配置 AI 工具

根据您使用的 AI 工具，将以下配置导入到相应位置：

#### Claude Desktop / Claude Code

**macOS**:
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows**:
```bash
%APPDATA%/Claude/claude_desktop_config.json
```

**Linux**:
```bash
~/.config/Claude/claude_desktop_config.json
```

配置示例：
```json
{
  "mcpServers": {
    "demox": {
      "command": "npx",
      "args": ["-y", "@demox-site/mcp-server"]
    }
  }
}
```

#### Cursor AI

**macOS / Linux**: `~/.cursor/mcp.json`
**Windows**: `%APPDATA%/Cursor/mcp.json`

#### Cline (VS Code 插件)

所有平台: `~/.cline/mcp.json`

#### Continue (VS Code 插件)

所有平台: `~/.continue/mcp.json`

### 2. 重启 AI 工具

配置完成后，重启您的 AI 工具。

### 3. 首次使用

首次调用 MCP 工具时，会自动打开浏览器登录。

登录成功后，凭证会保存在本地（`~/.demox/token.json`），Access Token 有效期 5 分钟，Refresh Token 有效期 30 天。

**自动登录**：Token 过期时会自动打开浏览器，无需手动运行登录命令。

---

## 可用工具

### deploy_website

部署静态网站到 Demox 平台。

**参数**:
- `zipFile` (string, **必需**): ZIP 文件路径或目录路径
  - 支持本地 ZIP 文件：`./dist.zip`
  - 支持本地目录（自动打包）：`./dist`
  - 支持 HTTPS URL（必须 .zip 结尾）：`https://example.com/file.zip`
- `fileName` (string, 可选): 网站名称，用于标识和展示
- `websiteId` (string, 可选): 网站 ID，更新现有网站时提供

**限制**:
- 仅支持 ZIP 文件格式
- 最大文件大小：500MB
- 不支持 base64 编码内容

### list_websites

获取用户在 Demox 平台上的所有网站列表。

**返回信息**:
- 网站 ID
- 网站名称
- 访问 URL
- 创建时间

### get_website

获取指定网站的详细信息。

**参数**:
- `websiteId` (string, **必需**): 要查询的网站 ID

### delete_website

删除指定的网站及其所有文件。

**参数**:
- `websiteId` (string, **必需**): 要删除的网站 ID

**⚠️ 注意**: 此操作不可撤销

---

## 使用示例

### 在 Claude Desktop 中

```
用户: 部署 dist 目录到 Demox

Claude: 好的，我来帮您部署 dist 目录。

[检测到目录，自动打包成 ZIP...]
[正在上传文件到 CloudBase Storage...]
[文件上传成功]

✅ 网站部署成功！
网站名称: dist
网站 ID: ABC12345
访问地址: https://abc12345.demox.site
```

### 在 Cursor 中

```
# 在 Cursor 的 Chat 中输入

部署当前项目到 Demox

# Cursor 会自动：
# 1. 检测到项目目录（如 ./dist）
# 2. 自动打包成 ZIP
# 3. 上传到云存储
# 4. 调用云函数部署
# 5. 返回访问链接
```

### 示例对话

**场景 1：部署新网站**

```
用户: 把我的 react 项目的 build 目录部署到 Demox

Claude: 我来帮您部署 React 项目的 build 目录。

[正在打包目录 ./build...]
[文件大小: 2.3MB]

✅ 网站部署成功！
网站名称: build
网站 ID: XYZ67890
访问地址: https://xyz67890.demox.site

您现在可以访问上述地址查看您的网站了。
```

**场景 2：更新现有网站**

```
用户: 更新网站 ABC12345

Claude: 我来帮您更新网站 ABC12345。

[文件大小: 2.5MB]

✅ 网站部署成功！
网站名称: my-project
网站 ID: ABC12345
访问地址: https://abc12345.demox.site
```

**场景 3：查看所有网站**

```
用户: 显示我部署的所有网站

Claude: 我来帮您查看所有已部署的网站。

📋 您的网站列表（共 3 个）

1. **my-portfolio**
   - ID: `ABC12345`
   - URL: https://abc12345.demox.site
   - 创建时间: 2026-01-20 14:30:00

2. **blog**
   - ID: `XYZ67890`
   - URL: https://xyz67890.demox.site
   - 创建时间: 2026-01-21 09:15:00

3. **docs**
   - ID: `DEF24680`
   - URL: https://def24680.demox.site
   - 创建时间: 2026-01-22 16:45:00
```

---

## 常见问题

### Token 过期怎么办？

**自动登录**：系统会在 Token 过期时自动打开浏览器登录，无需手动操作。

登录成功后会自动重试失败的工具调用。

### 支持哪些文件格式？

**仅支持 ZIP 文件或目录**：
- ✅ 本地 ZIP 文件：`./dist.zip`
- ✅ 本地目录：`./dist`（自动打包成 ZIP）
- ✅ HTTPS URL：`https://example.com/file.zip`（必须 .zip 结尾）
- ❌ 其他压缩格式（tar.gz, rar 等）
- ❌ Base64 编码内容

### 最大文件大小限制？

**500MB**

大文件会被流式传输，不会占用大量内存。

### 如何撤销授权？

删除本地 Token 文件：

```bash
rm ~/.demox/token.json
```

下次使用时会自动触发登录。

### 支持哪些 AI 工具？

所有支持 MCP 协议的 AI 工具：
- Claude Desktop / Claude Code
- Cursor AI
- Cline (VS Code 插件)
- Continue (VS Code 插件)
- 其他 MCP 客户端

### 多台设备可以使用吗？

可以。每台设备需要单独登录，互不影响。

### 如何查看调试日志？

MCP Server 的日志会输出到 stderr，可以在 AI 工具的日志中查看。

---

## 技术细节

### 文件上传流程

```
输入（文件/目录/URL）
    ↓
转换为本地 ZIP 文件
    ↓
检查文件大小（最大 500MB）
    ↓
上传到 CloudBase Storage（流式传输）
    ↓
获取 fileId
    ↓
云函数从 Storage 下载并部署
```

### 安全性

- **OAuth 2.0 认证**: 使用标准的 OAuth 2.0 协议
- **Token 加密存储**: 本地存储的 Token 包含 Refresh Token
- **自动刷新**: Access Token 过期后自动刷新
- **作用域限制**: Token 仅包含必要的权限范围

---

## 技术支持

- 📖 **文档**: https://demox.site
- 🐛 **Issues**: https://github.com/demox-site/mcp-server/issues
- 📧 **邮箱**: support@demox.site

---

## 开发

### 本地开发

```bash
# 克隆项目
git clone https://github.com/demox-site/mcp-server.git
cd mcp-server

# 安装依赖
npm install

# 开发模式
npm run dev

# 构建
npm run build

# 测试 MCP Server
node dist/index.js
```

### 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 许可证

[MIT License](LICENSE)

---

Made with ❤️ by Demox Team
