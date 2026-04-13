# 快速开始

[English](../QUICKSTART.md) | 中文

这份文档帮助你在几分钟内完成插件构建、安装、启动和基础验证。

## 前置要求

- Windows 10/11
- 已安装 x64dbg 或 x32dbg
- Visual Studio 2022
- CMake
- vcpkg

## 安装方式

### 方式一：使用已编译版本

1. 获取插件文件：
   - `x64dbg_mcp.dp64` 用于 x64dbg
   - `x32dbg_mcp.dp32` 用于 x32dbg
2. 复制到插件目录：
   - x64dbg: `x64dbg\x64\plugins\`
   - x32dbg: `x64dbg\x32\plugins\`
3. 创建插件配置目录并复制配置文件：
   - `plugins/x64dbg-mcp/config.json`
   - 或 `plugins/x32dbg-mcp/config.json`
4. 重启调试器

### 方式二：从源码构建

```powershell
git clone https://github.com/SetsunaYukiOvO/x64dbg-mcp.git
cd x64dbg-mcp

# 推荐：同时构建 x64 与 x86
.\build.bat

# 只构建 x64
.\build.bat --x64-only

# 只构建 x86
.\build.bat --x86-only
```

构建输出：

- `dist\x64dbg_mcp.dp64`
- `dist\x32dbg_mcp.dp32`

## 启动插件服务

1. 打开 x64dbg 或 x32dbg
2. 加载目标程序开始调试
3. 在插件菜单中启动 `MCP HTTP Server`
4. 默认监听：

```text
http://127.0.0.1:3000
```

## 使用 Python 客户端

仓库根目录提供了与 `x64dbg-example.py` 风格一致的客户端：

```powershell
python x64dbg-mcp.py ListServerTools
python x64dbg-mcp.py IsDebugActive
python x64dbg-mcp.py RegisterGet rip
python x64dbg-mcp.py GetMemoryMap
```

这个脚本当前还支持：

- MCP 初始化与原始 RPC 调用
- `tools/list` / `resources/list` / `prompts/list`
- `resources/read` / `prompts/get`
- SSE 事件订阅
- 与插件真实能力对齐的 example 风格 wrapper

## 新增 native 接口快速验证

如果你已经使用最新插件版本，并且插件目录里的 `config.json` 已包含 `native.*` 白名单，可以直接执行：

```powershell
# Xref
python x64dbg-mcp.py XrefGet 0x401000
python x64dbg-mcp.py XrefCount 0x401000

# Patch
python x64dbg-mcp.py GetPatchList
python x64dbg-mcp.py GetPatchAt 0x401000

# Native 数据
python x64dbg-mcp.py EnumHandles
python x64dbg-mcp.py EnumTcpConnections

# 页保护
python x64dbg-mcp.py SetPageRights 0x401000 rx
```

预期行为：

- 没有 xref 时，`XrefGet` 返回空数组，`XrefCount` 返回 `0`
- 没有 patch 时，`GetPatchList` 返回空列表
- 查询无 patch 地址时，`GetPatchAt` 返回结构化 not found 错误
- `EnumHandles` 返回真实 handle 列表
- 没有 TCP 连接时，`EnumTcpConnections` 返回空列表

## 最小 MCP 调用流程

如果你自己写客户端，最小 MCP 会话通常是：

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. `tools/call`

## 常见问题

### 新增 native 接口调用失败

确认插件配置目录中的 `config.json` 包含：

```json
"native.*"
```

### 构建失败

优先使用 `build.bat`，不要直接裸跑 `cmake`，因为脚本会自动处理 vcpkg 依赖。

### 服务连接失败

- 检查插件是否已启动 MCP HTTP Server
- 检查端口 3000 是否可访问
- 检查是否连接到了正确地址

## 下一步

如果你需要更完整的功能说明与新增能力对比，请查看：

- [README_CN.md](README_CN.md)
