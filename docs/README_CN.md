# x64dbg MCP 服务端插件

[English](../README.md) | 中文

这是一个面向 x64dbg 和 x32dbg 的 Model Context Protocol (MCP) 服务端实现。插件通过 JSON-RPC 2.0 接口对外提供调试能力，使外部程序、脚本和 AI Agent 可以用统一方式驱动调试器。

当前版本同时支持 x64 与 x86 两种架构。

## 功能特性

- 完整 MCP 能力
  - Tools: 76 个可调用调试工具
  - Resources: 15 个上下文资源
  - Prompts: 10 个调试工作流模板
- 标准 JSON-RPC 2.0 协议
- HTTP + SSE 通信方式
- 基于权限白名单的访问控制
- 可扩展的处理器、资源与提示词体系

## 当前插件能力总览

当前插件已经覆盖以下能力类别：

- 调试控制
  - 查询状态、运行、暂停、单步、步过、步出、运行到指定地址、重启、停止
- 寄存器
  - 单寄存器读取、批量读取、全寄存器快照、寄存器写入
- 内存
  - 读、写、搜索、枚举、分配、释放、区域信息查询、页保护修改
- 断点
  - 设置、删除、启用、禁用、切换、条件、日志、命中计数重置
- 反汇编与符号
  - 按地址、范围、函数反汇编，符号解析，注释与标签操作
- 线程与栈
  - 线程枚举、线程切换、挂起、恢复、栈回溯、栈帧读取
- Dump 与脱壳
  - 模块 dump、内存区域 dump、可 dump 区域分析、OEP 检测、导入修复、PE 重建
- 脚本与上下文
  - x64dbg 命令执行、批量脚本、上下文快照捕获与比较
- 原生 x64dbg 数据
  - xref 计数与列表、patch 列表与单点查询、handle 枚举、TCP 连接枚举

这些能力既可以通过插件暴露的 MCP tools 调用，也可以通过 `x64dbg-mcp.py` 中与 `x64dbg-example.py` 风格对齐的 wrapper 调用。

## Python 客户端能力总览

仓库中的 `x64dbg-mcp.py` 现在不仅是一个示例脚本，也已经是一个可直接使用的 MCP 客户端，当前具备以下能力：

- **直接 MCP 会话能力**
  - 健康检查
  - `initialize` 握手
  - 原始 JSON-RPC 调用
  - SSE 事件订阅
- **MCP 元数据访问**
  - `tools/list`
  - `resources/list`
  - `resources/templates/list`
  - `prompts/list`
- **高层 MCP 操作**
  - `tools/call`
  - `resources/read`
  - `prompts/get`
- **example 风格 wrapper 调用**
  - 与 `x64dbg-example.py` 风格对齐
  - 可以通过脚本入口直接调用
  - 可通过 `ListServerTools` 发现可用 wrapper
- **与插件新增 native 能力对齐的 wrapper**
  - `XrefGet`
  - `XrefCount`
  - `GetPatchList`
  - `GetPatchAt`
  - `EnumHandles`
  - `EnumTcpConnections`
  - `SetPageRights`
- **兼容性行为**
  - 优先调用插件原生 MCP 方法
  - 仅在少数保留兼容策略的操作上按需回退到脚本命令

## 本次相比之前新增的功能

这次补齐并验证了以下插件真实能力：

- 原生 xref 接口
  - `native.get_xrefs`
  - `native.get_xref_count`
  - `XrefGet` 在地址没有交叉引用时返回空数组，而不是报错
- 原生 patch 查询
  - `native.list_patches`
  - `native.get_patch_at`
- 原生系统对象枚举
  - `native.enum_handles`
  - `native.enum_tcp_connections`
- 原生内存页保护控制
  - `memory.set_protection`
  - `SetPageRights` 优先走原生 MCP 方法，失败时才回退到脚本命令
- 权限白名单更新
  - 默认 `allowed_methods` 新增 `native.*`
- client / plugin 对齐
  - `x64dbg-mcp.py` 只暴露插件真实承载的功能
  - example 风格 wrapper 与插件工具能力一一对应
  - Python 脚本已经从最小示例升级为完整可用的 MCP client

## 运行时验证结果

当前版本已经在真实运行中的 x64dbg 环境中完成验证：

- `XrefGet 0x401000` 返回空引用列表
- `XrefCount 0x401000` 返回 `0`
- `GetPatchList` 在没有 patch 时返回空列表
- `GetPatchAt 0x401000` 在没有 patch 时返回结构化 not found 错误
- `EnumHandles` 能返回被调试进程的真实 handle 列表
- `EnumTcpConnections` 在没有连接时返回空列表
- `RegisterGet rip` 等原有 example 风格接口继续可用
- `x64dbg-mcp.py` 已经可以端到端驱动并验证这些新增 native 接口
- `build.bat` 已成功构建 x64 与 x86 版本

## v1.0.3 既有更新

- 通用化脱壳逻辑
  - 扩展 OEP/转移识别模式
  - 移除只针对 UPX 的硬编码路径
- Dump/脱壳稳定性修复
  - 修复假成功 dump
  - 修复导入回退导致的布局损坏
  - 提升 `debug_pause` 可靠性
  - 统一 `dump_auto_unpack` 默认 `max_iterations`
- 运行态恢复能力
  - 为 dump 与 OEP 检测增强暂停状态恢复
  - 改进运行中自动脱壳的上下文恢复路径

## 构建

### 前置要求

- Windows 10/11
- Visual Studio 2022
- CMake
- vcpkg
- Git

### 推荐构建方式

使用仓库根目录的 `build.bat`：

```powershell
# 同时构建 x64 与 x86
.\build.bat

# 只构建 x64
.\build.bat --x64-only

# 只构建 x86
.\build.bat --x86-only

# 清理后重建
.\build.bat --clean
```

输出文件位于 `dist/`：

- `dist\x64dbg_mcp.dp64`
- `dist\x32dbg_mcp.dp32`

## 安装

将插件复制到调试器插件目录，并复制配置文件：

```powershell
# x64dbg
copy dist\x64dbg_mcp.dp64 <x64dbg-path>\x64\plugins\
mkdir <x64dbg-path>\x64\plugins\x64dbg-mcp
copy config.json <x64dbg-path>\x64\plugins\x64dbg-mcp\

# x32dbg
copy dist\x32dbg_mcp.dp32 <x64dbg-path>\x32\plugins\
mkdir <x64dbg-path>\x32\plugins\x32dbg-mcp
copy config.json <x64dbg-path>\x32\plugins\x32dbg-mcp\
```

如果要使用新增的原生接口，请确认插件目录中的 `config.json` 里 `permissions.allowed_methods` 包含 `native.*`。

## 架构

插件主要分为四层：

1. 通信层：HTTP 服务与 SSE
2. 协议层：JSON-RPC / MCP 解析、校验、分发
3. 业务层：调试控制、寄存器、内存、符号、dump 等能力
4. 插件层：x64dbg 回调、事件、菜单与生命周期管理

## 故障排查

### 插件加载成功但新接口调用报 `Method not allowed`

请检查插件实际运行目录中的配置文件：

- `plugins/x64dbg-mcp/config.json`

确认其中 `permissions.allowed_methods` 包含：

```json
"native.*"
```

### 构建失败

优先使用 `build.bat`，因为它会自动接入 vcpkg toolchain 并处理依赖。

### 无法连接到服务端

- 确认已在插件菜单里启动 MCP HTTP Server
- 确认监听地址与端口配置正确
- 确认客户端连接的是 `http://127.0.0.1:3000`

## 版本历史

完整历史请查看：

- [CHANGELOG_CN.md](../CHANGELOG_CN.md)
