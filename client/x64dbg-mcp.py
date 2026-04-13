#!/usr/bin/env python3
"""x64dbg MCP HTTP client.

This script talks to the x64dbg-mcp plugin over HTTP JSON-RPC and SSE.
It mirrors the server implementation in this repository:
  - GET  /           health check
  - GET  /sse        event stream
  - POST /rpc        JSON-RPC requests

Examples:
  python x64dbg-mcp.py health
  python x64dbg-mcp.py init
  python x64dbg-mcp.py tools
  python x64dbg-mcp.py call debug_get_state
  python x64dbg-mcp.py call memory_read --args "{\"address\":\"0x401000\",\"size\":32}"
  python x64dbg-mcp.py resources
  python x64dbg-mcp.py read x64dbg://registers
  python x64dbg-mcp.py prompts
  python x64dbg-mcp.py prompt crash_analysis --args "{\"exception_code\":\"0xC0000005\"}"
  python x64dbg-mcp.py events
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Generator, List, Optional

from mcp.server.fastmcp import FastMCP


class MCPClientError(RuntimeError):
    """Raised when the MCP server returns an error or is unreachable."""


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 3000
DEFAULT_TIMEOUT = 30.0
DEFAULT_BASE_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
DEFAULT_X64DBG_SERVER = f"{DEFAULT_BASE_URL}/"

mcp = FastMCP("x64dbg-mcp")


def _resolve_connection_defaults() -> tuple[str, int]:
    env_url = os.getenv("X64DBG_MCP_URL") or os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http://"):
        trimmed = env_url[len("http://") :].rstrip("/")
        if ":" in trimmed:
            host, port_text = trimmed.rsplit(":", 1)
            try:
                return host, int(port_text)
            except ValueError:
                pass
    return DEFAULT_HOST, DEFAULT_PORT


def _resolve_server_url_from_args_env() -> str:
    env_url = os.getenv("X64DBG_URL") or os.getenv("X64DBG_MCP_URL")
    if env_url and env_url.startswith("http"):
        return env_url
    if len(sys.argv) > 1 and isinstance(sys.argv[1], str) and sys.argv[1].startswith("http"):
        return sys.argv[1]
    return DEFAULT_X64DBG_SERVER


class X64DbgMCPClient:
    """Small HTTP client for the x64dbg MCP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 3000, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        data = None
        request_headers = {"User-Agent": "x64dbg-mcp-python-client/1.0"}
        if headers:
            request_headers.update(headers)

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout if timeout is None else timeout) as resp:
                body = resp.read()
                if not body:
                    return None
                charset = resp.headers.get_content_charset("utf-8")
                return json.loads(body.decode(charset))
        except urllib.error.HTTPError as exc:
            body = exc.read()
            details = body.decode("utf-8", errors="replace") if body else exc.reason
            raise MCPClientError(f"HTTP {exc.code}: {details}") from exc
        except urllib.error.URLError as exc:
            raise MCPClientError(f"Connection failed: {exc.reason}") from exc

    def health(self) -> Dict[str, Any]:
        result = self._request("GET", "/", timeout=5)
        if not isinstance(result, dict):
            raise MCPClientError("Unexpected health-check response")
        return result

    def call(self, rpc_method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": rpc_method,
            "params": params or {},
        }
        response = self._request("POST", "/rpc", payload=payload)
        if response is None:
            raise MCPClientError("Empty response from server")
        if "error" in response:
            error = response["error"]
            code = error.get("code", "unknown")
            message = error.get("message", "Unknown error")
            raise MCPClientError(f"RPC error {code}: {message}")
        return response.get("result")

    def notify(self, rpc_method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": rpc_method,
            "params": params or {},
        }
        self._request("POST", "/rpc", payload=payload)

    def initialize(self, send_initialized: bool = True) -> Dict[str, Any]:
        result = self.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "x64dbg-mcp.py",
                    "version": "1.0.0",
                },
            },
        )
        if send_initialized:
            self.notify("notifications/initialized")
        if not isinstance(result, dict):
            raise MCPClientError("Unexpected initialize response")
        return result

    def list_tools(self) -> Dict[str, Any]:
        return self.call("tools/list")

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = self.call(
            "tools/call",
            {
                "name": name,
                "arguments": arguments or {},
            },
        )
        if not isinstance(result, dict):
            raise MCPClientError("Unexpected tool result")
        return result

    def list_resources(self) -> Dict[str, Any]:
        return self.call("resources/list")

    def list_resource_templates(self) -> Dict[str, Any]:
        return self.call("resources/templates/list")

    def read_resource(self, uri: str) -> Dict[str, Any]:
        result = self.call("resources/read", {"uri": uri})
        if not isinstance(result, dict):
            raise MCPClientError("Unexpected resource result")
        return result

    def list_prompts(self) -> Dict[str, Any]:
        return self.call("prompts/list")

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = self.call(
            "prompts/get",
            {
                "name": name,
                "arguments": arguments or {},
            },
        )
        if not isinstance(result, dict):
            raise MCPClientError("Unexpected prompt result")
        return result

    def iter_sse_events(self, include_ping: bool = False) -> Generator[Dict[str, Any], None, None]:
        req = urllib.request.Request(
            f"{self.base_url}/sse",
            headers={
                "Accept": "text/event-stream",
                "Cache-Control": "no-cache",
                "User-Agent": "x64dbg-mcp-python-client/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=None) as resp:
                event_name = "message"
                data_lines = []

                while True:
                    raw_line = resp.readline()
                    if not raw_line:
                        break

                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line:
                        if not data_lines:
                            event_name = "message"
                            continue

                        data = "\n".join(data_lines)
                        data_lines = []
                        if event_name == "ping" and not include_ping:
                            event_name = "message"
                            continue

                        parsed: Any
                        try:
                            parsed = json.loads(data)
                        except json.JSONDecodeError:
                            parsed = data

                        yield {"event": event_name, "data": parsed}
                        event_name = "message"
                        continue

                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip() or "message"
                        continue
                    if line.startswith("data:"):
                        data_lines.append(line[5:].lstrip())
        except urllib.error.URLError as exc:
            raise MCPClientError(f"SSE connection failed: {exc.reason}") from exc


_DEFAULT_CLIENT_HOST, _DEFAULT_CLIENT_PORT = _resolve_connection_defaults()
_global_client = X64DbgMCPClient(_DEFAULT_CLIENT_HOST, _DEFAULT_CLIENT_PORT, DEFAULT_TIMEOUT)
x64dbg_server_url = f"http://{_DEFAULT_CLIENT_HOST}:{_DEFAULT_CLIENT_PORT}/"


def set_x64dbg_server_url(url: str) -> None:
    """Set the default MCP server URL used by wrapper functions."""
    global _global_client, x64dbg_server_url

    if not url.startswith("http://"):
        raise MCPClientError(f"Unsupported URL: {url}")

    trimmed = url[len("http://") :].rstrip("/")
    if ":" not in trimmed:
        raise MCPClientError(f"URL must include host and port: {url}")

    host, port_text = trimmed.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError as exc:
        raise MCPClientError(f"Invalid port in URL: {url}") from exc

    _global_client = X64DbgMCPClient(host=host, port=port, timeout=DEFAULT_TIMEOUT)
    x64dbg_server_url = f"http://{host}:{port}/"


def _default_client() -> X64DbgMCPClient:
    return _global_client


def _is_http_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _configure_client_from_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise MCPClientError(f"Unsupported URL scheme: {url}")
    if not parsed.hostname or not parsed.port:
        raise MCPClientError(f"URL must include host and port: {url}")
    set_x64dbg_server_url(f"http://{parsed.hostname}:{parsed.port}")


RESOURCE_SHORTCUTS = {
    "state": "debugger://state/current",
    "registers": "debugger://registers/all",
    "modules": "debugger://modules/list",
    "threads": "debugger://threads/list",
    "memory-map": "debugger://memory/map",
    "breakpoints": "debugger://breakpoints/all",
    "stack": "debugger://stack/trace",
}


PROMPT_SHORTCUTS = {
    "crash": "analyze-crash",
    "vuln": "find-vulnerability",
    "trace": "trace-function",
    "unpack": "unpack-binary",
    "algorithm": "reverse-algorithm",
    "compare": "compare-execution",
    "strings": "hunt-strings",
    "patch": "patch-code",
    "session": "debug-session",
    "api": "api-monitor",
}


COMMAND_ALIASES = {
    "ls-tools": "tools",
    "ls-res": "resources",
    "ls-prompts": "prompts",
    "res": "read",
    "tpl": "resource-templates",
    "wrapped-tools": "api-tools",
    "wrapped-call": "api-call",
}


PLUGIN_BACKED_TOOL_NAMES = {
    "Initialize",
    "ListServerTools",
    "ListResources",
    "ListResourceTemplates",
    "ListPrompts",
    "IsDebugging",
    "IsDebugActive",
    "GetRegisterDump",
    "RegisterGet",
    "RegisterSet",
    "MemoryRead",
    "MemoryWrite",
    "MemoryIsValidPtr",
    "MemoryGetProtect",
    "DebugRun",
    "DebugPause",
    "DebugStepIn",
    "DebugStepInto",
    "DebugStepOver",
    "DebugStepOut",
    "DebugStop",
    "GetModuleList",
    "QuerySymbols",
    "GetThreadList",
    "GetTebAddress",
    "MemoryBase",
    "SetPageRights",
    "StringGetAt",
    "XrefGet",
    "XrefCount",
    "GetMemoryMap",
    "MemoryRemoteAlloc",
    "MemoryRemoteFree",
    "GetBranchDestination",
    "GetCallStack",
    "GetBreakpointList",
    "DebugSetBreakpoint",
    "DebugDeleteBreakpoint",
    "LabelSet",
    "LabelGet",
    "LabelList",
    "CommentSet",
    "CommentGet",
    "SetHardwareBreakpoint",
    "DeleteHardwareBreakpoint",
    "DisasmGetInstructionRange",
    "AssemblerAssemble",
    "AssemblerAssembleMem",
    "StackPop",
    "StackPush",
    "StackPeek",
    "FlagGet",
    "FlagSet",
    "PatternFindMem",
    "MiscParseExpression",
    "MiscRemoteGetProcAddress",
    "StepInWithDisasm",
    "ExecCommand",
    "EnumTcpConnections",
    "GetPatchList",
    "GetPatchAt",
    "EnumHandles",
    "ReadResource",
    "GetPrompt",
}


def safe_rpc(method: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Call a raw MCP JSON-RPC method using the default client."""
    return _default_client().call(method, params or {})


def safe_get(endpoint: str, params: dict = None):
    """Compatibility shim matching x64dbg-example.py naming."""
    params = params or {}
    if endpoint == "IsDebugActive":
        return IsDebugActive()
    if endpoint == "Is_Debugging":
        return IsDebugging()
    if endpoint == "Register/Get":
        return RegisterGet(params.get("register", ""))
    if endpoint == "Register/Set":
        return RegisterSet(params.get("register", ""), params.get("value", ""))
    if endpoint == "Memory/Read":
        return MemoryRead(params.get("addr", ""), params.get("size", 0))
    if endpoint == "Memory/Write":
        return MemoryWrite(params.get("addr", ""), params.get("data", ""))
    if endpoint == "Memory/IsValidPtr":
        return MemoryIsValidPtr(params.get("addr", ""))
    if endpoint == "Memory/GetProtect":
        return MemoryGetProtect(params.get("addr", ""))
    if endpoint == "Debug/Run":
        return DebugRun()
    if endpoint == "Debug/Pause":
        return DebugPause()
    if endpoint == "Debug/Stop":
        return DebugStop()
    if endpoint == "Debug/StepIn":
        return DebugStepIn()
    if endpoint == "Debug/StepOver":
        return DebugStepOver()
    if endpoint == "Debug/StepOut":
        return DebugStepOut()
    if endpoint == "Debug/SetBreakpoint":
        return DebugSetBreakpoint(params.get("addr", ""))
    if endpoint == "Debug/DeleteBreakpoint":
        return DebugDeleteBreakpoint(params.get("addr", ""))
    if endpoint == "GetModuleList":
        return GetModuleList()
    if endpoint == "GetThreadList":
        return GetThreadList()
    if endpoint == "GetMemoryMap":
        return GetMemoryMap()
    if endpoint == "GetCallStack":
        return GetCallStack()
    if endpoint == "GetRegisterDump":
        return GetRegisterDump()
    return _unsupported("safe_get", f"Unsupported compatibility endpoint: {endpoint}")


def safe_post(endpoint: str, data: dict | str):
    """Compatibility shim matching x64dbg-example.py naming."""
    if isinstance(data, str):
        payload = {"raw": data}
    else:
        payload = data
    return _unsupported("safe_post", f"Unsupported compatibility endpoint: {endpoint}, data={payload}")


def safe_call_tool(name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Call an MCP tool using the default client and normalize text payloads."""
    return normalize_tool_result(_default_client().call_tool(name, arguments or {}))


def safe_read_resource(uri: str) -> Dict[str, Any]:
    """Read an MCP resource using the default client."""
    return _default_client().read_resource(uri)


def safe_get_prompt(name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get an MCP prompt using the default client."""
    return _default_client().get_prompt(name, arguments or {})


def _unsupported(name: str, detail: str) -> Dict[str, Any]:
    return {
        "error": f"{name} is not supported by the current x64dbg-mcp backend",
        "detail": detail,
    }


FLAG_BIT_MAP = {
    "CF": 0,
    "PF": 2,
    "AF": 4,
    "ZF": 6,
    "SF": 7,
    "TF": 8,
    "IF": 9,
    "DF": 10,
    "OF": 11,
}


def _extract_first_parsed_content(result: Dict[str, Any]) -> Any:
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                if "parsed" in item:
                    return item["parsed"]
                if "text" in item:
                    return item["text"]
    return result


def _stringify_tool_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _parse_int_like(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"Cannot parse integer from {value!r}")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _get_mcp_tools_registry() -> Dict[str, Callable[..., Any]]:
    """Discover exported wrapper functions following the x64dbg-example style."""
    registry: Dict[str, Callable[..., Any]] = {}
    for name, obj in globals().items():
        if not name or not name[0].isupper():
            continue
        if name not in PLUGIN_BACKED_TOOL_NAMES:
            continue
        if not inspect.isfunction(obj):
            continue
        if getattr(obj, "__module__", None) != __name__:
            continue
        try:
            inspect.signature(obj)
            registry[name] = obj
        except (TypeError, ValueError):
            continue
    return registry


def _describe_tool(name: str, func: Callable[..., Any]) -> Dict[str, Any]:
    sig = inspect.signature(func)
    params = []
    for p in sig.parameters.values():
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if p.annotation is bool:
            param_type = "boolean"
        elif p.annotation is int:
            param_type = "integer"
        else:
            param_type = "string"
        params.append(
            {
                "name": p.name,
                "required": p.default is inspect._empty,
                "type": param_type,
            }
        )
    return {
        "name": name,
        "description": (func.__doc__ or "").strip(),
        "params": params,
    }


def _list_tools_description() -> List[Dict[str, Any]]:
    registry = _get_mcp_tools_registry()
    return [_describe_tool(name, func) for name, func in sorted(registry.items(), key=lambda item: item[0].lower())]


def _invoke_tool_by_name(name: str, args: Dict[str, Any]) -> Any:
    registry = _get_mcp_tools_registry()
    if name not in registry:
        return {"error": f"Unknown tool: {name}"}

    func = registry[name]
    sig = inspect.signature(func)
    bound_kwargs: Dict[str, Any] = {}
    for p in sig.parameters.values():
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if p.name not in args:
            continue
        value = args[p.name]
        if p.annotation is bool:
            value = _coerce_bool(value)
        elif p.annotation is int and isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                value = int(value)
        bound_kwargs[p.name] = value

    return func(**bound_kwargs)


def _invoke_tool_by_positional_args(name: str, args: List[str]) -> Any:
    registry = _get_mcp_tools_registry()
    if name not in registry:
        return {"error": f"Unknown tool: {name}"}

    func = registry[name]
    sig = inspect.signature(func)
    params = [
        p
        for p in sig.parameters.values()
        if p.kind
        not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    ]

    if len(args) > len(params):
        return {"error": f"Too many positional args for {name}"}

    bound_kwargs: Dict[str, Any] = {}
    for param, raw_value in zip(params, args):
        value: Any = raw_value
        if param.annotation is bool:
            value = _coerce_bool(raw_value)
        elif param.annotation is int:
            try:
                value = int(raw_value, 0)
            except ValueError:
                value = int(raw_value)
        bound_kwargs[param.name] = value

    try:
        return func(**bound_kwargs)
    except Exception as exc:
        return {"error": str(exc)}


def _block_to_dict(block: Any) -> Dict[str, Any]:
    try:
        if hasattr(block, "model_dump") and callable(getattr(block, "model_dump")):
            return block.model_dump()
    except Exception:
        pass
    if isinstance(block, dict):
        return block
    btype = getattr(block, "type", None)
    if btype == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if btype == "tool_use":
        return {
            "type": "tool_use",
            "id": getattr(block, "id", None),
            "name": getattr(block, "name", None),
            "input": getattr(block, "input", {}) or {},
        }
    return {"type": str(btype or "unknown"), "raw": str(block)}


def Initialize() -> Dict[str, Any]:
    """Initialize MCP session and send notifications/initialized."""
    return _default_client().initialize()


def ListServerTools() -> Dict[str, Any]:
    """List all native tools exposed by the x64dbg MCP server."""
    return _default_client().list_tools()


def ListResources() -> Dict[str, Any]:
    """List available MCP resources."""
    return _default_client().list_resources()


def ListResourceTemplates() -> Dict[str, Any]:
    """List available MCP resource templates."""
    return _default_client().list_resource_templates()


def ListPrompts() -> Dict[str, Any]:
    """List available MCP prompts."""
    return _default_client().list_prompts()


def IsDebugging() -> bool:
    """Check whether x64dbg currently has an active debugging session."""
    payload = _extract_first_parsed_content(safe_call_tool("debug_get_state"))
    if isinstance(payload, dict):
        return payload.get("state") in {"running", "paused"}
    return False


def IsDebugActive() -> bool:
    """Check if debugger is actively running."""
    payload = _extract_first_parsed_content(safe_call_tool("debug_get_state"))
    if isinstance(payload, dict):
        return payload.get("state") == "running"
    return False


def GetRegisterDump() -> Any:
    """Get register dump using register_list."""
    return _extract_first_parsed_content(safe_call_tool("register_list", {"general_only": False}))


def RegisterGet(register: str) -> Any:
    """Get a single register value."""
    return _extract_first_parsed_content(safe_call_tool("register_get", {"name": register}))


def RegisterSet(register: str, value: str) -> Any:
    """Set a single register value."""
    return _extract_first_parsed_content(safe_call_tool("register_set", {"name": register, "value": value}))


def MemoryRead(addr: str, size: int, encoding: str = "hex") -> Any:
    """Read memory from the debuggee."""
    return _extract_first_parsed_content(
        safe_call_tool("memory_read", {"address": addr, "size": size, "encoding": encoding})
    )


def MemoryWrite(addr: str, data: str, encoding: str = "hex") -> Any:
    """Write memory to the debuggee."""
    return _extract_first_parsed_content(
        safe_call_tool("memory_write", {"address": addr, "data": data, "encoding": encoding})
    )


def MemoryIsValidPtr(addr: str) -> bool:
    """Check if memory address is valid."""
    try:
        payload = _extract_first_parsed_content(safe_call_tool("memory_get_info", {"address": addr}))
        return isinstance(payload, dict) and not payload.get("error")
    except Exception:
        return False


def MemoryGetProtect(addr: str) -> Any:
    """Get memory protection flags for an address."""
    payload = _extract_first_parsed_content(safe_call_tool("memory_get_info", {"address": addr}))
    if isinstance(payload, dict):
        for key in ("protection", "protect", "permissions"):
            if key in payload:
                return payload[key]
    return payload


def DebugRun() -> Any:
    """Resume execution."""
    return _extract_first_parsed_content(safe_call_tool("debug_run"))


def DebugPause() -> Any:
    """Pause execution."""
    return _extract_first_parsed_content(safe_call_tool("debug_pause"))


def DebugStepIn() -> Any:
    """Step into the next instruction."""
    return _extract_first_parsed_content(safe_call_tool("debug_step_into"))


def DebugStepInto() -> Any:
    """Step into the next instruction."""
    return _extract_first_parsed_content(safe_call_tool("debug_step_into"))


def DebugStepOver() -> Any:
    """Step over the next instruction."""
    return _extract_first_parsed_content(safe_call_tool("debug_step_over"))


def DebugStepOut() -> Any:
    """Step out of the current function."""
    return _extract_first_parsed_content(safe_call_tool("debug_step_out"))


def DebugStop() -> Any:
    """Stop debugging."""
    return _extract_first_parsed_content(safe_call_tool("debug_stop"))


def GetModuleList() -> Any:
    """Get loaded module list."""
    return _extract_first_parsed_content(safe_call_tool("module_list"))


def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> Any:
    """List symbols for a module."""
    payload = _extract_first_parsed_content(safe_call_tool("symbol_list", {"module": module}))
    if isinstance(payload, list):
        return {
            "total": len(payload),
            "module": module,
            "offset": offset,
            "limit": limit,
            "symbols": payload[offset : offset + limit],
        }
    return payload


def GetThreadList() -> Any:
    """Get thread list."""
    return _extract_first_parsed_content(safe_call_tool("thread_list"))


def GetTebAddress(tid: str) -> Any:
    """Get thread information for a thread ID."""
    try:
        return _extract_first_parsed_content(safe_call_tool("thread_get", {"thread_id": int(tid, 0)}))
    except ValueError:
        return _extract_first_parsed_content(safe_call_tool("thread_get", {"thread_id": int(tid)}))


def MemoryBase(addr: str) -> Any:
    """Get memory region details for an address."""
    return _extract_first_parsed_content(safe_call_tool("memory_get_info", {"address": addr}))


def SetPageRights(addr: str, rights: str) -> Dict[str, Any]:
    """Change memory page rights using the plugin-native memory_set_protection tool."""
    rights_map = {
        "r": "ReadOnly",
        "rw": "ReadWrite",
        "rx": "ExecuteRead",
        "rwx": "ExecuteReadWrite",
        "x": "Execute",
        "n": "NoAccess",
    }
    plugin_map = {
        "ReadOnly": "PAGE_READONLY",
        "ReadWrite": "PAGE_READWRITE",
        "ExecuteRead": "PAGE_EXECUTE_READ",
        "ExecuteReadWrite": "PAGE_EXECUTE_READWRITE",
        "Execute": "PAGE_EXECUTE",
        "NoAccess": "PAGE_NOACCESS",
    }
    normalized = rights_map.get(rights.lower(), rights)
    protection = plugin_map.get(normalized, normalized)

    try:
        result = _extract_first_parsed_content(
            safe_call_tool("memory_set_protection", {"address": addr, "protection": protection})
        )
        return result if isinstance(result, dict) else {"result": result}
    except Exception as exc:
        command = f"setpagerights {addr}, {normalized}"
        fallback = _extract_first_parsed_content(safe_call_tool("script_execute", {"command": command}))
        return {
            "success": isinstance(fallback, dict) and bool(fallback.get("success")),
            "command": command,
            "result": fallback,
            "fallback_reason": str(exc),
        }


def StringGetAt(addr: str) -> Dict[str, Any]:
    """Try to decode a string at the given address."""
    data = _extract_first_parsed_content(
        safe_call_tool("memory_read", {"address": addr, "size": 256, "encoding": "ascii"})
    )
    if isinstance(data, str):
        return {"address": addr, "string": data.split("\x00", 1)[0]}
    return {"address": addr, "result": data}


def XrefGet(addr: str) -> Dict[str, Any]:
    """Get cross-references targeting the specified address."""
    return _extract_first_parsed_content(safe_call_tool("native_get_xrefs", {"address": addr}))


def XrefCount(addr: str) -> Dict[str, Any]:
    """Get the number of cross-references targeting the specified address."""
    return _extract_first_parsed_content(safe_call_tool("native_get_xref_count", {"address": addr}))


def GetMemoryMap() -> Any:
    """Get the process memory map."""
    return _extract_first_parsed_content(safe_call_tool("memory_enumerate"))


def MemoryRemoteAlloc(size: str, addr: str = "0") -> Any:
    """Allocate memory in the debuggee."""
    del addr
    try:
        size_value = int(size, 0)
    except ValueError:
        size_value = int(size)
    return _extract_first_parsed_content(safe_call_tool("memory_allocate", {"size": size_value}))


def MemoryRemoteFree(addr: str) -> Any:
    """Free memory in the debuggee."""
    return _extract_first_parsed_content(safe_call_tool("memory_free", {"address": addr}))


def GetBranchDestination(addr: str) -> Dict[str, Any]:
    """Best-effort branch inspection using disassembly."""
    insn = _extract_first_parsed_content(safe_call_tool("disassembly_at", {"address": addr, "count": 1}))
    return {"address": addr, "instruction": insn}


def GetCallStack() -> Any:
    """Get current call stack."""
    return _extract_first_parsed_content(safe_call_tool("stack_get_trace"))


def GetBreakpointList(type: str = "all") -> Any:
    """Get all breakpoints."""
    payload = _extract_first_parsed_content(safe_call_tool("breakpoint_list"))
    if type == "all" or not isinstance(payload, list):
        return payload
    return [bp for bp in payload if str(bp.get("type", "")).lower() == type.lower()]


def DebugSetBreakpoint(addr: str, type: str = "software", enabled: bool = True) -> Any:
    """Set a breakpoint at the specified address."""
    return _extract_first_parsed_content(
        safe_call_tool("breakpoint_set", {"address": addr, "type": type, "enabled": enabled})
    )


def DebugDeleteBreakpoint(addr: str) -> Any:
    """Delete a breakpoint at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("breakpoint_delete", {"address": addr}))


def LabelSet(addr: str, text: str) -> Any:
    """Set a label at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("symbol_set_label", {"address": addr, "label": text}))


def LabelGet(addr: str) -> Any:
    """Get the symbol/label for the specified address."""
    return _extract_first_parsed_content(safe_call_tool("symbol_from_address", {"address": addr}))


def LabelList() -> Any:
    """List symbols for the main module as a label approximation."""
    return _extract_first_parsed_content(safe_call_tool("symbol_list"))


def CommentSet(addr: str, text: str) -> Any:
    """Set a comment at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("symbol_set_comment", {"address": addr, "comment": text}))


def CommentGet(addr: str) -> Any:
    """Get the comment at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("symbol_get_comment", {"address": addr}))


def SetHardwareBreakpoint(addr: str, type: str = "execute") -> Any:
    """Set a hardware breakpoint."""
    return _extract_first_parsed_content(
        safe_call_tool("breakpoint_set", {"address": addr, "type": "hardware", "enabled": True})
    )


def DeleteHardwareBreakpoint(addr: str) -> Any:
    """Delete a hardware breakpoint."""
    return _extract_first_parsed_content(safe_call_tool("breakpoint_delete", {"address": addr}))


def DisasmGetInstructionRange(addr: str, count: int = 8) -> Any:
    """Disassemble instructions starting at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("disassembly_at", {"address": addr, "count": count}))


def AssemblerAssemble(addr: str, instruction: str) -> Dict[str, Any]:
    """Assemble an instruction at the given address using x64dbg's asm command."""
    escaped = instruction.replace('"', '\\"')
    command = f'asm {addr}, "{escaped}"'
    result = _extract_first_parsed_content(safe_call_tool("script_execute", {"command": command}))
    try:
        verify = _extract_first_parsed_content(safe_call_tool("disassembly_at", {"address": addr, "count": 1}))
    except Exception as exc:
        verify = {"error": str(exc)}
    return {"success": isinstance(result, dict) and bool(result.get("success")), "command": command, "result": result, "verify": verify}


def AssemblerAssembleMem(addr: str, instruction: str) -> Dict[str, Any]:
    """Assemble and fill remaining bytes with NOPs."""
    escaped = instruction.replace('"', '\\"')
    command = f'asm {addr}, "{escaped}", 1'
    result = _extract_first_parsed_content(safe_call_tool("script_execute", {"command": command}))
    try:
        verify = _extract_first_parsed_content(safe_call_tool("disassembly_at", {"address": addr, "count": 1}))
    except Exception as exc:
        verify = {"error": str(exc)}
    return {"success": isinstance(result, dict) and bool(result.get("success")), "command": command, "result": result, "verify": verify}


def StackPop() -> Dict[str, Any]:
    """Pop one pointer-sized value from the stack."""
    pointers = _extract_first_parsed_content(safe_call_tool("stack_get_pointers"))
    if not isinstance(pointers, dict):
        return {"error": "Failed to query stack pointers", "pointers": pointers}

    sp = pointers.get("sp") or pointers.get("rsp") or pointers.get("esp")
    if not sp:
        return {"error": "Stack pointer field not found", "pointers": pointers}

    width = 8 if ("rsp" in pointers or str(sp).startswith("0x0000")) else 4
    value = _extract_first_parsed_content(
        safe_call_tool("memory_read", {"address": sp, "size": width, "encoding": "hex"})
    )
    sp_value = _parse_int_like(sp)
    new_sp = hex(sp_value + width)
    set_result = _extract_first_parsed_content(safe_call_tool("register_set", {"name": "rsp", "value": new_sp}))
    return {"value": value, "old_sp": sp, "new_sp": new_sp, "set_result": set_result}


def StackPush(value: str) -> Dict[str, Any]:
    """Push one pointer-sized value onto the stack."""
    pointers = _extract_first_parsed_content(safe_call_tool("stack_get_pointers"))
    if not isinstance(pointers, dict):
        return {"error": "Failed to query stack pointers", "pointers": pointers}

    sp = pointers.get("sp") or pointers.get("rsp") or pointers.get("esp")
    if not sp:
        return {"error": "Stack pointer field not found", "pointers": pointers}

    sp_value = _parse_int_like(sp)
    width = 8 if ("rsp" in pointers or str(sp).startswith("0x0000")) else 4
    mask = (1 << (width * 8)) - 1
    new_sp = hex((sp_value - width) & mask)
    set_result = _extract_first_parsed_content(safe_call_tool("register_set", {"name": "rsp", "value": new_sp}))
    write_result = _extract_first_parsed_content(
        safe_call_tool("memory_write", {"address": new_sp, "data": value, "encoding": "hex"})
    )
    return {"value": value, "old_sp": sp, "new_sp": new_sp, "set_result": set_result, "write_result": write_result}


def StackPeek(offset: str = "0") -> Any:
    """Best-effort stack peek via stack_read_frame."""
    try:
        off = int(offset, 0)
    except ValueError:
        off = int(offset)
    pointers = _extract_first_parsed_content(safe_call_tool("stack_get_pointers"))
    if not isinstance(pointers, dict) or "sp" not in pointers:
        return {"error": "Failed to resolve stack pointer", "pointers": pointers}
    sp = pointers["sp"]
    return _extract_first_parsed_content(
        safe_call_tool("stack_read_frame", {"address": sp, "size": max(8, off + 8)})
    )


def FlagGet(flag: str) -> Dict[str, Any]:
    """Get a CPU flag from EFLAGS/RFLAGS."""
    bit = FLAG_BIT_MAP.get(flag.upper())
    if bit is None:
        return {"error": f"Unsupported flag: {flag}"}
    raw = _extract_first_parsed_content(safe_call_tool("register_get", {"name": "eflags"}))
    try:
        eflags = _parse_int_like(raw)
    except Exception:
        return {"error": "Failed to parse eflags", "raw": raw}
    return {"flag": flag.upper(), "value": bool((eflags >> bit) & 1), "eflags": hex(eflags)}


def FlagSet(flag: str, value: bool) -> Dict[str, Any]:
    """Set a CPU flag by updating EFLAGS/RFLAGS."""
    bit = FLAG_BIT_MAP.get(flag.upper())
    if bit is None:
        return {"error": f"Unsupported flag: {flag}"}
    raw = _extract_first_parsed_content(safe_call_tool("register_get", {"name": "eflags"}))
    try:
        eflags = _parse_int_like(raw)
    except Exception:
        return {"error": "Failed to parse eflags", "raw": raw}
    if value:
        new_eflags = eflags | (1 << bit)
    else:
        new_eflags = eflags & ~(1 << bit)
    set_result = _extract_first_parsed_content(
        safe_call_tool("register_set", {"name": "eflags", "value": hex(new_eflags)})
    )
    return {"flag": flag.upper(), "value": bool(value), "old_eflags": hex(eflags), "new_eflags": hex(new_eflags), "set_result": set_result}


def PatternFindMem(start: str, size: str, pattern: str) -> Any:
    """Search memory for a pattern."""
    params: Dict[str, Any] = {"pattern": pattern, "start": start}
    try:
        size_value = int(size, 0)
    except ValueError:
        size_value = int(size)
    try:
        start_value = int(start, 0)
        params["end"] = hex(start_value + size_value)
    except ValueError:
        pass
    return _extract_first_parsed_content(safe_call_tool("memory_search", params))


def MiscParseExpression(expression: str) -> Dict[str, Any]:
    """Best-effort expression parsing for hex/int literals and common registers."""
    expr = expression.strip()
    try:
        return {"expression": expression, "value": hex(int(expr, 0))}
    except Exception:
        pass

    register_names = {
        "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp","rip",
        "eax","ebx","ecx","edx","esi","edi","esp","ebp","eip",
        "eflags",
    }
    lower = expr.lower()
    if lower in register_names:
        value = _extract_first_parsed_content(safe_call_tool("register_get", {"name": lower}))
        return {"expression": expression, "value": value}

    return {"error": "Unsupported expression syntax", "expression": expression}


def MiscRemoteGetProcAddress(module: str, api: str) -> Any:
    """Resolve a symbol using module.api naming."""
    return _extract_first_parsed_content(safe_call_tool("symbol_resolve", {"symbol": f"{module}.{api}"}))


def StepInWithDisasm() -> Dict[str, Any]:
    """Step in once and then fetch current disassembly."""
    step_result = _extract_first_parsed_content(safe_call_tool("debug_step_into"))
    state = _extract_first_parsed_content(safe_call_tool("debug_get_state"))
    address = state.get("rip") if isinstance(state, dict) else None
    disasm = None
    if address:
        disasm = _extract_first_parsed_content(safe_call_tool("disassembly_at", {"address": address, "count": 1}))
    return {"step": step_result, "state": state, "disasm": disasm}


def ExecCommand(cmd: str) -> Any:
    """Execute an x64dbg script command via script_execute."""
    return _extract_first_parsed_content(safe_call_tool("script_execute", {"command": cmd}))


def EnumTcpConnections() -> Dict[str, Any]:
    """Enumerate TCP connections from the plugin-native backend."""
    return _extract_first_parsed_content(safe_call_tool("native_enum_tcp_connections"))


def GetPatchList() -> Dict[str, Any]:
    """List active patches from the plugin-native backend."""
    return _extract_first_parsed_content(safe_call_tool("native_list_patches"))


def GetPatchAt(addr: str) -> Dict[str, Any]:
    """Get patch information at the specified address."""
    return _extract_first_parsed_content(safe_call_tool("native_get_patch_at", {"address": addr}))


def EnumHandles() -> Dict[str, Any]:
    """Enumerate handles from the plugin-native backend."""
    return _extract_first_parsed_content(safe_call_tool("native_enum_handles"))


def ReadResource(uri: str) -> Dict[str, Any]:
    """Read an MCP resource by URI or built-in shortcut."""
    return safe_read_resource(RESOURCE_SHORTCUTS.get(uri, uri))


def GetPrompt(name: str, arguments: str = "{}") -> Dict[str, Any]:
    """Get an MCP prompt by name or shortcut. Arguments should be a JSON object string."""
    return safe_get_prompt(PROMPT_SHORTCUTS.get(name, name), parse_json_argument(arguments))


def _register_tools_with_fastmcp() -> None:
    """Register uppercase wrapper functions as FastMCP tools."""
    for _, func in sorted(_get_mcp_tools_registry().items(), key=lambda item: item[0].lower()):
        mcp.tool()(func)


def parse_json_argument(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"Invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("JSON argument must be an object")
    return value


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def maybe_decode_json_text(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return text
    if stripped[0] not in "[{":
        return text
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return text


def normalize_tool_result(result: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(result)
    content = normalized.get("content")
    if not isinstance(content, list):
        return normalized

    decoded_content = []
    for item in content:
        if not isinstance(item, dict):
            decoded_content.append(item)
            continue

        decoded_item = dict(item)
        if decoded_item.get("type") == "text" and isinstance(decoded_item.get("text"), str):
            decoded_item["parsed"] = maybe_decode_json_text(decoded_item["text"])
        decoded_content.append(decoded_item)

    normalized["content"] = decoded_content
    return normalized


def print_tool_result(result: Dict[str, Any]) -> None:
    normalized = normalize_tool_result(result)
    print_json(normalized)


def split_shell_words(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=False)
    except ValueError as exc:
        raise MCPClientError(f"Failed to parse input: {exc}") from exc


def build_repl_help() -> str:
    return """Commands:
  help                              Show this help
  quit | exit                       Leave the REPL
  health                            Check server health
  init                              Run initialize + initialized
  tools                             List tools
  api-tools                         List example-style wrapper tools
  call <tool> [json]                Call tool, JSON object is optional args
  api-call <tool> [json]            Call wrapper tool by exported function name
  resources                         List resources
  resource-templates                List resource templates
  read <uri|shortcut>               Read resource, shortcut example: registers
  prompts                           List prompts
  prompt <name|shortcut> [json]     Get prompt, shortcut example: crash
  rpc <method> [json]               Raw JSON-RPC call
  events                            Stream SSE events

Shortcuts:
  resources: state, registers, modules, threads, memory-map, breakpoints, stack
  prompts: crash, vuln, trace, unpack, algorithm, compare, strings, patch, session, api
"""


def run_repl(client: X64DbgMCPClient) -> int:
    print(f"Connected client ready for {client.base_url}")
    print("Type 'help' for commands, 'quit' to exit.")

    while True:
        try:
            line = input("x64dbg-mcp> ").strip()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 130

        if not line:
            continue

        try:
            parts = split_shell_words(line)
            if not parts:
                continue

            parts[0] = COMMAND_ALIASES.get(parts[0], parts[0])
            cmd = parts[0]

            if cmd in {"quit", "exit"}:
                return 0
            if cmd == "help":
                print(build_repl_help())
                continue
            if cmd == "health":
                print_json(client.health())
                continue
            if cmd == "init":
                print_json(client.initialize())
                continue
            if cmd == "tools":
                print_json(client.list_tools())
                continue
            if cmd == "api-tools":
                print_json({"tools": _list_tools_description()})
                continue
            if cmd == "resources":
                print_json(client.list_resources())
                continue
            if cmd == "resource-templates":
                print_json(client.list_resource_templates())
                continue
            if cmd == "prompts":
                print_json(client.list_prompts())
                continue
            if cmd == "events":
                print("Streaming events. Press Ctrl+C to stop.")
                try:
                    for event in client.iter_sse_events():
                        print_json(event)
                except KeyboardInterrupt:
                    print()
                continue
            if cmd == "call":
                if len(parts) < 2:
                    raise MCPClientError("Usage: call <tool_name> [json_args]")
                tool_name = parts[1]
                raw_args = " ".join(parts[2:]) if len(parts) > 2 else None
                print_tool_result(client.call_tool(tool_name, parse_json_argument(raw_args)))
                continue
            if cmd == "api-call":
                if len(parts) < 2:
                    raise MCPClientError("Usage: api-call <tool_name> [json_args]")
                tool_name = parts[1]
                raw_args = " ".join(parts[2:]) if len(parts) > 2 else None
                print_json(_invoke_tool_by_name(tool_name, parse_json_argument(raw_args)))
                continue
            if cmd == "read":
                if len(parts) < 2:
                    raise MCPClientError("Usage: read <uri|shortcut>")
                uri = RESOURCE_SHORTCUTS.get(parts[1], parts[1])
                print_json(client.read_resource(uri))
                continue
            if cmd == "prompt":
                if len(parts) < 2:
                    raise MCPClientError("Usage: prompt <name|shortcut> [json_args]")
                prompt_name = PROMPT_SHORTCUTS.get(parts[1], parts[1])
                raw_args = " ".join(parts[2:]) if len(parts) > 2 else None
                print_json(client.get_prompt(prompt_name, parse_json_argument(raw_args)))
                continue
            if cmd == "rpc":
                if len(parts) < 2:
                    raise MCPClientError("Usage: rpc <method> [json_params]")
                method = parts[1]
                raw_params = " ".join(parts[2:]) if len(parts) > 2 else None
                print_json(client.call(method, parse_json_argument(raw_params)))
                continue

            raise MCPClientError(f"Unknown command: {cmd}")
        except (MCPClientError, argparse.ArgumentTypeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)


def main_cli() -> None:
    parser = argparse.ArgumentParser(description="x64dbg MCP CLI wrapper")
    parser.add_argument("tool", help="Tool/function name (e.g. ExecCommand, RegisterGet, MemoryRead)")
    parser.add_argument("args", nargs="*", help="Arguments for the tool")
    parser.add_argument(
        "--x64dbg-url",
        dest="x64dbg_url",
        default=os.getenv("X64DBG_URL") or os.getenv("X64DBG_MCP_URL"),
        help="x64dbg MCP HTTP server URL",
    )

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    result = _invoke_tool_by_positional_args(opts.tool, opts.args)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def claude_cli() -> None:
    parser = argparse.ArgumentParser(description="Chat with Claude using x64dbg MCP tools")
    parser.add_argument("prompt", nargs=argparse.REMAINDER, help="Initial user prompt. If empty, read from stdin")
    parser.add_argument(
        "--model",
        dest="model",
        default=os.getenv("ANTHROPIC_MODEL", "claude-3-7-sonnet-2025-06-20"),
        help="Claude model",
    )
    parser.add_argument("--api-key", dest="api_key", default=os.getenv("ANTHROPIC_API_KEY"), help="Anthropic API key")
    parser.add_argument(
        "--system",
        dest="system",
        default="You can control x64dbg via MCP tools.",
        help="System prompt",
    )
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=100, help="Max tool-use iterations")
    parser.add_argument(
        "--x64dbg-url",
        dest="x64dbg_url",
        default=os.getenv("X64DBG_URL") or os.getenv("X64DBG_MCP_URL"),
        help="x64dbg MCP HTTP server URL",
    )
    parser.add_argument("--no-tools", dest="no_tools", action="store_true", help="Disable tool-use (text-only)")

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    user_prompt = " ".join(opts.prompt).strip()
    if not user_prompt:
        user_prompt = sys.stdin.read().strip()
    if not user_prompt:
        print("No prompt provided.")
        return

    try:
        import anthropic
    except Exception as exc:
        print("Anthropic SDK not installed. Run: pip install anthropic")
        print(str(exc))
        return

    if not opts.api_key:
        print("Missing Anthropic API key. Set ANTHROPIC_API_KEY or pass --api-key.")
        return

    client = anthropic.Anthropic(api_key=opts.api_key)

    tools_spec: List[Dict[str, Any]] = []
    if not opts.no_tools:
        tools_spec = [
            {
                "name": "mcp_list_tools",
                "description": "List available MCP tool functions and their parameters.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "mcp_call_tool",
                "description": "Invoke an MCP tool by name with arguments.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"},
                    },
                    "required": ["tool"],
                },
            },
        ]

    messages: List[Dict[str, Any]] = [{"role": "user", "content": user_prompt}]

    step = 0
    while True:
        step += 1
        response = client.messages.create(
            model=opts.model,
            system=opts.system,
            messages=messages,
            tools=tools_spec if not opts.no_tools else None,
            max_tokens=1024,
        )

        assistant_text_chunks: List[str] = []
        tool_uses: List[Dict[str, Any]] = []
        for block in response.content:
            b = _block_to_dict(block)
            if b.get("type") == "text":
                assistant_text_chunks.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_uses.append(b)

        if assistant_text_chunks:
            print("\n".join(assistant_text_chunks))

        if not tool_uses or opts.no_tools:
            break

        tool_result_blocks: List[Dict[str, Any]] = []
        for tu in tool_uses:
            name = tu.get("name")
            tu_id = tu.get("id")
            input_obj = tu.get("input", {}) or {}
            if name == "mcp_list_tools":
                result = {"tools": _list_tools_description()}
            elif name == "mcp_call_tool":
                tool_name = input_obj.get("tool")
                args = input_obj.get("args", {}) or {}
                result = _invoke_tool_by_name(tool_name, args)
            else:
                result = {"error": f"Unknown tool: {name}"}

            try:
                result_text = json.dumps(result)
            except Exception:
                result_text = str(result)

            tool_result_blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu_id,
                    "content": result_text,
                }
            )

        assistant_blocks = [_block_to_dict(b) for b in response.content]
        messages.append({"role": "assistant", "content": assistant_blocks})
        messages.append({"role": "user", "content": tool_result_blocks})

        if step >= opts.max_steps:
            break


_register_tools_with_fastmcp()


if __name__ == "__main__":
    # Support multiple modes:
    #  - "serve" or "--serve": run MCP server
    #  - "claude" subcommand: run Claude Messages chat loop
    #  - default: tool invocation CLI
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--serve", "serve"):
            mcp.run()
        elif sys.argv[1] == "claude":
            sys.argv.pop(1)
            claude_cli()
        else:
            main_cli()
    else:
        mcp.run()
