"""
AK Master Security System — Tool Registry
Central registry for all approved Nexus tools.

SECURITY DESIGN:
- Every tool must be registered with a defined schema
- Parameters are validated against the schema before execution
- Hallucination defense: if tool ID does not exist → immediate BLOCK
- No tool accepts arbitrary unrestricted shell commands
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────
# Tool definition schema
# ──────────────────────────────────────────────────────────

@dataclass
class ToolDefinition:
    tool_id: str
    name: str
    description: str
    category: str
    risk_level: int               # 0–4 per §7
    version: str = "1.0.0"
    required_permissions: List[str] = field(default_factory=list)
    supported_os: List[str] = field(default_factory=list)  # ["windows","linux","darwin"]
    timeout_seconds: int = 30
    requires_confirmation: bool = False
    requires_audit: bool = True
    is_active: bool = True
    # The actual implementation function
    implementation: Optional[Callable] = None
    # Pydantic model class for input validation
    input_model: Optional[type] = None


@dataclass
class ToolCallRequest:
    tool_id: str
    parameters: Dict[str, Any]
    user_id: str
    correlation_id: str
    session_id: Optional[str] = None


@dataclass
class ToolCallResult:
    success: bool
    tool_id: str
    correlation_id: str
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    was_blocked: bool = False
    block_reason: Optional[str] = None


# ──────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Central registry for all approved Nexus tools.

    Key security properties:
    1. Only registered tools can be called
    2. Parameters validated against Pydantic schema
    3. Nonexistent tool → immediate BLOCK (hallucination defense)
    4. Inactive tools → BLOCK
    5. OS mismatch → BLOCK
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._call_count: Dict[str, int] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool. Raises ValueError if tool_id already registered."""
        if tool.tool_id in self._tools:
            raise ValueError(f"Tool '{tool.tool_id}' is already registered.")
        self._tools[tool.tool_id] = tool
        self._call_count[tool.tool_id] = 0
        logger.debug("Registered tool: %s (risk=%d)", tool.tool_id, tool.risk_level)

    def get(self, tool_id: str) -> Optional[ToolDefinition]:
        """Get a tool by ID. Returns None if not found."""
        return self._tools.get(tool_id)

    def exists(self, tool_id: str) -> bool:
        return tool_id in self._tools

    def list_tools(self, category: Optional[str] = None) -> List[ToolDefinition]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def validate_call(
        self,
        request: ToolCallRequest,
        current_os: str = "windows",
    ) -> tuple[bool, str]:
        """
        Validate a tool call request.
        Returns (is_valid, reason_if_invalid).

        This is the HALLUCINATION DEFENSE — called before any execution.
        """
        tool = self._tools.get(request.tool_id)

        # 1. Tool existence check — primary hallucination defense
        if tool is None:
            logger.warning(
                "HALLUCINATION BLOCKED: Tool '%s' does not exist in registry. "
                "Correlation: %s",
                request.tool_id, request.correlation_id,
            )
            return False, (
                f"Tool '{request.tool_id}' is not registered. "
                "This tool call has been blocked to prevent hallucinated actions."
            )

        # 2. Active check
        if not tool.is_active:
            return False, f"Tool '{request.tool_id}' is currently disabled."

        # 3. OS compatibility check
        if tool.supported_os and current_os.lower() not in [o.lower() for o in tool.supported_os]:
            return False, (
                f"Tool '{request.tool_id}' is not supported on {current_os}. "
                f"Supported: {tool.supported_os}"
            )

        # 4. Parameter schema validation
        if tool.input_model is not None:
            try:
                tool.input_model(**request.parameters)
            except ValidationError as e:
                return False, f"Invalid parameters for tool '{request.tool_id}': {e}"
            except TypeError as e:
                return False, f"Parameter type error for tool '{request.tool_id}': {e}"

        return True, ""

    async def execute(self, request: ToolCallRequest) -> ToolCallResult:
        """
        Execute a validated tool call.
        MUST only be called after validate_call() + permission check + firewall check.
        """
        tool = self._tools.get(request.tool_id)
        if not tool or not tool.implementation:
            return ToolCallResult(
                success=False,
                tool_id=request.tool_id,
                correlation_id=request.correlation_id,
                was_blocked=True,
                block_reason="Tool has no implementation.",
            )

        self._call_count[request.tool_id] = self._call_count.get(request.tool_id, 0) + 1

        try:
            import asyncio
            impl = tool.implementation
            validated_params = request.parameters
            if tool.input_model:
                validated_params = tool.input_model(**request.parameters).model_dump()

            if asyncio.iscoroutinefunction(impl):
                output = await asyncio.wait_for(
                    impl(**validated_params),
                    timeout=tool.timeout_seconds,
                )
            else:
                output = impl(**validated_params)

            return ToolCallResult(
                success=True,
                tool_id=request.tool_id,
                correlation_id=request.correlation_id,
                output=output if isinstance(output, dict) else {"result": output},
            )

        except asyncio.TimeoutError:
            return ToolCallResult(
                success=False,
                tool_id=request.tool_id,
                correlation_id=request.correlation_id,
                error=f"Tool '{request.tool_id}' timed out after {tool.timeout_seconds}s.",
            )
        except Exception as e:
            logger.error("Tool '%s' execution error: %s", request.tool_id, e)
            return ToolCallResult(
                success=False,
                tool_id=request.tool_id,
                correlation_id=request.correlation_id,
                error=f"Tool execution failed: {e}",
            )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_registered": len(self._tools),
            "active": sum(1 for t in self._tools.values() if t.is_active),
            "call_counts": dict(self._call_count),
        }


# Singleton registry
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        _register_phase1_tools(_registry)
    return _registry


# ──────────────────────────────────────────────────────────
# Phase 1 Tool Input Models
# ──────────────────────────────────────────────────────────

class ListFilesInput(BaseModel):
    path: str
    pattern: str = "*"
    max_results: int = 100

    class Config:
        extra = "forbid"


class SearchFilesInput(BaseModel):
    directory: str
    pattern: str
    recursive: bool = False
    max_results: int = 50

    class Config:
        extra = "forbid"


class URLScanInput(BaseModel):
    url: str

    class Config:
        extra = "forbid"


class FileScanInput(BaseModel):
    file_path: str

    class Config:
        extra = "forbid"


class OpenApplicationInput(BaseModel):
    app_name: str

    class Config:
        extra = "forbid"


# ──────────────────────────────────────────────────────────
# Phase 1 Tool implementations
# ──────────────────────────────────────────────────────────

def _impl_system_information() -> dict:
    """Read system information — no side effects."""
    import platform
    import psutil
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "python": platform.python_version(),
            "cpu_percent": cpu,
            "memory_total_gb": round(mem.total / 1e9, 2),
            "memory_used_percent": mem.percent,
            "disk_total_gb": round(disk.total / 1e9, 2),
            "disk_used_percent": disk.percent,
        }
    except Exception as e:
        return {"error": str(e)}


def _impl_battery_status() -> dict:
    try:
        import psutil
        batt = psutil.sensors_battery()
        if batt is None:
            return {"available": False, "message": "No battery detected (desktop system)"}
        return {
            "available": True,
            "percent": round(batt.percent, 1),
            "charging": batt.power_plugged,
            "seconds_left": batt.secsleft if batt.secsleft != psutil.POWER_TIME_UNLIMITED else None,
        }
    except Exception as e:
        return {"error": str(e)}


def _impl_list_files(path: str, pattern: str = "*", max_results: int = 100) -> dict:
    """List files in a directory — read only, no modification."""
    import os
    import fnmatch
    from pathlib import Path

    try:
        p = Path(path)
        if not p.exists():
            return {"error": f"Path does not exist: {path}"}
        if not p.is_dir():
            return {"error": f"Path is not a directory: {path}"}

        files = []
        for entry in p.iterdir():
            if fnmatch.fnmatch(entry.name, pattern):
                stat = entry.stat()
                files.append({
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "size_bytes": stat.st_size if entry.is_file() else None,
                    "modified": stat.st_mtime,
                })
            if len(files) >= max_results:
                break

        return {
            "path": str(p.resolve()),
            "count": len(files),
            "truncated": len(files) == max_results,
            "files": files,
        }
    except PermissionError:
        return {"error": f"Permission denied: {path}"}
    except Exception as e:
        return {"error": str(e)}


def _impl_search_files(
    directory: str,
    pattern: str,
    recursive: bool = False,
    max_results: int = 50,
) -> dict:
    """Search for files matching a pattern — read only."""
    import fnmatch
    from pathlib import Path

    try:
        base = Path(directory)
        if not base.exists():
            return {"error": f"Directory does not exist: {directory}"}

        results = []
        glob_fn = base.rglob if recursive else base.glob
        for match in glob_fn(pattern):
            results.append(str(match))
            if len(results) >= max_results:
                break

        return {
            "directory": str(base.resolve()),
            "pattern": pattern,
            "count": len(results),
            "truncated": len(results) == max_results,
            "results": results,
        }
    except PermissionError:
        return {"error": f"Permission denied: {directory}"}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────

def _register_phase1_tools(registry: ToolRegistry) -> None:
    """Register all Phase 1 approved tools."""

    registry.register(ToolDefinition(
        tool_id="system.information",
        name="System Information",
        description="Read system information: OS, CPU, memory, disk. Read-only, no side effects.",
        category="system",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=10,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_system_information,
        input_model=None,
    ))

    registry.register(ToolDefinition(
        tool_id="system.battery_status",
        name="Battery Status",
        description="Read battery charge level and charging state. Read-only.",
        category="system",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=5,
        requires_confirmation=False,
        requires_audit=False,
        implementation=_impl_battery_status,
        input_model=None,
    ))

    registry.register(ToolDefinition(
        tool_id="file.list",
        name="List Files",
        description="List files in a directory. Read-only. Requires permitted path.",
        category="file",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=10,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_list_files,
        input_model=ListFilesInput,
    ))

    registry.register(ToolDefinition(
        tool_id="file.search",
        name="Search Files",
        description="Search for files matching a pattern in a directory. Read-only.",
        category="file",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=15,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_search_files,
        input_model=SearchFilesInput,
    ))

    registry.register(ToolDefinition(
        tool_id="security.url_scan",
        name="URL Security Scan",
        description="Analyze a URL for security risks using multi-layer analysis engine.",
        category="security",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=30,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_url_scan,
        input_model=URLScanInput,
    ))

    registry.register(ToolDefinition(
        tool_id="security.file_scan",
        name="File Security Scan",
        description="Analyze a file for security risks: hash, type, metadata, static analysis.",
        category="security",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=60,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_file_scan,
        input_model=FileScanInput,
    ))

    registry.register(ToolDefinition(
        tool_id="security.process_list",
        name="Process List",
        description="List running processes with security risk assessment. Read-only.",
        category="security",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=15,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_process_list,
        input_model=None,
    ))

    registry.register(ToolDefinition(
        tool_id="security.network_connections",
        name="Network Connections",
        description="List active network connections with security analysis. Read-only.",
        category="security",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=15,
        requires_confirmation=False,
        requires_audit=True,
        implementation=_impl_network_connections,
        input_model=None,
    ))

    registry.register(ToolDefinition(
        tool_id="security.health_check",
        name="Security Health Check",
        description="Check status of all security modules. Read-only.",
        category="security",
        risk_level=0,
        version="1.0.0",
        supported_os=["windows", "linux", "darwin"],
        timeout_seconds=10,
        requires_confirmation=False,
        requires_audit=False,
        implementation=_impl_health_check,
        input_model=None,
    ))

    logger.info("Phase 1 tool registry initialized with %d tools.", len(registry._tools))


# ──────────────────────────────────────────────────────────
# New tool implementations
# ──────────────────────────────────────────────────────────

def _impl_url_scan(url: str) -> dict:
    """Scan a URL using the multi-layer URL scanner."""
    from security_modules.web.url_scanner import scan_url
    result = scan_url(url)
    return result.to_dict()


def _impl_file_scan(file_path: str) -> dict:
    """Scan a file using the static analysis file scanner."""
    from security_modules.files.file_scanner import scan_file
    result = scan_file(file_path)
    return result.to_dict()


def _impl_process_list() -> dict:
    """List running processes with security analysis."""
    from security_modules.processes.process_monitor import get_process_list
    result = get_process_list(sort_by="cpu", limit=50)
    return result.to_dict()


def _impl_network_connections() -> dict:
    """List active network connections."""
    from security_modules.network.network_monitor import get_network_connections
    result = get_network_connections(limit=100)
    return result.to_dict()


def _impl_health_check() -> dict:
    """Run health check — must be called in async context."""
    # For sync tool execution, return basic info
    import platform
    return {
        "os": platform.system(),
        "note": "For detailed health check, use the /api/v1/health/detailed endpoint.",
    }

