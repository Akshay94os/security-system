"""
AK Master Security System — Process Monitor (§14, §15)
Process security monitoring using psutil.

Features:
- Running process enumeration
- CPU/memory per process
- Process tree
- Executable path & signer (where available)
- Start time
- Suspicious behavior indicators
- Network activity per process (where available)

No offensive capabilities. Read-only monitoring.
"""
from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ProcessRiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    status: str = ""
    username: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_mb: float = 0.0
    num_threads: int = 0
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    create_time: Optional[str] = None
    risk_level: ProcessRiskLevel = ProcessRiskLevel.SAFE
    risk_indicators: List[str] = field(default_factory=list)
    connections_count: int = 0

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "status": self.status,
            "username": self.username,
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_percent": round(self.memory_percent, 1),
            "memory_mb": round(self.memory_mb, 1),
            "num_threads": self.num_threads,
            "ppid": self.ppid,
            "parent_name": self.parent_name,
            "create_time": self.create_time,
            "risk_level": self.risk_level.value,
            "risk_indicators": self.risk_indicators,
            "connections_count": self.connections_count,
        }


@dataclass
class ProcessScanResult:
    total_processes: int = 0
    processes: List[ProcessInfo] = field(default_factory=list)
    suspicious_count: int = 0
    high_cpu_count: int = 0
    high_memory_count: int = 0
    system_cpu_percent: float = 0.0
    system_memory_percent: float = 0.0
    scan_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "total_processes": self.total_processes,
            "suspicious_count": self.suspicious_count,
            "high_cpu_count": self.high_cpu_count,
            "high_memory_count": self.high_memory_count,
            "system_cpu_percent": round(self.system_cpu_percent, 1),
            "system_memory_percent": round(self.system_memory_percent, 1),
            "processes": [p.to_dict() for p in self.processes],
            "scan_error": self.scan_error,
        }


# ──────────────────────────────────────────────────────────
# Suspicious process patterns
# ──────────────────────────────────────────────────────────

# Process names commonly associated with suspicious activity
_SUSPICIOUS_PROCESS_NAMES = frozenset({
    "mimikatz", "lazagne", "procdump", "pwdump",
    "keylogger", "cryptominer", "xmrig", "nbminer",
    "ncat", "netcat", "nc.exe", "socat",
    "msfconsole", "meterpreter", "cobaltstrike",
})

# Processes that shouldn't normally have network connections
_NO_NETWORK_EXPECTED = frozenset({
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "calculator.exe", "snippingtool.exe",
})

# Common persistence locations
_PERSISTENCE_PATHS = [
    "startup", "appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    "\\temp\\", "\\tmp\\",
]


def _assess_process_risk(proc: ProcessInfo) -> None:
    """Assess risk indicators for a single process."""
    indicators = []
    name_lower = (proc.name or "").lower()
    exe_lower = (proc.exe or "").lower()

    # Known suspicious names
    if name_lower.replace(".exe", "") in _SUSPICIOUS_PROCESS_NAMES:
        indicators.append(f"Known suspicious process name: {proc.name}")

    # High CPU usage (potential cryptominer)
    if proc.cpu_percent > 80:
        indicators.append(f"Very high CPU usage: {proc.cpu_percent:.1f}%")

    # High memory usage
    if proc.memory_percent > 20:
        indicators.append(f"High memory usage: {proc.memory_percent:.1f}%")

    # Running from temp directory
    for ppath in _PERSISTENCE_PATHS:
        if ppath in exe_lower:
            indicators.append(f"Running from suspicious location: {proc.exe}")
            break

    # Process with no executable path (possible injection)
    if proc.pid > 4 and not proc.exe:
        indicators.append("No executable path — possible process injection")

    # Unexpected network from normally offline apps
    if name_lower in _NO_NETWORK_EXPECTED and proc.connections_count > 0:
        indicators.append(
            f"Unexpected network activity from {proc.name} ({proc.connections_count} connections)"
        )

    proc.risk_indicators = indicators
    if len(indicators) >= 2:
        proc.risk_level = ProcessRiskLevel.HIGH
    elif len(indicators) == 1:
        proc.risk_level = ProcessRiskLevel.SUSPICIOUS
    else:
        proc.risk_level = ProcessRiskLevel.SAFE


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def get_process_list(
    sort_by: str = "cpu",
    limit: int = 100,
    include_system: bool = False,
) -> ProcessScanResult:
    """
    Get a list of running processes with security analysis.
    Read-only — does not terminate or modify any process.
    """
    try:
        import psutil
    except ImportError:
        return ProcessScanResult(
            scan_error="psutil is not installed. Process monitoring unavailable.",
        )

    result = ProcessScanResult()
    processes: List[ProcessInfo] = []

    try:
        result.system_cpu_percent = psutil.cpu_percent(interval=0.5)
        result.system_memory_percent = psutil.virtual_memory().percent
    except Exception:
        pass

    try:
        for proc in psutil.process_iter([
            "pid", "name", "exe", "cmdline", "status", "username",
            "cpu_percent", "memory_percent", "memory_info",
            "num_threads", "ppid", "create_time",
        ]):
            try:
                info = proc.info
                pid = info.get("pid", 0)

                # Skip system processes unless requested
                if not include_system and pid <= 4:
                    continue

                # Get connection count
                conn_count = 0
                try:
                    conn_count = len(proc.net_connections())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Get parent name
                parent_name = None
                ppid = info.get("ppid")
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Format create time
                create_time = None
                ct = info.get("create_time")
                if ct:
                    try:
                        create_time = datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
                    except (ValueError, OSError):
                        pass

                # Memory in MB
                mem_info = info.get("memory_info")
                memory_mb = (mem_info.rss / 1e6) if mem_info else 0.0

                cmdline = info.get("cmdline")
                cmdline_str = " ".join(cmdline) if cmdline else None

                p = ProcessInfo(
                    pid=pid,
                    name=info.get("name", ""),
                    exe=info.get("exe"),
                    cmdline=cmdline_str[:500] if cmdline_str else None,  # Truncate
                    status=info.get("status", ""),
                    username=info.get("username"),
                    cpu_percent=info.get("cpu_percent", 0.0) or 0.0,
                    memory_percent=info.get("memory_percent", 0.0) or 0.0,
                    memory_mb=memory_mb,
                    num_threads=info.get("num_threads", 0) or 0,
                    ppid=ppid,
                    parent_name=parent_name,
                    create_time=create_time,
                    connections_count=conn_count,
                )

                # Risk assessment
                _assess_process_risk(p)
                processes.append(p)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    except Exception as e:
        result.scan_error = f"Process enumeration error: {e}"
        logger.error("Process monitor error: %s", e)

    # Sort
    if sort_by == "cpu":
        processes.sort(key=lambda p: p.cpu_percent, reverse=True)
    elif sort_by == "memory":
        processes.sort(key=lambda p: p.memory_percent, reverse=True)
    elif sort_by == "risk":
        risk_order = {"HIGH": 0, "SUSPICIOUS": 1, "LOW": 2, "SAFE": 3}
        processes.sort(key=lambda p: risk_order.get(p.risk_level.value, 9))
    elif sort_by == "name":
        processes.sort(key=lambda p: p.name.lower())

    # Apply limit
    result.total_processes = len(processes)
    result.processes = processes[:limit]
    result.suspicious_count = sum(1 for p in processes if p.risk_level in (ProcessRiskLevel.SUSPICIOUS, ProcessRiskLevel.HIGH))
    result.high_cpu_count = sum(1 for p in processes if p.cpu_percent > 50)
    result.high_memory_count = sum(1 for p in processes if p.memory_percent > 10)

    logger.info(
        "PROCESS SCAN | total=%d | suspicious=%d | high_cpu=%d",
        result.total_processes, result.suspicious_count, result.high_cpu_count,
    )

    return result


def get_process_detail(pid: int) -> Optional[Dict[str, Any]]:
    """Get detailed information about a specific process."""
    try:
        import psutil
        proc = psutil.Process(pid)

        connections = []
        try:
            for conn in proc.net_connections():
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        open_files = []
        try:
            for f in proc.open_files()[:20]:  # Limit
                open_files.append(f.path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        children = []
        try:
            for child in proc.children(recursive=False):
                children.append({
                    "pid": child.pid,
                    "name": child.name(),
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        return {
            "pid": proc.pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cwd": proc.cwd() if hasattr(proc, "cwd") else None,
            "status": proc.status(),
            "username": proc.username(),
            "cpu_percent": proc.cpu_percent(interval=0.5),
            "memory_percent": round(proc.memory_percent(), 2),
            "num_threads": proc.num_threads(),
            "create_time": datetime.fromtimestamp(
                proc.create_time(), tz=timezone.utc
            ).isoformat(),
            "connections": connections,
            "open_files": open_files,
            "children": children,
        }

    except ImportError:
        return {"error": "psutil not installed"}
    except psutil.NoSuchProcess:
        return {"error": f"Process {pid} not found"}
    except psutil.AccessDenied:
        return {"error": f"Access denied to process {pid}"}
    except Exception as e:
        return {"error": str(e)}
