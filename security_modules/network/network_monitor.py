"""
AK Master Security System — Network Monitor (§16, §17)
Network connection monitoring and security analysis.

Features:
- Active connection enumeration (via psutil)
- Process association for connections
- Remote address analysis
- Suspicious pattern detection
- Connection frequency analysis
- DNS-related indicator detection (where feasible)

Read-only monitoring. Does not block connections at OS level.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ConnectionRisk(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"


@dataclass
class ConnectionInfo:
    local_address: str
    local_port: int
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: str = "tcp"
    status: str = ""
    pid: Optional[int] = None
    process_name: Optional[str] = None
    risk_level: ConnectionRisk = ConnectionRisk.SAFE
    risk_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
            "risk_level": self.risk_level.value,
            "risk_indicators": self.risk_indicators,
        }


@dataclass
class NetworkScanResult:
    total_connections: int = 0
    connections: List[ConnectionInfo] = field(default_factory=list)
    suspicious_count: int = 0
    unique_remote_ips: int = 0
    listening_ports: List[int] = field(default_factory=list)
    top_remote_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_processes: List[Dict[str, Any]] = field(default_factory=list)
    scan_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "total_connections": self.total_connections,
            "suspicious_count": self.suspicious_count,
            "unique_remote_ips": self.unique_remote_ips,
            "listening_ports": self.listening_ports,
            "top_remote_ips": self.top_remote_ips,
            "top_processes": self.top_processes,
            "connections": [c.to_dict() for c in self.connections],
            "scan_error": self.scan_error,
        }


# ──────────────────────────────────────────────────────────
# Suspicious port/IP patterns
# ──────────────────────────────────────────────────────────

# Ports commonly used by malware
_SUSPICIOUS_REMOTE_PORTS = frozenset({
    4444, 5555, 6666, 7777, 8888, 9999,  # Common reverse shell ports
    1337, 31337,  # "elite" ports
    4443, 8443,   # Alt HTTPS often used for C2
    6667, 6668, 6669,  # IRC (used by some botnets)
    3389,  # RDP (outbound is suspicious)
    5900, 5901,  # VNC (outbound suspicious)
})

# Known non-routable / loopback
_LOCAL_PREFIXES = ("127.", "::1", "0.0.0.0", "::")

# Suspicious outbound patterns
_HIGH_PORTS_THRESHOLD = 50000  # Many connections to high ports = suspicious


def _assess_connection_risk(conn: ConnectionInfo) -> None:
    """Evaluate risk for a single connection."""
    indicators = []

    remote = conn.remote_address or ""
    remote_port = conn.remote_port or 0

    # Skip local connections
    if remote.startswith(_LOCAL_PREFIXES) or not remote:
        conn.risk_level = ConnectionRisk.SAFE
        return

    # Suspicious remote port
    if remote_port in _SUSPICIOUS_REMOTE_PORTS:
        indicators.append(
            f"Connected to suspicious port {remote_port} "
            f"(commonly used by malware/remote access tools)"
        )

    # High numbered ephemeral remote port for outbound
    if remote_port > _HIGH_PORTS_THRESHOLD and conn.status == "ESTABLISHED":
        # This is normal for client connections, but flag if process is unexpected
        pass  # Only flag if combined with other signals

    # Outbound RDP
    if remote_port == 3389 and conn.status == "ESTABLISHED":
        indicators.append(
            f"Outbound RDP connection to {remote}:{remote_port}"
        )

    # Outbound VNC
    if remote_port in (5900, 5901) and conn.status == "ESTABLISHED":
        indicators.append(
            f"Outbound VNC connection to {remote}:{remote_port}"
        )

    conn.risk_indicators = indicators
    if len(indicators) >= 2:
        conn.risk_level = ConnectionRisk.HIGH
    elif len(indicators) == 1:
        conn.risk_level = ConnectionRisk.SUSPICIOUS
    else:
        conn.risk_level = ConnectionRisk.SAFE


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def get_network_connections(
    protocol: Optional[str] = None,
    limit: int = 200,
    include_listening: bool = True,
) -> NetworkScanResult:
    """
    Get active network connections with security analysis.
    Read-only — does not block or modify connections.
    """
    try:
        import psutil
    except ImportError:
        return NetworkScanResult(
            scan_error="psutil is not installed. Network monitoring unavailable.",
        )

    result = NetworkScanResult()
    connections: List[ConnectionInfo] = []
    remote_ips: Counter = Counter()
    process_conns: Counter = Counter()
    listening: List[int] = []

    try:
        kind = "inet"
        if protocol == "tcp":
            kind = "tcp"
        elif protocol == "udp":
            kind = "udp"

        for conn in psutil.net_connections(kind=kind):
            try:
                # Extract addresses
                laddr_ip = conn.laddr.ip if conn.laddr else ""
                laddr_port = conn.laddr.port if conn.laddr else 0
                raddr_ip = conn.raddr.ip if conn.raddr else None
                raddr_port = conn.raddr.port if conn.raddr else None

                # Track listening ports
                if conn.status == "LISTEN":
                    listening.append(laddr_port)
                    if not include_listening:
                        continue

                # Get process name
                proc_name = None
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = f"PID:{conn.pid}"

                # Determine protocol string
                proto = "tcp"
                if hasattr(conn, "type"):
                    import socket
                    if conn.type == socket.SOCK_DGRAM:
                        proto = "udp"

                ci = ConnectionInfo(
                    local_address=laddr_ip,
                    local_port=laddr_port,
                    remote_address=raddr_ip,
                    remote_port=raddr_port,
                    protocol=proto,
                    status=conn.status or "",
                    pid=conn.pid,
                    process_name=proc_name,
                )

                # Risk assessment
                _assess_connection_risk(ci)
                connections.append(ci)

                # Track stats
                if raddr_ip and not raddr_ip.startswith(_LOCAL_PREFIXES):
                    remote_ips[raddr_ip] += 1
                if proc_name:
                    process_conns[proc_name] += 1

            except Exception:
                continue

    except psutil.AccessDenied:
        result.scan_error = "Access denied — run with elevated privileges for full network visibility."
    except Exception as e:
        result.scan_error = f"Network scan error: {e}"
        logger.error("Network monitor error: %s", e)

    # Apply limit
    result.total_connections = len(connections)
    result.connections = connections[:limit]
    result.suspicious_count = sum(
        1 for c in connections
        if c.risk_level in (ConnectionRisk.SUSPICIOUS, ConnectionRisk.HIGH)
    )
    result.unique_remote_ips = len(remote_ips)
    result.listening_ports = sorted(set(listening))

    # Top remote IPs
    result.top_remote_ips = [
        {"ip": ip, "count": count}
        for ip, count in remote_ips.most_common(10)
    ]

    # Top processes by connection count
    result.top_processes = [
        {"process": name, "connections": count}
        for name, count in process_conns.most_common(10)
    ]

    logger.info(
        "NETWORK SCAN | total=%d | suspicious=%d | unique_ips=%d | listening=%d",
        result.total_connections, result.suspicious_count,
        result.unique_remote_ips, len(result.listening_ports),
    )

    return result
