"""
AK Master Security System — Security API Router
Endpoints for security scanning, process monitoring, network monitoring, DLP.
All operations are read-only unless explicitly noted.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.engine import get_db

logger = logging.getLogger(__name__)

security_router = APIRouter(prefix="/security", tags=["Security"])


# ──────────────────────────────────────────────────────────
# URL Scan
# ──────────────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str


@security_router.post("/url/scan")
async def scan_url(body: URLScanRequest):
    """Scan a URL using the multi-layer analysis engine."""
    from security_modules.web.url_scanner import scan_url as do_scan
    result = do_scan(body.url)
    return result.to_dict()


# ──────────────────────────────────────────────────────────
# File Scan
# ──────────────────────────────────────────────────────────

class FileScanRequest(BaseModel):
    file_path: str


@security_router.post("/file/scan")
async def scan_file(body: FileScanRequest):
    """Scan a file for security risks (static analysis, no execution)."""
    from security_modules.files.file_scanner import scan_file as do_scan
    result = do_scan(body.file_path)
    return result.to_dict()


# ──────────────────────────────────────────────────────────
# Process Monitor
# ──────────────────────────────────────────────────────────

@security_router.get("/processes")
async def list_processes(
    sort_by: str = Query(default="cpu", regex="^(cpu|memory|risk|name)$"),
    limit: int = Query(default=50, le=200),
    include_system: bool = Query(default=False),
):
    """List running processes with security analysis."""
    from security_modules.processes.process_monitor import get_process_list
    result = get_process_list(sort_by=sort_by, limit=limit, include_system=include_system)
    return result.to_dict()


@security_router.get("/processes/{pid}")
async def process_detail(pid: int):
    """Get detailed information about a specific process."""
    from security_modules.processes.process_monitor import get_process_detail
    result = get_process_detail(pid)
    if result and "error" in result:
        return {"error": result["error"]}
    return result


# ──────────────────────────────────────────────────────────
# Network Monitor
# ──────────────────────────────────────────────────────────

@security_router.get("/network/connections")
async def list_connections(
    protocol: Optional[str] = Query(default=None, regex="^(tcp|udp)$"),
    limit: int = Query(default=100, le=500),
    include_listening: bool = Query(default=True),
):
    """List active network connections with security analysis."""
    from security_modules.network.network_monitor import get_network_connections
    result = get_network_connections(
        protocol=protocol, limit=limit, include_listening=include_listening,
    )
    return result.to_dict()


# ──────────────────────────────────────────────────────────
# DLP Scan
# ──────────────────────────────────────────────────────────

class DLPScanRequest(BaseModel):
    file_path: Optional[str] = None
    content: Optional[str] = None


@security_router.post("/dlp/scan")
async def dlp_scan(body: DLPScanRequest):
    """
    Scan content or a file for sensitive data patterns.
    All findings are REDACTED — raw secrets are never returned.
    """
    if body.file_path:
        from security_modules.dlp.dlp_engine import scan_file as do_scan
        result = do_scan(body.file_path)
    elif body.content:
        from security_modules.dlp.dlp_engine import scan_text
        result = scan_text(body.content)
    else:
        return {"error": "Provide either file_path or content to scan."}
    return result.to_dict()


# ──────────────────────────────────────────────────────────
# Risk Assessment
# ──────────────────────────────────────────────────────────

@security_router.get("/risk/assessment")
async def risk_assessment():
    """Get the current system risk assessment from the central risk engine."""
    from backend.risk_engine.engine import get_risk_engine
    engine = get_risk_engine()
    engine.clear()  # Fresh assessment each time
    result = await engine.assess()
    return result.to_dict()


# ──────────────────────────────────────────────────────────
# Security Dashboard Summary
# ──────────────────────────────────────────────────────────

@security_router.get("/dashboard/summary")
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    """
    Aggregate summary for the main dashboard.
    Returns real data from health check, events, and system metrics.
    """
    from backend.security.health_monitor import run_health_check
    from sqlalchemy import select, func, desc
    from backend.database.models import SecurityEvent, Incident, AuditLog, Alert

    # Health check
    health = await run_health_check()

    # Recent event counts
    from datetime import datetime, timedelta, timezone
    last_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

    event_count = await db.execute(
        select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.created_at >= last_24h
        )
    )
    events_24h = event_count.scalar() or 0

    # Active incidents
    incident_count = await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.status.in_(["OPEN", "INVESTIGATING"])
        )
    )
    active_incidents = incident_count.scalar() or 0

    # Recent critical events
    critical_events = await db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.severity.in_(["HIGH", "CRITICAL"]))
        .order_by(desc(SecurityEvent.created_at))
        .limit(5)
    )
    critical_list = critical_events.scalars().all()

    # System metrics
    system_metrics = {}
    try:
        import psutil
        system_metrics = {
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
        }
        batt = psutil.sensors_battery()
        if batt:
            system_metrics["battery_percent"] = round(batt.percent, 1)
            system_metrics["battery_charging"] = batt.power_plugged
    except ImportError:
        system_metrics["error"] = "psutil not installed"
    except Exception:
        pass

    return {
        "health": {
            "status": health.overall_status.value,
            "warnings": health.warnings,
            "modules": [
                {
                    "name": m.name,
                    "status": m.status.value,
                    "message": m.message,
                }
                for m in health.modules
            ],
        },
        "events_24h": events_24h,
        "active_incidents": active_incidents,
        "critical_events": [
            {
                "id": e.id,
                "title": e.title,
                "severity": e.severity,
                "source_module": e.source_module,
                "created_at": e.created_at.isoformat(),
            }
            for e in critical_list
        ],
        "system_metrics": system_metrics,
        "platform": health.platform_info,
    }
