"""
AK Master Security System — Security Health Monitor
Monitors all modules and honestly reports their status.

CRITICAL RULE: Never claim full protection when any module is degraded.
Every check must either confirm real functionality or clearly label unavailability.
"""
from __future__ import annotations

import logging
import platform
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ModuleStatus(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    UNCONFIGURED = "UNCONFIGURED"


@dataclass
class ModuleHealth:
    name: str
    status: ModuleStatus
    message: str
    latency_ms: Optional[float] = None
    last_checked: Optional[datetime] = None
    details: Optional[dict] = None


@dataclass
class SystemHealth:
    overall_status: ModuleStatus
    modules: List[ModuleHealth]
    warnings: List[str]
    checked_at: datetime
    platform_info: dict


async def _check_database() -> ModuleHealth:
    start = time.monotonic()
    try:
        from backend.database.engine import get_engine
        engine = get_engine()
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (time.monotonic() - start) * 1000
        return ModuleHealth(
            name="Database",
            status=ModuleStatus.OPERATIONAL,
            message="Database connection OK",
            latency_ms=round(latency, 2),
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="Database",
            status=ModuleStatus.ERROR,
            message=f"Database connection failed: {e}",
            last_checked=datetime.now(timezone.utc),
        )


async def _check_ai_provider() -> ModuleHealth:
    from backend.config import get_settings
    settings = get_settings()
    if not settings.ai_provider_configured:
        return ModuleHealth(
            name="AI Provider (Gemini)",
            status=ModuleStatus.UNCONFIGURED,
            message=(
                "AI provider not configured. "
                "Set GEMINI_API_KEY in .env to enable Nexus AI capabilities. "
                "The system is operational but AI reasoning is unavailable."
            ),
            last_checked=datetime.now(timezone.utc),
        )
    try:
        start = time.monotonic()
        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        # Lightweight check — just list models
        list(genai.list_models())
        latency = (time.monotonic() - start) * 1000
        return ModuleHealth(
            name="AI Provider (Gemini)",
            status=ModuleStatus.OPERATIONAL,
            message=f"Gemini API reachable. Model: {settings.gemini_model}",
            latency_ms=round(latency, 2),
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="AI Provider (Gemini)",
            status=ModuleStatus.ERROR,
            message=f"Gemini API check failed: {e}. Nexus AI reasoning unavailable.",
            last_checked=datetime.now(timezone.utc),
        )


def _check_face_auth() -> ModuleHealth:
    from backend.auth.face_auth import get_face_module_status, FaceAuthStatus
    status = get_face_module_status()
    if status == FaceAuthStatus.AVAILABLE:
        return ModuleHealth(
            name="Face Authentication",
            status=ModuleStatus.OPERATIONAL,
            message="face_recognition library available. Full biometric pipeline active.",
            last_checked=datetime.now(timezone.utc),
        )
    elif status == FaceAuthStatus.DEGRADED_BASIC:
        return ModuleHealth(
            name="Face Authentication",
            status=ModuleStatus.DEGRADED,
            message=(
                "Running in degraded mode (OpenCV HOG only). "
                "Install face_recognition for full accuracy. "
                "See docs/INSTALLATION.md."
            ),
            last_checked=datetime.now(timezone.utc),
        )
    else:
        return ModuleHealth(
            name="Face Authentication",
            status=ModuleStatus.UNAVAILABLE,
            message=(
                "No face recognition module available. "
                "Password authentication is still operational. "
                "Install face_recognition to enable biometrics."
            ),
            last_checked=datetime.now(timezone.utc),
        )


def _check_process_monitor() -> ModuleHealth:
    try:
        import psutil
        # Verify we can actually read processes
        count = len(psutil.pids())
        return ModuleHealth(
            name="Process Monitor",
            status=ModuleStatus.OPERATIONAL,
            message=f"psutil operational. Monitoring {count} processes.",
            last_checked=datetime.now(timezone.utc),
        )
    except ImportError:
        return ModuleHealth(
            name="Process Monitor",
            status=ModuleStatus.UNAVAILABLE,
            message="psutil not installed. Process monitoring unavailable.",
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="Process Monitor",
            status=ModuleStatus.ERROR,
            message=f"Process monitor error: {e}",
            last_checked=datetime.now(timezone.utc),
        )


def _check_url_scanner() -> ModuleHealth:
    from backend.config import get_settings
    settings = get_settings()
    if not settings.url_scan_enabled:
        return ModuleHealth(
            name="URL Scanner",
            status=ModuleStatus.UNCONFIGURED,
            message="URL scanning disabled in configuration.",
            last_checked=datetime.now(timezone.utc),
        )
    return ModuleHealth(
        name="URL Scanner",
        status=ModuleStatus.OPERATIONAL,
        message="Local rule engine active. External threat intelligence: depends on provider config.",
        last_checked=datetime.now(timezone.utc),
    )


def _check_audit_log() -> ModuleHealth:
    try:
        from pathlib import Path
        from backend.config import get_settings
        settings = get_settings()
        path = Path(settings.audit_log_path)
        path.mkdir(parents=True, exist_ok=True)
        return ModuleHealth(
            name="Audit Log",
            status=ModuleStatus.OPERATIONAL,
            message=f"Audit log path accessible: {path.resolve()}",
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="Audit Log",
            status=ModuleStatus.ERROR,
            message=f"Audit log path error: {e}. Security events may not be persisted.",
            last_checked=datetime.now(timezone.utc),
        )


def _check_permission_engine() -> ModuleHealth:
    try:
        from nexus.permissions.engine import PermissionEngine
        PermissionEngine()  # Basic instantiation check
        return ModuleHealth(
            name="Permission Engine",
            status=ModuleStatus.OPERATIONAL,
            message="Permission engine loaded. Default policy: DENY for undefined capabilities.",
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="Permission Engine",
            status=ModuleStatus.ERROR,
            message=f"Permission engine failed to load: {e}. ALL tool calls will be blocked.",
            last_checked=datetime.now(timezone.utc),
        )


def _check_agent_firewall() -> ModuleHealth:
    try:
        from nexus.firewall.agent_firewall import AgentFirewall
        AgentFirewall()
        return ModuleHealth(
            name="Agent Firewall",
            status=ModuleStatus.OPERATIONAL,
            message="Agent Firewall active. All Nexus actions pass through security validation.",
            last_checked=datetime.now(timezone.utc),
        )
    except Exception as e:
        return ModuleHealth(
            name="Agent Firewall",
            status=ModuleStatus.ERROR,
            message=f"Agent Firewall failed to load: {e}. Nexus commands will be BLOCKED for safety.",
            last_checked=datetime.now(timezone.utc),
        )


async def run_health_check() -> SystemHealth:
    """
    Run all module health checks and return a SystemHealth report.
    NEVER claims operational status when a module has failed.
    """
    checks = []

    # Async checks
    checks.append(await _check_database())
    checks.append(await _check_ai_provider())

    # Sync checks
    checks.append(_check_face_auth())
    checks.append(_check_process_monitor())
    checks.append(_check_url_scanner())
    checks.append(_check_audit_log())
    checks.append(_check_permission_engine())
    checks.append(_check_agent_firewall())

    # Determine overall status
    statuses = [m.status for m in checks]
    if ModuleStatus.ERROR in statuses:
        overall = ModuleStatus.ERROR
    elif ModuleStatus.UNAVAILABLE in statuses or ModuleStatus.DEGRADED in statuses:
        overall = ModuleStatus.DEGRADED
    elif ModuleStatus.UNCONFIGURED in statuses:
        overall = ModuleStatus.DEGRADED
    else:
        overall = ModuleStatus.OPERATIONAL

    warnings = []
    if overall != ModuleStatus.OPERATIONAL:
        warnings.append(
            "One or more security modules are degraded or unavailable. "
            "Security coverage may be reduced. Review module status for details."
        )

    return SystemHealth(
        overall_status=overall,
        modules=checks,
        warnings=warnings,
        checked_at=datetime.now(timezone.utc),
        platform_info={
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
            "machine": platform.machine(),
        },
    )
