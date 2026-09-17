"""
AK Master Security System — Health, Nexus Command, Events, and Tools API Routers
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.engine import get_db
from backend.database.models import AuditLog, SecurityEvent, User
from backend.security.health_monitor import run_health_check

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)


# ──────────────────────────────────────────────────────────
# Health Router
# ──────────────────────────────────────────────────────────

health_router = APIRouter(prefix="/health", tags=["Health"])


@health_router.get("")
async def health_check():
    """Basic health check — returns overall system status."""
    health = await run_health_check()
    return {
        "status": health.overall_status.value,
        "warnings": health.warnings,
        "platform": health.platform_info,
        "checked_at": health.checked_at.isoformat(),
    }


@health_router.get("/detailed")
async def health_check_detailed():
    """
    Detailed health check — returns status of every security module.
    CRITICAL POLICY: Never claims full protection when any module is degraded.
    """
    health = await run_health_check()
    return {
        "overall_status": health.overall_status.value,
        "warnings": health.warnings,
        "platform": health.platform_info,
        "checked_at": health.checked_at.isoformat(),
        "modules": [
            {
                "name": m.name,
                "status": m.status.value,
                "message": m.message,
                "latency_ms": m.latency_ms,
                "last_checked": m.last_checked.isoformat() if m.last_checked else None,
            }
            for m in health.modules
        ],
    }


# ──────────────────────────────────────────────────────────
# Nexus Command Router
# ──────────────────────────────────────────────────────────

nexus_router = APIRouter(prefix="/nexus", tags=["Nexus"])


class NexusCommandRequest(BaseModel):
    command: str
    session_id: Optional[str] = None


@nexus_router.post("/command")
async def nexus_command(
    body: NexusCommandRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit a natural language command to AK Nexus.
    All commands pass through the full security pipeline.
    """
    from backend.auth.session import decode_access_token, get_active_session
    from nexus.agent.executor import NexusExecutor

    user_id = "anonymous"
    user_role = "USER"
    session_active = False

    if credentials:
        payload = decode_access_token(credentials.credentials)
        if payload:
            user_id = payload.get("sub", "anonymous")
            user_role = payload.get("role", "USER")
            session_id = payload.get("sid")
            session = await get_active_session(db, session_id)
            session_active = session is not None

    executor = NexusExecutor()
    result = await executor.execute(
        user_input=body.command,
        user_id=user_id,
        user_role=user_role,
        session_active=session_active,
        db=db,
    )

    return {
        "correlation_id": result.correlation_id,
        "status": result.status.value,
        "message": result.user_message,
        "requires_confirmation": result.requires_confirmation,
        "confirmation_message": result.confirmation_message,
        "requires_auth": result.requires_auth,
        "firewall_decision": result.firewall_decision,
        "tool_output": result.tool_output,
        "steps_taken": result.steps_taken,
        "error": result.error,
    }


# ──────────────────────────────────────────────────────────
# Security Events Router
# ──────────────────────────────────────────────────────────

events_router = APIRouter(prefix="/events", tags=["Security Events"])


@events_router.get("")
async def list_events(
    limit: int = Query(default=50, le=200),
    severity: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """List recent security events."""
    query = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
    if severity:
        query = query.where(SecurityEvent.severity == severity.upper())
    result = await db.execute(query)
    events = result.scalars().all()
    return {
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "title": e.title,
                "source_module": e.source_module,
                "risk_score": e.risk_score,
                "created_at": e.created_at.isoformat(),
                "is_resolved": e.is_resolved,
            }
            for e in events
        ],
    }


# ──────────────────────────────────────────────────────────
# Audit Log Router
# ──────────────────────────────────────────────────────────

audit_router = APIRouter(prefix="/audit", tags=["Audit"])


@audit_router.get("")
async def list_audit_logs(
    limit: int = Query(default=50, le=200),
    action: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """List recent audit log entries."""
    from backend.security.audit_log import verify_audit_record
    query = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
    if action:
        query = query.where(AuditLog.action == action.upper())
    result = await db.execute(query)
    logs = result.scalars().all()

    entries = []
    for log in logs:
        verified = verify_audit_record(log)
        entries.append({
            "id": log.id,
            "sequence_number": log.sequence_number,
            "correlation_id": log.correlation_id,
            "actor_user_id": log.actor_user_id,
            "actor_type": log.actor_type,
            "action": log.action,
            "tool_id": log.tool_id,
            "target": log.target,
            "outcome": log.outcome,
            "policy_result": log.policy_result,
            "permission_result": log.permission_result,
            "created_at": log.created_at.isoformat(),
            "hmac_verified": verified,  # Show tamper detection status
        })

    return {"count": len(entries), "logs": entries}


# ──────────────────────────────────────────────────────────
# Tool Registry Router
# ──────────────────────────────────────────────────────────

tools_router = APIRouter(prefix="/tools", tags=["Tools"])


@tools_router.get("")
async def list_tools(category: Optional[str] = Query(default=None)):
    """List all registered tools and their metadata."""
    from nexus.tools.registry import get_tool_registry
    registry = get_tool_registry()
    tools = registry.list_tools(category=category)
    return {
        "count": len(tools),
        "tools": [
            {
                "tool_id": t.tool_id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "risk_level": t.risk_level,
                "version": t.version,
                "requires_confirmation": t.requires_confirmation,
                "supported_os": t.supported_os,
                "is_active": t.is_active,
            }
            for t in tools
        ],
        "stats": registry.get_stats(),
    }
