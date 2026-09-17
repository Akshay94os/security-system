"""
AK Master Security System — Central Event Bus
Async event pipeline: Collector → Normalizer → Risk Engine → Policy → Notification → Audit

All security events flow through this bus with correlation IDs.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    # Authentication
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGIN_FACE = "AUTH_LOGIN_FACE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_SESSION_REVOKED = "AUTH_SESSION_REVOKED"
    AUTH_LOCKOUT = "AUTH_LOCKOUT"
    AUTH_RESET_REQUEST = "AUTH_RESET_REQUEST"
    AUTH_RESET_COMPLETE = "AUTH_RESET_COMPLETE"

    # Nexus / AI
    NEXUS_COMMAND = "NEXUS_COMMAND"
    NEXUS_TOOL_CALL = "NEXUS_TOOL_CALL"
    NEXUS_FIREWALL_BLOCK = "NEXUS_FIREWALL_BLOCK"
    NEXUS_PERMISSION_REQUEST = "NEXUS_PERMISSION_REQUEST"
    NEXUS_PERMISSION_GRANTED = "NEXUS_PERMISSION_GRANTED"
    NEXUS_PERMISSION_DENIED = "NEXUS_PERMISSION_DENIED"
    NEXUS_PROMPT_INJECTION = "NEXUS_PROMPT_INJECTION"
    NEXUS_TOOL_NOT_FOUND = "NEXUS_TOOL_NOT_FOUND"
    NEXUS_HALLUCINATION_BLOCKED = "NEXUS_HALLUCINATION_BLOCKED"

    # URL/Web
    URL_SCAN = "URL_SCAN"
    URL_BLOCKED = "URL_BLOCKED"
    URL_SUSPICIOUS = "URL_SUSPICIOUS"

    # Files
    FILE_SCAN = "FILE_SCAN"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    FILE_SUSPICIOUS = "FILE_SUSPICIOUS"

    # Process
    PROCESS_SUSPICIOUS = "PROCESS_SUSPICIOUS"
    PROCESS_KILLED = "PROCESS_KILLED"

    # Network
    NETWORK_SUSPICIOUS = "NETWORK_SUSPICIOUS"
    NETWORK_CONNECTION_BLOCKED = "NETWORK_CONNECTION_BLOCKED"

    # DLP
    DLP_SENSITIVE_DETECTED = "DLP_SENSITIVE_DETECTED"
    DLP_TRANSFER_BLOCKED = "DLP_TRANSFER_BLOCKED"

    # System
    SYSTEM_HEALTH_DEGRADED = "SYSTEM_HEALTH_DEGRADED"
    MODULE_FAILURE = "MODULE_FAILURE"
    POLICY_CHANGED = "POLICY_CHANGED"

    # Incidents
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"


@dataclass
class SecurityEvent:
    """Normalized security event flowing through the event bus."""
    event_type: EventType
    source_module: str
    title: str
    description: str = ""
    severity: str = "INFO"
    risk_score: float = 0.0
    affected_asset: Optional[str] = None
    affected_user_id: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────────────────────────────────
# Event Bus
# ──────────────────────────────────────────────────────────

class EventBus:
    """
    Async central event bus.
    Handlers are registered per event type or as catch-all.
    All events get a correlation ID.
    """

    def __init__(self):
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=10000)
        self._handlers: Dict[Optional[EventType], List[Callable]] = {}
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    def subscribe(
        self,
        handler: Callable[[SecurityEvent], Any],
        event_type: Optional[EventType] = None,
    ) -> None:
        """
        Register a handler for a specific event type, or None for all events.
        """
        key = event_type
        if key not in self._handlers:
            self._handlers[key] = []
        self._handlers[key].append(handler)

    async def publish(self, event: SecurityEvent) -> None:
        """Publish an event to the bus. Non-blocking."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning(
                "Event bus queue full — dropping event %s (correlation: %s)",
                event.event_type, event.correlation_id,
            )

    async def _dispatch(self, event: SecurityEvent) -> None:
        """Dispatch event to registered handlers."""
        handlers = (
            self._handlers.get(event.event_type, [])
            + self._handlers.get(None, [])
        )
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(
                    "Event handler %s failed for %s: %s",
                    handler.__name__, event.event_type, e,
                )

    async def _worker(self) -> None:
        """Background worker that processes events from the queue."""
        logger.info("Event bus worker started.")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Event bus worker error: %s", e)
        logger.info("Event bus worker stopped.")

    async def start(self) -> None:
        self._running = True
        self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        self._running = False
        if self._worker_task:
            await asyncio.wait_for(self._worker_task, timeout=5.0)


# Singleton event bus
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


async def publish_event(
    event_type: EventType,
    source_module: str,
    title: str,
    description: str = "",
    severity: str = "INFO",
    risk_score: float = 0.0,
    affected_asset: Optional[str] = None,
    affected_user_id: Optional[str] = None,
    raw_data: Optional[dict] = None,
    indicators: Optional[list] = None,
    correlation_id: Optional[str] = None,
) -> SecurityEvent:
    """Convenience function to create and publish a security event."""
    event = SecurityEvent(
        event_type=event_type,
        source_module=source_module,
        title=title,
        description=description,
        severity=severity,
        risk_score=risk_score,
        affected_asset=affected_asset,
        affected_user_id=affected_user_id,
        raw_data=raw_data or {},
        indicators=indicators or [],
        correlation_id=correlation_id or str(uuid.uuid4()),
    )
    bus = get_event_bus()
    await bus.publish(event)
    return event
