"""
AK Master Security System — Audit Log
Append-only, HMAC-signed audit records.

SECURITY DESIGN:
- Every security-relevant action is recorded
- HMAC-SHA256 signature for tamper detection
- Sequence numbers for gap detection
- Sensitive parameters are REDACTED before storage
- Never update or delete records — only INSERT
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.database.models import AuditLog, utcnow

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────
# Sensitive parameter redaction
# ──────────────────────────────────────────────────────────

_SENSITIVE_KEYS = frozenset({
    "password", "token", "secret", "key", "credential", "auth",
    "embedding", "biometric", "ssn", "card", "cvv", "pin",
    "api_key", "access_token", "refresh_token", "private_key",
})


def redact_parameters(params: dict) -> dict:
    """
    Recursively redact sensitive keys from a parameter dict.
    Used before storing in audit log.
    """
    result = {}
    for k, v in params.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            result[k] = "[REDACTED]"
        elif isinstance(v, dict):
            result[k] = redact_parameters(v)
        elif isinstance(v, list):
            result[k] = ["[REDACTED]" if isinstance(i, str) and len(i) > 20 else i for i in v]
        else:
            result[k] = v
    return result


# ──────────────────────────────────────────────────────────
# HMAC signing
# ──────────────────────────────────────────────────────────

def _compute_hmac(record_data: str) -> str:
    """Compute HMAC-SHA256 over the serialized record data."""
    settings = get_settings()
    key = settings.audit_hmac_key.encode()
    sig = hmac.new(key, record_data.encode(), hashlib.sha256)
    return sig.hexdigest()


def _build_signable_string(
    record_id: str,
    correlation_id: str,
    sequence_number: int,
    actor_user_id: Optional[str],
    action: str,
    tool_id: Optional[str],
    target: Optional[str],
    outcome: str,
    created_at: str,
) -> str:
    """Canonical string for HMAC signing."""
    parts = [
        record_id, correlation_id, str(sequence_number),
        actor_user_id or "", action, tool_id or "",
        target or "", outcome, created_at,
    ]
    return "|".join(parts)


def verify_audit_record(record: AuditLog) -> bool:
    """
    Verify the HMAC signature of an audit record.
    Returns True if untampered, False if signature mismatch.
    """
    signable = _build_signable_string(
        record_id=record.id,
        correlation_id=record.correlation_id,
        sequence_number=record.sequence_number,
        actor_user_id=record.actor_user_id,
        action=record.action,
        tool_id=record.tool_id,
        target=record.target,
        outcome=record.outcome,
        created_at=record.created_at.isoformat(),
    )
    expected = _compute_hmac(signable)
    return hmac.compare_digest(expected, record.hmac_signature)


# ──────────────────────────────────────────────────────────
# Audit log writer
# ──────────────────────────────────────────────────────────

async def write_audit_log(
    db: AsyncSession,
    *,
    correlation_id: str,
    actor_user_id: Optional[str],
    action: str,
    outcome: str,
    actor_type: str = "user",
    tool_id: Optional[str] = None,
    target: Optional[str] = None,
    parameters: Optional[dict] = None,
    policy_result: Optional[str] = None,
    permission_result: Optional[str] = None,
    auth_result: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """
    Create and store an immutable, HMAC-signed audit log entry.
    This function should be called for EVERY security-relevant action.
    """
    # Get next sequence number
    result = await db.execute(select(func.count()).select_from(AuditLog))
    count = result.scalar() or 0
    sequence_number = count + 1

    record_id = str(uuid.uuid4())
    now = utcnow()

    signable = _build_signable_string(
        record_id=record_id,
        correlation_id=correlation_id,
        sequence_number=sequence_number,
        actor_user_id=actor_user_id,
        action=action,
        tool_id=tool_id,
        target=target,
        outcome=outcome,
        created_at=now.isoformat(),
    )
    hmac_sig = _compute_hmac(signable)

    params_redacted = redact_parameters(parameters or {})

    log_entry = AuditLog(
        id=record_id,
        correlation_id=correlation_id,
        sequence_number=sequence_number,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        tool_id=tool_id,
        target=target,
        parameters_redacted=params_redacted,
        policy_result=policy_result,
        permission_result=permission_result,
        auth_result=auth_result,
        outcome=outcome,
        error_code=error_code,
        error_message=error_message,
        ip_address=ip_address,
        hmac_signature=hmac_sig,
        created_at=now,
    )
    db.add(log_entry)
    await db.flush()

    logger.info(
        "AUDIT | seq=%d | correlation=%s | actor=%s | action=%s | outcome=%s",
        sequence_number, correlation_id, actor_user_id, action, outcome,
    )
    return log_entry
