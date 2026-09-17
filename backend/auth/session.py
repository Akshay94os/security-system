"""
AK Master Security System — JWT Session Management
Handles access tokens, refresh tokens, and session records.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.database.models import Session, User, utcnow

logger = logging.getLogger(__name__)

settings = get_settings()


# ──────────────────────────────────────────────────────────
# Token generation
# ──────────────────────────────────────────────────────────

def create_access_token(user_id: str, role: str, session_id: str) -> str:
    """Generate a short-lived JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {
        "sub": user_id,
        "role": role,
        "sid": session_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token() -> tuple[str, str]:
    """
    Generate a cryptographically secure refresh token.
    Returns (raw_token, hashed_token_for_storage).
    Never store the raw token.
    """
    raw = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT. Returns payload dict or None."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError as e:
        logger.debug("JWT decode failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────
# Session management
# ──────────────────────────────────────────────────────────

async def create_session(
    db: AsyncSession,
    user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    auth_method: str = "password",
) -> tuple[str, str, Session]:
    """
    Create a new session record and return (access_token, refresh_token, session).
    """
    raw_refresh, hashed_refresh = create_refresh_token()
    session_id = str(uuid.uuid4())

    session = Session(
        id=session_id,
        user_id=user.id,
        refresh_token_hash=hashed_refresh,
        ip_address=ip_address,
        user_agent=user_agent,
        auth_method=auth_method,
        is_active=True,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        ).replace(tzinfo=None),
        last_activity_at=utcnow(),
    )
    db.add(session)
    await db.flush()

    access_token = create_access_token(user.id, user.role, session_id)
    return access_token, raw_refresh, session


async def revoke_session(
    db: AsyncSession,
    session_id: str,
    reason: str = "logout",
) -> bool:
    """Revoke a session by ID."""
    result = await db.execute(
        update(Session)
        .where(Session.id == session_id, Session.is_active == True)  # noqa: E712
        .values(
            is_active=False,
            revoked_at=utcnow(),
            revoked_reason=reason,
        )
    )
    return result.rowcount > 0


async def get_active_session(db: AsyncSession, session_id: str) -> Optional[Session]:
    """Fetch an active session by ID."""
    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.is_active == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none()


async def validate_refresh_token(
    db: AsyncSession,
    session_id: str,
    raw_refresh_token: str,
) -> Optional[Session]:
    """Validate a refresh token. Returns session if valid."""
    session = await get_active_session(db, session_id)
    if not session:
        return None

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if session.expires_at < now:
        await revoke_session(db, session_id, "expired")
        return None

    token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
    if session.refresh_token_hash != token_hash:
        # Possible token theft — revoke session
        logger.warning("Refresh token mismatch for session %s — possible theft", session_id)
        await revoke_session(db, session_id, "token_mismatch_possible_theft")
        return None

    # Update last activity
    session.last_activity_at = utcnow()
    return session


async def revoke_all_user_sessions(
    db: AsyncSession,
    user_id: str,
    reason: str = "security_event",
) -> int:
    """Revoke all active sessions for a user. Returns count revoked."""
    result = await db.execute(
        update(Session)
        .where(Session.user_id == user_id, Session.is_active == True)  # noqa: E712
        .values(
            is_active=False,
            revoked_at=utcnow(),
            revoked_reason=reason,
        )
    )
    return result.rowcount
