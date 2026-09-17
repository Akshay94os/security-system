"""
AK Master Security System — Authentication API Router
Handles: register, login (password + face), logout, refresh, password reset, session management.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.password import hash_password, validate_password_strength, verify_password
from backend.auth.session import (
    create_session, decode_access_token, get_active_session, revoke_session,
    revoke_all_user_sessions,
)
from backend.config import get_settings
from backend.database.engine import get_db
from backend.database.models import FaceTemplate, PasswordReset, Session, User, UserRole, utcnow
from backend.security.audit_log import write_audit_log
from backend.security.event_bus import EventType, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
bearer_scheme = HTTPBearer(auto_error=False)
settings = get_settings()


# ──────────────────────────────────────────────────────────
# Request/Response Models
# ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    biometric_consent: bool = False

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3–64 characters.")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, hyphens, and underscores.")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class FaceLoginRequest(BaseModel):
    username: str
    image_base64: str  # base64-encoded image


class PasswordResetRequestModel(BaseModel):
    email: EmailStr


class PasswordResetConfirmModel(BaseModel):
    token: str
    new_password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str


class RefreshRequest(BaseModel):
    session_id: str
    refresh_token: str


# ──────────────────────────────────────────────────────────
# Dependencies
# ──────────────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = payload.get("sub")
    session_id = payload.get("sid")

    # Verify session is still active
    session = await get_active_session(db, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or revoked")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))  # noqa: E712
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user


async def get_current_session_id(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[str]:
    if not credentials:
        return None
    payload = decode_access_token(credentials.credentials)
    return payload.get("sid") if payload else None


# ──────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    correlation_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    # Check existing username/email
    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == str(body.email))
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered.",
        )

    # Validate password strength
    is_strong, issues = validate_password_strength(body.password)
    if not is_strong:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Password does not meet security requirements.", "issues": issues},
        )

    user = User(
        id=str(uuid.uuid4()),
        username=body.username,
        email=str(body.email),
        password_hash=hash_password(body.password),
        role=UserRole.USER.value,
        biometric_consent=body.biometric_consent,
    )
    db.add(user)
    await db.flush()

    ua = request.headers.get("user-agent", "")
    access_token, refresh_token, session = await create_session(
        db, user, ip_address=ip, user_agent=ua, auth_method="password"
    )

    await write_audit_log(
        db=db,
        correlation_id=correlation_id,
        actor_user_id=user.id,
        action="USER_REGISTER",
        outcome="SUCCESS",
        ip_address=ip,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with username and password."""
    correlation_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")

    result = await db.execute(
        select(User).where(User.username == body.username, User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    # Check lockout
    if user and user.locked_until:
        if datetime.now(timezone.utc).replace(tzinfo=None) < user.locked_until:
            await write_audit_log(
                db=db, correlation_id=correlation_id, actor_user_id=user.id,
                action="AUTH_LOGIN_LOCKED", outcome="BLOCKED", ip_address=ip,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked due to too many failed attempts. Try again later.",
            )

    if not user or not verify_password(body.password, user.password_hash):
        # Record failed attempt
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= settings.account_lockout_threshold:
                from datetime import timedelta
                user.locked_until = (
                    datetime.now(timezone.utc) + timedelta(minutes=settings.account_lockout_minutes)
                ).replace(tzinfo=None)
                await publish_event(
                    EventType.AUTH_LOCKOUT, "auth",
                    f"Account locked: {user.username}",
                    severity="HIGH",
                    affected_user_id=user.id if user else None,
                    correlation_id=correlation_id,
                )

        await write_audit_log(
            db=db, correlation_id=correlation_id,
            actor_user_id=user.id if user else None,
            action="AUTH_LOGIN_FAILURE", outcome="FAILURE", ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # Successful login — reset failures
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    user.last_login_ip = ip

    access_token, refresh_token, session = await create_session(
        db, user, ip_address=ip, user_agent=ua, auth_method="password"
    )

    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=user.id,
        action="AUTH_LOGIN_SUCCESS", outcome="SUCCESS",
        auth_result="PASSWORD_OK", ip_address=ip,
    )
    await publish_event(
        EventType.AUTH_LOGIN_SUCCESS, "auth",
        f"Successful login: {user.username}",
        affected_user_id=user.id, correlation_id=correlation_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post("/login/face", response_model=TokenResponse)
async def login_face(
    request: Request,
    body: FaceLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with face recognition (1:1 verification)."""
    correlation_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")

    from backend.auth.face_auth import get_face_module_status, FaceAuthStatus, verify_face, FaceAuthResult
    if get_face_module_status() == FaceAuthStatus.UNAVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Face authentication is not available. Please use password authentication.",
        )

    result = await db.execute(
        select(User).where(User.username == body.username, User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()
    if not user or not user.biometric_consent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    # Get active face template
    template_result = await db.execute(
        select(FaceTemplate).where(
            FaceTemplate.user_id == user.id,
            FaceTemplate.is_active == True,  # noqa: E712
        )
    )
    template = template_result.scalar_one_or_none()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No face template enrolled. Please enroll using password login first.",
        )

    import base64
    try:
        image_bytes = base64.b64decode(body.image_base64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid image data.")

    auth_result, confidence = verify_face(
        image_bytes, template.encrypted_embedding, template.model_name
    )

    if auth_result != FaceAuthResult.VERIFIED:
        await write_audit_log(
            db=db, correlation_id=correlation_id, actor_user_id=user.id,
            action="AUTH_LOGIN_FACE_FAILURE", outcome="FAILURE",
            auth_result=auth_result.value, ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Face authentication failed: {auth_result.value}",
        )

    # Update template last_used
    template.last_used_at = utcnow()
    user.last_login_at = utcnow()
    user.last_login_ip = ip

    access_token, refresh_token, session = await create_session(
        db, user, ip_address=ip, user_agent=ua, auth_method="face"
    )

    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=user.id,
        action="AUTH_LOGIN_FACE_SUCCESS", outcome="SUCCESS",
        auth_result=f"FACE_VERIFIED confidence={confidence:.2f}", ip_address=ip,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    session_id: Optional[str] = Depends(get_current_session_id),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current session."""
    correlation_id = str(uuid.uuid4())
    if session_id:
        await revoke_session(db, session_id, "logout")
    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=current_user.id,
        action="AUTH_LOGOUT", outcome="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Logged out successfully."}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new access token."""
    from backend.auth.session import validate_refresh_token, create_access_token
    session = await validate_refresh_token(db, body.session_id, body.refresh_token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token.")

    result = await db.execute(select(User).where(User.id == session.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    new_access_token = create_access_token(user.id, user.role, session.id)
    # Note: we do NOT rotate the refresh token here for simplicity in Phase 1
    # Phase 2 will implement refresh token rotation

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=body.refresh_token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user profile."""
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "biometric_consent": current_user.biometric_consent,
        "created_at": current_user.created_at.isoformat(),
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
    }


@router.get("/sessions")
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List active sessions for the current user."""
    result = await db.execute(
        select(Session).where(
            Session.user_id == current_user.id,
            Session.is_active == True,  # noqa: E712
        )
    )
    sessions = result.scalars().all()
    return {
        "sessions": [
            {
                "id": s.id,
                "ip_address": s.ip_address,
                "auth_method": s.auth_method,
                "created_at": s.created_at.isoformat(),
                "last_activity_at": s.last_activity_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
            }
            for s in sessions
        ]
    }


@router.delete("/sessions/{session_id}")
async def revoke_other_session(
    session_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a specific session."""
    correlation_id = str(uuid.uuid4())
    session = await get_active_session(db, session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    await revoke_session(db, session_id, "revoked_by_user")
    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=current_user.id,
        action="AUTH_SESSION_REVOKED", outcome="SUCCESS", target=session_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Session revoked."}


@router.post("/face/enroll")
async def enroll_face(
    request: Request,
    image_base64: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enroll a face for biometric authentication."""
    correlation_id = str(uuid.uuid4())

    if not current_user.biometric_consent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Biometric consent not given. Update account settings first.",
        )

    from backend.auth.face_auth import enroll_face as do_enroll, get_face_module_status, FaceAuthStatus
    if get_face_module_status() == FaceAuthStatus.UNAVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Face authentication module not available.")

    import base64
    try:
        image_bytes = base64.b64decode(image_base64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid image data.")

    result = do_enroll(image_bytes)
    if not result.success:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Face enrollment failed: {result.error}")

    # Deactivate old templates
    await db.execute(
        update(FaceTemplate)
        .where(FaceTemplate.user_id == current_user.id)
        .values(is_active=False)
    )

    template = FaceTemplate(
        user_id=current_user.id,
        encrypted_embedding=result.encrypted_embedding,
        model_name=result.model_name,
        quality_score=result.quality_score,
    )
    db.add(template)

    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=current_user.id,
        action="FACE_ENROLLMENT", outcome="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    return {
        "message": "Face enrolled successfully.",
        "model": result.model_name,
        "quality_score": result.quality_score,
    }


@router.delete("/face/template")
async def delete_face_template(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete all face templates (biometric data deletion per privacy policy)."""
    correlation_id = str(uuid.uuid4())
    await db.execute(
        update(FaceTemplate)
        .where(FaceTemplate.user_id == current_user.id)
        .values(is_active=False, encrypted_embedding="[DELETED]")
    )
    await write_audit_log(
        db=db, correlation_id=correlation_id, actor_user_id=current_user.id,
        action="FACE_TEMPLATE_DELETED", outcome="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "All face biometric data has been deleted."}
