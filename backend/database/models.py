"""
AK Master Security System — Database Models
All SQLAlchemy models for Phase 1.

Design principles:
- All tables have: id (UUID), created_at, updated_at
- Soft-delete where appropriate (deleted_at)
- Correlation IDs throughout for audit linking
- No plaintext passwords, no raw biometric images
- Audit trail foreign keys where appropriate
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, JSON, String, Text, UniqueConstraint, Index
)
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # store naive UTC


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ──────────────────────────────────────────────────────────
# ENUMERATIONS
# ──────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PermissionDecision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CONFIRMATION = "ALLOW_WITH_CONFIRMATION"
    REQUIRE_AUTHENTICATION = "REQUIRE_AUTHENTICATION"
    SANDBOX = "SANDBOX"
    DENY = "DENY"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class UserRole(str, Enum):
    USER = "USER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


# ──────────────────────────────────────────────────────────
# USER & IDENTITY
# ──────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=new_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default=UserRole.USER.value, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(64), nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    biometric_consent = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    # Relationships
    sessions = relationship("Session", back_populates="user", lazy="dynamic")
    face_templates = relationship("FaceTemplate", back_populates="user", lazy="dynamic")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="dynamic")
    password_resets = relationship("PasswordReset", back_populates="user", lazy="dynamic")
    permission_requests = relationship("PermissionRequest", back_populates="user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class FaceTemplate(Base):
    """
    Stores biometric face embedding — NOT raw images.
    Embeddings are encrypted at application level before storage.
    """
    __tablename__ = "face_templates"

    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    # Encrypted embedding blob — never the raw face image
    encrypted_embedding = Column(Text, nullable=False)
    embedding_version = Column(String(32), default="v1", nullable=False)
    model_name = Column(String(128), nullable=False)
    quality_score = Column(Float, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    enrolled_at = Column(DateTime, default=utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="face_templates")

    __table_args__ = (
        Index("ix_face_template_user_active", "user_id", "is_active"),
    )


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    refresh_token_hash = Column(String(256), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    device_fingerprint = Column(String(256), nullable=True)
    auth_method = Column(String(32), default="password", nullable=False)  # password, face, mfa
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity_at = Column(DateTime, default=utcnow, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(256), nullable=True)
    suspicious_flag = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("ix_session_user_active", "user_id", "is_active"),
    )


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(256), nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="password_resets")


# ──────────────────────────────────────────────────────────
# TOOL REGISTRY & PERMISSIONS
# ──────────────────────────────────────────────────────────

class ToolRegistration(Base):
    __tablename__ = "tool_registrations"

    id = Column(String(36), primary_key=True, default=new_uuid)
    tool_id = Column(String(128), unique=True, nullable=False, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(String(32), default="1.0.0", nullable=False)
    category = Column(String(64), nullable=False)
    risk_level = Column(Integer, default=0, nullable=False)  # 0–4
    required_permissions = Column(JSON, default=list, nullable=False)
    input_schema = Column(JSON, default=dict, nullable=False)
    output_schema = Column(JSON, default=dict, nullable=False)
    supported_os = Column(JSON, default=list, nullable=False)
    timeout_seconds = Column(Integer, default=30, nullable=False)
    requires_confirmation = Column(Boolean, default=False, nullable=False)
    requires_audit = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    scope = Column(String(32), default="user", nullable=False)  # system, role, user
    scope_id = Column(String(36), nullable=True)  # user_id or role name
    tool_id = Column(String(128), nullable=True)  # NULL = applies to all
    action = Column(String(32), nullable=False)  # ALLOW, DENY, REQUIRE_CONFIRMATION, etc.
    conditions = Column(JSON, default=dict, nullable=False)
    priority = Column(Integer, default=100, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_policy_scope_tool", "scope", "tool_id", "is_active"),
    )


class PermissionRequest(Base):
    __tablename__ = "permission_requests"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    tool_id = Column(String(128), nullable=False)
    parameters = Column(JSON, default=dict, nullable=False)
    risk_level = Column(Integer, nullable=False)
    decision = Column(String(32), nullable=False)  # PermissionDecision
    policy_matched = Column(String(36), nullable=True)
    requires_auth = Column(Boolean, default=False, nullable=False)
    user_confirmed = Column(Boolean, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="permission_requests")


# ──────────────────────────────────────────────────────────
# SECURITY EVENTS & INCIDENTS
# ──────────────────────────────────────────────────────────

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    source_module = Column(String(64), nullable=False)
    severity = Column(String(16), default=EventSeverity.INFO.value, nullable=False, index=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict, nullable=False)
    indicators = Column(JSON, default=list, nullable=False)
    affected_asset = Column(String(512), nullable=True)
    affected_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    is_resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    incident = relationship("Incident", back_populates="events")

    __table_args__ = (
        Index("ix_security_event_type_severity", "event_type", "severity"),
        Index("ix_security_event_created", "created_at"),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=new_uuid)
    incident_number = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), default=EventSeverity.MEDIUM.value, nullable=False)
    status = Column(String(32), default=IncidentStatus.OPEN.value, nullable=False, index=True)
    affected_assets = Column(JSON, default=list, nullable=False)
    indicators = Column(JSON, default=list, nullable=False)
    evidence = Column(JSON, default=list, nullable=False)
    timeline = Column(JSON, default=list, nullable=False)
    actions_taken = Column(JSON, default=list, nullable=False)
    analyst_notes = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    assigned_to = Column(String(36), ForeignKey("users.id"), nullable=True)
    detected_at = Column(DateTime, default=utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    events = relationship("SecurityEvent", back_populates="incident", lazy="dynamic")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    event_id = Column(String(36), ForeignKey("security_events.id"), nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    alert_type = Column(String(64), nullable=False)  # CRITICAL, WARNING, INFO, PERMISSION
    title = Column(String(512), nullable=False)
    message = Column(Text, nullable=False)
    action_required = Column(Boolean, default=False, nullable=False)
    is_dismissed = Column(Boolean, default=False, nullable=False)
    dismissed_at = Column(DateTime, nullable=True)
    snoozed_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────────────────
# AUDIT LOG (tamper-resistant)
# ──────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Append-only audit log. Records are HMAC-signed.
    NEVER update or delete records — only INSERT.
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    sequence_number = Column(Integer, nullable=False, index=True)
    actor_user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    actor_type = Column(String(32), default="user", nullable=False)  # user, system, nexus
    action = Column(String(128), nullable=False, index=True)
    tool_id = Column(String(128), nullable=True)
    target = Column(String(512), nullable=True)
    parameters_redacted = Column(JSON, default=dict, nullable=False)
    policy_result = Column(String(32), nullable=True)
    permission_result = Column(String(32), nullable=True)
    auth_result = Column(String(32), nullable=True)
    outcome = Column(String(32), nullable=False)  # SUCCESS, FAILURE, BLOCKED, PARTIAL
    error_code = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    hmac_signature = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_log_actor_action", "actor_user_id", "action"),
        Index("ix_audit_log_created_seq", "created_at", "sequence_number"),
    )


# ──────────────────────────────────────────────────────────
# AI / NEXUS COMMANDS
# ──────────────────────────────────────────────────────────

class AICommand(Base):
    __tablename__ = "ai_commands"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    input_text = Column(Text, nullable=False)
    parsed_intent = Column(JSON, default=dict, nullable=False)
    planned_steps = Column(JSON, default=list, nullable=False)
    execution_result = Column(JSON, default=dict, nullable=False)
    firewall_decision = Column(String(32), nullable=True)
    permission_decision = Column(String(32), nullable=True)
    status = Column(String(32), default="PENDING", nullable=False, index=True)
    error = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    command_id = Column(String(36), ForeignKey("ai_commands.id"), nullable=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    tool_id = Column(String(128), nullable=False)
    parameters = Column(JSON, default=dict, nullable=False)
    firewall_decision = Column(String(32), nullable=False)
    firewall_reason = Column(Text, nullable=True)
    permission_decision = Column(String(32), nullable=True)
    auth_required = Column(Boolean, default=False, nullable=False)
    auth_passed = Column(Boolean, nullable=True)
    execution_output = Column(JSON, default=dict, nullable=False)
    verified_result = Column(JSON, default=dict, nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)
    error = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)


# ──────────────────────────────────────────────────────────
# THREAT INTELLIGENCE
# ──────────────────────────────────────────────────────────

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(String(36), primary_key=True, default=new_uuid)
    ioc_type = Column(String(32), nullable=False, index=True)  # url, domain, ip, hash, email
    ioc_value = Column(String(1024), nullable=False, index=True)
    risk_level = Column(String(16), nullable=False)
    source = Column(String(256), nullable=False)
    confidence = Column(Float, default=0.0, nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    raw_data = Column(JSON, default=dict, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_local = Column(Boolean, default=False, nullable=False)  # local rule vs external feed
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("ioc_type", "ioc_value", "source", name="uq_ti_ioc_source"),
        Index("ix_ti_type_value", "ioc_type", "ioc_value"),
    )


# ──────────────────────────────────────────────────────────
# URL / FILE / NETWORK / PROCESS RECORDS
# ──────────────────────────────────────────────────────────

class URLScanRecord(Base):
    __tablename__ = "url_scan_records"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(512), nullable=True, index=True)
    risk_level = Column(String(16), default="UNKNOWN", nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    signals = Column(JSON, default=list, nullable=False)
    explanation = Column(Text, nullable=True)
    action_taken = Column(String(32), default="NONE", nullable=False)  # NONE, BLOCKED, WARNED
    requested_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


class FileScanRecord(Base):
    __tablename__ = "file_scan_records"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    file_path = Column(Text, nullable=False)
    file_name = Column(String(512), nullable=False, index=True)
    file_size_bytes = Column(Integer, nullable=True)
    sha256_hash = Column(String(64), nullable=True, index=True)
    mime_type = Column(String(256), nullable=True)
    risk_level = Column(String(16), default="UNKNOWN", nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    signals = Column(JSON, default=list, nullable=False)
    action_taken = Column(String(32), default="NONE", nullable=False)
    quarantine_path = Column(Text, nullable=True)
    requested_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


class NetworkEventRecord(Base):
    __tablename__ = "network_events"

    id = Column(String(36), primary_key=True, default=new_uuid)
    correlation_id = Column(String(36), nullable=False, index=True)
    local_address = Column(String(256), nullable=True)
    remote_address = Column(String(256), nullable=True, index=True)
    remote_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    process_name = Column(String(512), nullable=True)
    process_pid = Column(Integer, nullable=True)
    status = Column(String(32), nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


# ──────────────────────────────────────────────────────────
# AUTOMATIONS & INTEGRATIONS
# ──────────────────────────────────────────────────────────

class Automation(Base):
    __tablename__ = "automations"

    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    trigger_type = Column(String(64), nullable=False)
    trigger_config = Column(JSON, default=dict, nullable=False)
    action_tool_id = Column(String(128), nullable=False)
    action_params = Column(JSON, default=dict, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    last_triggered_at = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(128), unique=True, nullable=False)
    provider = Column(String(64), nullable=False)
    is_connected = Column(Boolean, default=False, nullable=False)
    config_encrypted = Column(Text, nullable=True)  # Encrypted JSON config
    scopes = Column(JSON, default=list, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    connected_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


# ──────────────────────────────────────────────────────────
# RESEARCH
# ──────────────────────────────────────────────────────────

class ResearchExperiment(Base):
    __tablename__ = "research_experiments"

    id = Column(String(36), primary_key=True, default=new_uuid)
    experiment_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    module = Column(String(64), nullable=False)  # url_scanner, dlp, firewall, etc.
    model_version = Column(String(64), nullable=True)
    dataset_info = Column(JSON, default=dict, nullable=False)
    config = Column(JSON, default=dict, nullable=False)
    metrics = Column(JSON, default=dict, nullable=False)
    results = Column(JSON, default=dict, nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
