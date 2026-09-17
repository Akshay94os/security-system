"""
AK Master Security System — Central Configuration
Uses Pydantic Settings for type-safe, validated configuration from environment variables.
NEVER hard-code secrets here — use .env file.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AK Master Security System"
    app_env: str = "development"
    secret_key: str = secrets.token_hex(64)
    debug: bool = False
    log_level: str = "INFO"
    version: str = "1.0.0-phase1"

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/ak_master.db"

    # JWT
    jwt_secret_key: str = secrets.token_hex(64)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Session
    session_cookie_secure: bool = False
    session_cookie_httponly: bool = True

    # Rate Limiting
    rate_limit_login_per_minute: int = 5
    rate_limit_api_per_minute: int = 60
    account_lockout_threshold: int = 5
    account_lockout_minutes: int = 15

    # AI Provider — Google Gemini
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"
    gemini_timeout_seconds: int = 30

    # Face Authentication
    face_auth_enabled: bool = False
    face_model_path: str = ""
    face_embedding_encryption_key: str = secrets.token_hex(16)  # 32 hex chars = 16 bytes

    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@ak-security.local"
    email_reset_token_expire_minutes: int = 15

    # Security Modules
    url_scan_enabled: bool = True
    file_scan_enabled: bool = True
    process_monitor_enabled: bool = True
    dlp_enabled: bool = True
    network_monitor_enabled: bool = True

    # CORS
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Audit
    audit_log_path: str = "./data/audit"
    audit_hmac_key: str = secrets.token_hex(16)

    # Quarantine
    quarantine_path: str = "./data/quarantine"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_provider_configured(self) -> bool:
        return bool(self.gemini_api_key and self.gemini_api_key != "YOUR_GEMINI_API_KEY_HERE")

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user)

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() in ("development", "dev")

    @model_validator(mode="after")
    def validate_secret_keys(self) -> "Settings":
        """Warn when using default insecure keys in non-development mode."""
        if not self.is_development:
            if self.secret_key.startswith("CHANGE_ME"):
                raise ValueError("SECRET_KEY must be set in production")
            if self.jwt_secret_key.startswith("CHANGE_ME"):
                raise ValueError("JWT_SECRET_KEY must be set in production")
            if self.audit_hmac_key.startswith("CHANGE_ME"):
                raise ValueError("AUDIT_HMAC_KEY must be set in production")
        return self

    def ensure_data_dirs(self) -> None:
        """Create required data directories if they do not exist."""
        for path_str in [self.audit_log_path, self.quarantine_path, "./data"]:
            Path(path_str).mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton settings instance. Cached after first call."""
    settings = Settings()
    settings.ensure_data_dirs()
    return settings
