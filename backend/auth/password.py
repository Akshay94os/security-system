"""
AK Master Security System — Password Hashing & Validation
Uses bcrypt via passlib. NEVER store plaintext passwords.
"""
from __future__ import annotations

import re
from typing import Tuple

import bcrypt

# Common patterns that should not appear in passwords
_BREACH_PATTERNS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "admin", "welcome", "monkey", "master", "dragon",
]


def hash_password(password: str) -> str:
    """Hash a password using bcrypt. Returns the hash string."""
    pwd_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, list[str]]:
    """
    Validate password against security policy.
    Returns (is_valid, list_of_issues).
    """
    issues = []

    if len(password) < 12:
        issues.append("Password must be at least 12 characters long.")

    if not re.search(r"[A-Z]", password):
        issues.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        issues.append("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        issues.append("Password must contain at least one digit.")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        issues.append("Password must contain at least one special character.")

    lower = password.lower()
    for pattern in _BREACH_PATTERNS:
        if pattern in lower:
            issues.append(f"Password contains a commonly used pattern: '{pattern}'.")
            break

    return len(issues) == 0, issues
