"""
AK Master Security System — DLP Engine (§18)
Data Loss Prevention — Sensitive data pattern detection.

Features:
- Email address detection
- Phone number detection
- API key / access token patterns
- Passwords in plaintext
- Private key detection
- Database credential detection
- Financial identifiers
- Source code secret detection
- Entropy analysis for high-entropy strings
- Contextual classification
- Allowlists and false-positive suppression

CRITICAL: Never transmit detected sensitive data externally.
Redact values before any external AI analysis.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DLPSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DLPCategory(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    PASSWORD = "PASSWORD"
    PRIVATE_KEY = "PRIVATE_KEY"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    FINANCIAL = "FINANCIAL"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    GENERIC_SECRET = "GENERIC_SECRET"


@dataclass
class DLPFinding:
    category: DLPCategory
    severity: DLPSeverity
    description: str
    line_number: Optional[int] = None
    matched_pattern: str = ""
    redacted_value: str = ""  # ALWAYS redacted — never the full secret
    confidence: float = 0.0
    context_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "line_number": self.line_number,
            "matched_pattern": self.matched_pattern,
            "redacted_value": self.redacted_value,
            "confidence": round(self.confidence, 2),
            "context_hint": self.context_hint,
        }


@dataclass
class DLPScanResult:
    file_path: Optional[str] = None
    content_type: str = "text"
    total_findings: int = 0
    findings: List[DLPFinding] = field(default_factory=list)
    categories_found: List[str] = field(default_factory=list)
    highest_severity: str = "INFO"
    scan_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "content_type": self.content_type,
            "total_findings": self.total_findings,
            "categories_found": self.categories_found,
            "highest_severity": self.highest_severity,
            "findings": [f.to_dict() for f in self.findings],
            "scan_error": self.scan_error,
        }


# ──────────────────────────────────────────────────────────
# Pattern definitions
# ──────────────────────────────────────────────────────────

def _redact(value: str, show_chars: int = 4) -> str:
    """Redact a sensitive value, showing only first few chars."""
    if len(value) <= show_chars + 3:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars)


_DLP_PATTERNS: List[Tuple[str, DLPCategory, DLPSeverity, str, float]] = [
    # Format: (regex_pattern, category, severity, description, confidence)

    # Email addresses
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
     DLPCategory.EMAIL, DLPSeverity.LOW,
     "Email address detected", 0.9),

    # Phone numbers (US format)
    (r"\b(?:\+1[-.]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\b",
     DLPCategory.PHONE, DLPSeverity.LOW,
     "Phone number pattern detected", 0.6),

    # AWS Access Key
    (r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
     DLPCategory.API_KEY, DLPSeverity.CRITICAL,
     "AWS Access Key ID detected", 0.95),

    # AWS Secret Key
    (r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
     DLPCategory.CLOUD_CREDENTIAL, DLPSeverity.CRITICAL,
     "AWS Secret Access Key detected", 0.9),

    # Google API Key
    (r"AIza[0-9A-Za-z_-]{35}",
     DLPCategory.API_KEY, DLPSeverity.HIGH,
     "Google API Key detected", 0.9),

    # GitHub Token
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}",
     DLPCategory.ACCESS_TOKEN, DLPSeverity.CRITICAL,
     "GitHub Personal Access Token detected", 0.95),

    # Generic API key assignment
    (r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,64}['\"]?",
     DLPCategory.API_KEY, DLPSeverity.HIGH,
     "API key assignment detected", 0.7),

    # Generic token assignment
    (r"(?:access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['\"]?[A-Za-z0-9_\-.]{20,200}['\"]?",
     DLPCategory.ACCESS_TOKEN, DLPSeverity.HIGH,
     "Access token assignment detected", 0.7),

    # Password assignment in code
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
     DLPCategory.PASSWORD, DLPSeverity.HIGH,
     "Hardcoded password detected", 0.8),

    # Private key header
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     DLPCategory.PRIVATE_KEY, DLPSeverity.CRITICAL,
     "Private key detected", 0.99),

    # Database connection string
    (r"(?:postgresql|mysql|mongodb|redis|mssql)://[^\s\"']+:[^\s\"']+@[^\s\"']+",
     DLPCategory.DATABASE_CREDENTIAL, DLPSeverity.CRITICAL,
     "Database connection string with credentials detected", 0.9),

    # Generic secret assignment
    (r"(?:secret|private|encryption)[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}['\"]?",
     DLPCategory.GENERIC_SECRET, DLPSeverity.HIGH,
     "Secret key assignment detected", 0.6),

    # Slack Token
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
     DLPCategory.ACCESS_TOKEN, DLPSeverity.HIGH,
     "Slack token detected", 0.9),

    # Stripe API Key
    (r"[sr]k_(?:live|test)_[A-Za-z0-9]{24,}",
     DLPCategory.API_KEY, DLPSeverity.CRITICAL,
     "Stripe API key detected", 0.95),

    # Credit card (basic Luhn-eligible patterns — NOT for PCI compliance)
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
     DLPCategory.FINANCIAL, DLPSeverity.HIGH,
     "Possible credit card number pattern detected", 0.5),

    # SSN pattern
    (r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
     DLPCategory.FINANCIAL, DLPSeverity.MEDIUM,
     "Possible SSN pattern detected (may be false positive)", 0.3),
]

_COMPILED_DLP_PATTERNS = [
    (re.compile(p, re.IGNORECASE | re.MULTILINE), cat, sev, desc, conf)
    for p, cat, sev, desc, conf in _DLP_PATTERNS
]

# ──────────────────────────────────────────────────────────
# Allowlist for false positive suppression
# ──────────────────────────────────────────────────────────

_ALLOWLIST_PATTERNS = [
    re.compile(r"example\.com"),
    re.compile(r"test@test\.com"),
    re.compile(r"user@example\.com"),
    re.compile(r"YOUR_.*_HERE"),
    re.compile(r"CHANGE_ME"),
    re.compile(r"<[A-Z_]+>"),  # Placeholder tokens like <API_KEY>
    re.compile(r"xxx+", re.IGNORECASE),
]


def _is_allowlisted(value: str) -> bool:
    for pattern in _ALLOWLIST_PATTERNS:
        if pattern.search(value):
            return True
    return False


# ──────────────────────────────────────────────────────────
# Entropy analysis
# ──────────────────────────────────────────────────────────

def compute_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _check_high_entropy_strings(text: str) -> List[DLPFinding]:
    """Find suspiciously high-entropy strings (potential secrets)."""
    findings = []

    # Look for quoted strings and assignments with high entropy
    pattern = re.compile(
        r"""(?:=\s*|:\s*)['"]([A-Za-z0-9+/=_\-]{20,})['"]""",
        re.MULTILINE,
    )

    for match in pattern.finditer(text):
        value = match.group(1)
        entropy = compute_entropy(value)

        # High entropy threshold (random strings tend to have entropy > 4.5)
        if entropy > 4.5 and len(value) >= 24:
            if not _is_allowlisted(value):
                findings.append(DLPFinding(
                    category=DLPCategory.GENERIC_SECRET,
                    severity=DLPSeverity.MEDIUM,
                    description=f"High-entropy string detected (entropy: {entropy:.2f}) — possible secret.",
                    redacted_value=_redact(value),
                    confidence=min(0.8, (entropy - 4.0) / 2),
                    context_hint="High-entropy strings often indicate secrets, API keys, or tokens.",
                ))

    return findings


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def scan_text(
    text: str,
    source_path: Optional[str] = None,
    max_findings: int = 100,
) -> DLPScanResult:
    """
    Scan text content for sensitive data patterns.
    All findings have REDACTED values — never the raw secret.
    """
    findings: List[DLPFinding] = []
    lines = text.split("\n")

    # Pattern-based scanning
    for compiled, category, severity, description, base_confidence in _COMPILED_DLP_PATTERNS:
        for match in compiled.finditer(text):
            value = match.group(0)

            # Skip allowlisted
            if _is_allowlisted(value):
                continue

            # Find line number
            start = match.start()
            line_number = text[:start].count("\n") + 1

            findings.append(DLPFinding(
                category=category,
                severity=severity,
                description=description,
                line_number=line_number,
                matched_pattern=compiled.pattern[:50] + "...",
                redacted_value=_redact(value),
                confidence=base_confidence,
            ))

            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    # Entropy analysis
    entropy_findings = _check_high_entropy_strings(text)
    findings.extend(entropy_findings[:10])

    # Determine highest severity
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    highest = "INFO"
    for f in findings:
        if severity_order.get(f.severity.value, 0) > severity_order.get(highest, 0):
            highest = f.severity.value

    # Unique categories found
    categories = list(set(f.category.value for f in findings))

    return DLPScanResult(
        file_path=source_path,
        content_type="text",
        total_findings=len(findings),
        findings=findings,
        categories_found=categories,
        highest_severity=highest,
    )


def scan_file(
    file_path: str,
    max_size_mb: int = 10,
    max_findings: int = 100,
) -> DLPScanResult:
    """
    Scan a file for sensitive data patterns.
    Limits to max_size_mb to prevent excessive resource usage.
    """
    from pathlib import Path

    path = Path(file_path)

    if not path.exists():
        return DLPScanResult(
            file_path=file_path,
            scan_error=f"File does not exist: {file_path}",
        )

    if not path.is_file():
        return DLPScanResult(
            file_path=file_path,
            scan_error=f"Not a regular file: {file_path}",
        )

    size = path.stat().st_size
    if size > max_size_mb * 1_000_000:
        return DLPScanResult(
            file_path=file_path,
            scan_error=f"File too large ({size / 1e6:.1f} MB). Maximum: {max_size_mb} MB.",
        )

    # Skip binary files
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return DLPScanResult(
            file_path=file_path,
            scan_error=f"Failed to read file: {e}",
        )

    result = scan_text(content, source_path=file_path, max_findings=max_findings)

    logger.info(
        "DLP SCAN | file=%s | findings=%d | highest=%s | categories=%s",
        path.name, result.total_findings, result.highest_severity,
        ", ".join(result.categories_found),
    )

    return result
