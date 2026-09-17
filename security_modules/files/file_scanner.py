"""
AK Master Security System — File Security Scanner (§13)
Static file analysis engine for download security and file scanning.

Features:
- SHA-256 cryptographic hash
- MIME type detection (python-magic when available, fallback to mimetypes)
- File metadata inspection
- Executable detection
- Script/macro detection
- Suspicious characteristic analysis
- Archive inspection

Never executes suspicious files.
"""
from __future__ import annotations

import hashlib
import logging
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FileRiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass
class FileSignal:
    signal_id: str
    description: str
    risk_contribution: float
    confidence: float
    evidence: str = ""
    category: str = "general"


@dataclass
class FileScanResult:
    file_path: str
    file_name: str
    file_size_bytes: int
    sha256: Optional[str] = None
    mime_type: Optional[str] = None
    risk_level: FileRiskLevel = FileRiskLevel.UNKNOWN
    risk_score: float = 0.0
    signals: List[FileSignal] = field(default_factory=list)
    explanation: str = ""
    is_executable: bool = False
    is_archive: bool = False
    is_script: bool = False
    file_type_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "is_executable": self.is_executable,
            "is_archive": self.is_archive,
            "is_script": self.is_script,
            "file_type_verified": self.file_type_verified,
            "signals": [
                {
                    "signal_id": s.signal_id,
                    "description": s.description,
                    "risk_contribution": round(s.risk_contribution, 3),
                    "confidence": round(s.confidence, 2),
                    "evidence": s.evidence,
                    "category": s.category,
                }
                for s in self.signals
            ],
            "explanation": self.explanation,
            "metadata": self.metadata,
        }


# ──────────────────────────────────────────────────────────
# Magic bytes for file type verification
# ──────────────────────────────────────────────────────────

_MAGIC_BYTES = {
    b"\x4d\x5a": "application/x-executable",          # PE / EXE / DLL
    b"\x7fELF": "application/x-elf",                  # ELF
    b"\xca\xfe\xba\xbe": "application/x-mach-binary",  # Mach-O
    b"PK": "application/zip",                          # ZIP/DOCX/XLSX/JAR
    b"\x1f\x8b": "application/gzip",                   # GZIP
    b"Rar!": "application/x-rar",                      # RAR
    b"7z\xbc\xaf": "application/x-7z-compressed",      # 7z
    b"%PDF": "application/pdf",                        # PDF
    b"\xd0\xcf\x11\xe0": "application/x-ole-compound",  # OLE (DOC/XLS/PPT)
    b"\x89PNG": "image/png",                           # PNG
    b"\xff\xd8\xff": "image/jpeg",                     # JPEG
    b"GIF8": "image/gif",                              # GIF
}

# Extensions that are inherently executable
_EXECUTABLE_EXTENSIONS = frozenset({
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".scr", ".pif", ".com",
    ".hta", ".cpl", ".inf", ".reg", ".dll", ".sys", ".drv",
    ".jar", ".apk", ".app", ".elf", ".bin", ".run",
})

# Extensions that contain scripts/macros
_SCRIPT_EXTENSIONS = frozenset({
    ".py", ".rb", ".pl", ".sh", ".bash", ".zsh", ".fish",
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".ps1", ".psm1", ".psd1",  # PowerShell
    ".vbs", ".vbe", ".wsf",     # VBScript
    ".js", ".mjs", ".ts",      # JavaScript/TypeScript
})

# Extensions for archives
_ARCHIVE_EXTENSIONS = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tgz", ".tar.gz", ".cab", ".iso", ".dmg",
})

# OLE/Office with macro capability
_MACRO_EXTENSIONS = frozenset({
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".doc", ".xls", ".ppt",  # Legacy Office can contain macros
})


# ──────────────────────────────────────────────────────────
# Hash computation
# ──────────────────────────────────────────────────────────

def compute_sha256(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
    except (IOError, OSError) as e:
        logger.error("Hash computation failed for %s: %s", file_path, e)
        return None


# ──────────────────────────────────────────────────────────
# MIME type detection
# ──────────────────────────────────────────────────────────

def detect_mime_type(file_path: str) -> tuple[Optional[str], bool]:
    """
    Detect MIME type. Returns (mime_type, magic_verified).
    Uses python-magic if available, falls back to mimetypes.
    """
    # Try python-magic first (more reliable)
    try:
        import magic
        mime = magic.from_file(file_path, mime=True)
        return mime, True
    except ImportError:
        pass
    except Exception as e:
        logger.debug("python-magic failed: %s", e)

    # Fallback: check magic bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for magic_bytes, mime_type in _MAGIC_BYTES.items():
            if header.startswith(magic_bytes):
                return mime_type, True
    except (IOError, OSError):
        pass

    # Final fallback: extension-based
    import mimetypes
    mime, _ = mimetypes.guess_type(file_path)
    return mime, False


# ──────────────────────────────────────────────────────────
# Analysis functions
# ──────────────────────────────────────────────────────────

def _check_file_type(path: Path, ext: str, mime: Optional[str], magic_verified: bool) -> List[FileSignal]:
    """Check file type against extension and magic bytes."""
    signals = []

    if ext in _EXECUTABLE_EXTENSIONS:
        signals.append(FileSignal(
            signal_id="EXECUTABLE_FILE",
            description=f"File is an executable ({ext}).",
            risk_contribution=0.4, confidence=0.95,
            evidence=f"Extension: {ext}",
            category="file_type",
        ))

    if ext in _SCRIPT_EXTENSIONS:
        signals.append(FileSignal(
            signal_id="SCRIPT_FILE",
            description=f"File is a script ({ext}).",
            risk_contribution=0.2, confidence=0.9,
            evidence=f"Extension: {ext}",
            category="file_type",
        ))

    if ext in _MACRO_EXTENSIONS:
        signals.append(FileSignal(
            signal_id="MACRO_CAPABLE_DOCUMENT",
            description=f"Document type can contain macros ({ext}).",
            risk_contribution=0.25, confidence=0.8,
            evidence=f"Extension: {ext}",
            category="file_type",
        ))

    if ext in _ARCHIVE_EXTENSIONS:
        signals.append(FileSignal(
            signal_id="ARCHIVE_FILE",
            description=f"File is an archive ({ext}) — may contain hidden executables.",
            risk_contribution=0.1, confidence=0.9,
            evidence=f"Extension: {ext}",
            category="file_type",
        ))

    # Extension/MIME mismatch (masquerading)
    if magic_verified and mime:
        if ext in {".txt", ".pdf", ".jpg", ".png", ".doc"} and "executable" in (mime or ""):
            signals.append(FileSignal(
                signal_id="EXTENSION_MIME_MISMATCH",
                description="File extension does not match actual content type — possible masquerading.",
                risk_contribution=0.7, confidence=0.9,
                evidence=f"Extension: {ext}, Actual MIME: {mime}",
                category="masquerade",
            ))

    return signals


def _check_file_metadata(path: Path, size: int) -> List[FileSignal]:
    """Check file metadata for suspicious characteristics."""
    signals = []

    # Very small executable (stager/dropper pattern)
    ext = path.suffix.lower()
    if ext in _EXECUTABLE_EXTENSIONS and size < 10_000:
        signals.append(FileSignal(
            signal_id="TINY_EXECUTABLE",
            description="Executable is very small — could be a dropper or stager.",
            risk_contribution=0.3, confidence=0.5,
            evidence=f"Size: {size} bytes",
            category="metadata",
        ))

    # Very large archive (can be a zip bomb)
    if ext in _ARCHIVE_EXTENSIONS and size > 500_000_000:
        signals.append(FileSignal(
            signal_id="VERY_LARGE_ARCHIVE",
            description="Archive is very large — inspect before extraction.",
            risk_contribution=0.1, confidence=0.4,
            evidence=f"Size: {size / 1e6:.1f} MB",
            category="metadata",
        ))

    # Double extension (e.g., report.pdf.exe)
    name = path.name
    parts = name.rsplit(".", 2)
    if len(parts) >= 3:
        second_ext = f".{parts[-2]}"
        if second_ext in {".pdf", ".doc", ".txt", ".jpg", ".png", ".xlsx"}:
            signals.append(FileSignal(
                signal_id="DOUBLE_EXTENSION",
                description="File has a double extension — common social engineering technique.",
                risk_contribution=0.6, confidence=0.85,
                evidence=f"Name: {name}",
                category="masquerade",
            ))

    # Hidden file
    if name.startswith("."):
        signals.append(FileSignal(
            signal_id="HIDDEN_FILE",
            description="File is hidden (starts with dot).",
            risk_contribution=0.05, confidence=0.9,
            evidence=f"Name: {name}",
            category="metadata",
        ))

    return signals


def _check_pe_header(file_path: str) -> List[FileSignal]:
    """Basic PE header checks for Windows executables."""
    signals = []
    try:
        with open(file_path, "rb") as f:
            header = f.read(2)
            if header != b"MZ":
                return signals

            # Read PE offset
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return signals
            pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                signals.append(FileSignal(
                    signal_id="INVALID_PE_HEADER",
                    description="File has MZ header but invalid PE signature — possibly corrupted or packed.",
                    risk_contribution=0.3, confidence=0.7,
                    evidence="Invalid PE signature",
                    category="binary_analysis",
                ))
    except Exception:
        pass
    return signals


# ──────────────────────────────────────────────────────────
# Composite score
# ──────────────────────────────────────────────────────────

def _compute_file_risk(signals: List[FileSignal]) -> tuple[float, FileRiskLevel]:
    if not signals:
        return 0.0, FileRiskLevel.SAFE

    total = sum(s.risk_contribution * s.confidence for s in signals)
    total = max(0.0, min(1.0, total))

    # Check for immediate blockers
    for s in signals:
        if s.signal_id == "EXTENSION_MIME_MISMATCH" and s.risk_contribution >= 0.7:
            return total, FileRiskLevel.HIGH_RISK

    if total >= 0.7:
        return total, FileRiskLevel.HIGH_RISK
    elif total >= 0.4:
        return total, FileRiskLevel.SUSPICIOUS
    elif total >= 0.15:
        return total, FileRiskLevel.LOW
    else:
        return total, FileRiskLevel.SAFE


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def scan_file(file_path: str) -> FileScanResult:
    """
    Perform security analysis of a file.
    Never executes the file — read-only static analysis.
    """
    path = Path(file_path)

    if not path.exists():
        return FileScanResult(
            file_path=file_path, file_name=path.name, file_size_bytes=0,
            risk_level=FileRiskLevel.UNKNOWN,
            explanation=f"File does not exist: {file_path}",
        )

    if not path.is_file():
        return FileScanResult(
            file_path=file_path, file_name=path.name, file_size_bytes=0,
            risk_level=FileRiskLevel.UNKNOWN,
            explanation=f"Path is not a regular file: {file_path}",
        )

    stat = path.stat()
    size = stat.st_size
    ext = path.suffix.lower()

    # Compute hash
    sha256 = compute_sha256(file_path)

    # Detect MIME type
    mime, magic_verified = detect_mime_type(file_path)

    # Collect signals
    all_signals: List[FileSignal] = []

    # File type analysis
    type_signals = _check_file_type(path, ext, mime, magic_verified)
    all_signals.extend(type_signals)

    # Metadata analysis
    meta_signals = _check_file_metadata(path, size)
    all_signals.extend(meta_signals)

    # PE header check (Windows executables)
    if ext in {".exe", ".dll", ".sys", ".scr", ".com"}:
        pe_signals = _check_pe_header(file_path)
        all_signals.extend(pe_signals)

    # Compute risk
    risk_score, risk_level = _compute_file_risk(all_signals)

    # Build explanation
    if risk_level == FileRiskLevel.SAFE:
        explanation = "No significant security risks detected."
    else:
        risky = sorted(
            [s for s in all_signals if s.risk_contribution > 0],
            key=lambda s: s.risk_contribution, reverse=True,
        )
        reasons = [f"• {s.description}" for s in risky[:5]]
        explanation = "File analysis found the following concerns:\n" + "\n".join(reasons)

    # Metadata
    metadata = {
        "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "extension": ext,
        "magic_verified": magic_verified,
    }

    result = FileScanResult(
        file_path=str(path.resolve()),
        file_name=path.name,
        file_size_bytes=size,
        sha256=sha256,
        mime_type=mime,
        risk_level=risk_level,
        risk_score=risk_score,
        signals=all_signals,
        explanation=explanation,
        is_executable=ext in _EXECUTABLE_EXTENSIONS,
        is_archive=ext in _ARCHIVE_EXTENSIONS,
        is_script=ext in _SCRIPT_EXTENSIONS,
        file_type_verified=magic_verified,
        metadata=metadata,
    )

    logger.info(
        "FILE SCAN | %s | file=%s | risk=%s | score=%.3f | sha256=%s",
        risk_level.value, path.name, risk_score, risk_score, (sha256 or "N/A")[:16],
    )

    return result
