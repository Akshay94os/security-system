"""
AK Master Security System — Secret Scanner (§19)
Scans source code and config files for exposed secrets.

Wraps the DLP engine with source-code-specific patterns and
configuration file formats (JSON, YAML, .env, TOML, INI).

Never transmits detected secrets externally.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from security_modules.dlp.dlp_engine import scan_file as dlp_scan_file, scan_text, DLPScanResult

logger = logging.getLogger(__name__)

# File extensions likely to contain secrets
_SECRET_FILE_EXTENSIONS = frozenset({
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml", ".yaml", ".yml",
    ".json", ".xml", ".properties", ".pem", ".key", ".p12", ".pfx",
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".cs", ".php",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".tf", ".tfvars",  # Terraform
    ".dockerfile", "",  # Dockerfiles have no extension
})

# Files to skip
_SKIP_PATTERNS = frozenset({
    "node_modules", "__pycache__", ".git", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
})


def _should_scan(path: Path) -> bool:
    """Determine if a file should be scanned for secrets."""
    # Skip binary and large files
    if path.stat().st_size > 5_000_000:  # 5 MB limit
        return False

    # Check extension
    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix in _SECRET_FILE_EXTENSIONS:
        return True

    # Special filenames
    if name in (".env", ".env.local", ".env.production", ".env.staging",
                "credentials", "secrets", ".npmrc", ".pypirc", ".netrc"):
        return True

    return False


def _should_skip_dir(name: str) -> bool:
    return name.lower() in _SKIP_PATTERNS or name.startswith(".")


def scan_directory(
    directory: str,
    recursive: bool = True,
    max_files: int = 200,
    max_findings_per_file: int = 20,
) -> dict:
    """
    Scan a directory for secrets in source code and config files.

    Returns aggregate results with per-file findings.
    All secret values are REDACTED.
    """
    root = Path(directory)
    if not root.exists():
        return {"error": f"Directory does not exist: {directory}"}
    if not root.is_dir():
        return {"error": f"Not a directory: {directory}"}

    file_results: List[dict] = []
    total_findings = 0
    files_scanned = 0
    files_with_secrets = 0
    highest_severity = "INFO"
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def walk(path: Path, depth: int = 0):
        nonlocal files_scanned, files_with_secrets, total_findings, highest_severity

        if files_scanned >= max_files:
            return

        try:
            for entry in sorted(path.iterdir()):
                if files_scanned >= max_files:
                    return

                if entry.is_dir():
                    if recursive and not _should_skip_dir(entry.name) and depth < 10:
                        walk(entry, depth + 1)
                elif entry.is_file() and _should_scan(entry):
                    files_scanned += 1
                    try:
                        result = dlp_scan_file(
                            str(entry),
                            max_findings=max_findings_per_file,
                        )
                        if result.total_findings > 0:
                            files_with_secrets += 1
                            total_findings += result.total_findings

                            if severity_order.get(result.highest_severity, 0) > severity_order.get(highest_severity, 0):
                                highest_severity = result.highest_severity

                            file_results.append({
                                "file": str(entry.relative_to(root)),
                                "findings_count": result.total_findings,
                                "highest_severity": result.highest_severity,
                                "categories": result.categories_found,
                                "findings": [f.to_dict() for f in result.findings[:5]],
                            })
                    except Exception as e:
                        logger.debug("Secret scan skipped %s: %s", entry, e)

        except PermissionError:
            pass

    walk(root)

    logger.info(
        "SECRET SCAN | dir=%s | scanned=%d | with_secrets=%d | findings=%d | highest=%s",
        directory, files_scanned, files_with_secrets, total_findings, highest_severity,
    )

    return {
        "directory": str(root.resolve()),
        "files_scanned": files_scanned,
        "files_with_secrets": files_with_secrets,
        "total_findings": total_findings,
        "highest_severity": highest_severity,
        "truncated": files_scanned >= max_files,
        "file_results": file_results,
    }
