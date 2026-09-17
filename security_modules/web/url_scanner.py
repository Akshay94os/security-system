"""
AK Master Security System — URL Security Scanner (§11)
Multi-layer URL analysis engine.

Layers:
  A — Rule Engine (blocklists, allowlists)
  B — Feature Analysis (domain structure, URL patterns)
  C — ML Classifier (placeholder — clearly labelled)
  D — Threat Intelligence (provider adapter, unconfigured by default)
  E — Behavior/Context Analysis (redirects, encoding)
  F — AI Explanation Layer (Gemini integration when configured)

Every signal is explainable. Never fabricate intelligence.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


class URLRiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass
class URLSignal:
    """A single explainable security signal from the analysis."""
    layer: str          # A–F
    signal_id: str
    description: str
    risk_contribution: float  # 0.0–1.0
    confidence: float         # 0.0–1.0
    evidence: str = ""


@dataclass
class URLScanResult:
    url: str
    domain: str
    risk_level: URLRiskLevel
    risk_score: float          # 0.0–1.0 composite
    signals: List[URLSignal] = field(default_factory=list)
    explanation: str = ""
    is_https: bool = False
    redirect_chain: List[str] = field(default_factory=list)
    action_taken: str = "NONE"
    scan_layers_used: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "is_https": self.is_https,
            "signals": [
                {
                    "layer": s.layer,
                    "signal_id": s.signal_id,
                    "description": s.description,
                    "risk_contribution": round(s.risk_contribution, 3),
                    "confidence": round(s.confidence, 2),
                    "evidence": s.evidence,
                }
                for s in self.signals
            ],
            "explanation": self.explanation,
            "action_taken": self.action_taken,
            "scan_layers_used": self.scan_layers_used,
        }


# ──────────────────────────────────────────────────────────
# Layer A — Rule Engine
# ──────────────────────────────────────────────────────────

_KNOWN_SAFE_DOMAINS = frozenset({
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "github.com", "stackoverflow.com", "microsoft.com", "python.org",
    "wikipedia.org", "amazon.com", "apple.com", "mozilla.org",
    "docs.python.org", "pypi.org", "npmjs.com", "code.visualstudio.com",
})

_KNOWN_MALICIOUS_DOMAINS = frozenset({
    # These are synthetic test entries — not real domains
    "malware-test-domain.example",
    "phishing-test.example",
    "fake-login.example",
})

_SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often abused
    ".xyz", ".top", ".buzz", ".work", ".click",
    ".loan", ".download", ".racing", ".win", ".bid",
    ".stream", ".party", ".review", ".trade", ".webcam",
})

_PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "update", "confirm", "password",
    "banking", "paypal", "microsoft", "apple", "google",
    "netflix", "amazon", "ebay", "facebook", "instagram",
    "wallet", "crypto", "blockchain", "suspended", "urgent",
    "locked", "unusual", "unauthorized", "expire",
]

# Brands commonly impersonated
_IMPERSONATION_TARGETS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "dropbox": "dropbox.com",
}

# Homograph characters (lookalike Unicode)
_HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ᴏ': 'o', 'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i',
    '0': 'o', '1': 'l',
}


def _layer_a_rules(url: str, domain: str) -> List[URLSignal]:
    """Layer A: Rule-based checks against known lists."""
    signals = []

    # Strip subdomains for root domain check
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    if root_domain in _KNOWN_SAFE_DOMAINS or domain in _KNOWN_SAFE_DOMAINS:
        signals.append(URLSignal(
            layer="A", signal_id="KNOWN_SAFE_DOMAIN",
            description="Domain is in the known-safe allowlist.",
            risk_contribution=-0.5, confidence=0.95,
            evidence=f"Matched: {domain}",
        ))

    if root_domain in _KNOWN_MALICIOUS_DOMAINS or domain in _KNOWN_MALICIOUS_DOMAINS:
        signals.append(URLSignal(
            layer="A", signal_id="KNOWN_MALICIOUS_DOMAIN",
            description="Domain is in the known-malicious blocklist.",
            risk_contribution=1.0, confidence=0.99,
            evidence=f"Matched: {domain}",
        ))

    return signals


# ──────────────────────────────────────────────────────────
# Layer B — Feature Analysis
# ──────────────────────────────────────────────────────────

def _layer_b_features(url: str, parsed: Any, domain: str) -> List[URLSignal]:
    """Layer B: Structural and feature analysis of the URL."""
    signals = []

    # HTTPS check
    if parsed.scheme != "https":
        signals.append(URLSignal(
            layer="B", signal_id="NO_HTTPS",
            description="URL does not use HTTPS encryption.",
            risk_contribution=0.15, confidence=1.0,
            evidence=f"Scheme: {parsed.scheme}",
        ))

    # IP address as domain
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(domain):
        signals.append(URLSignal(
            layer="B", signal_id="IP_ADDRESS_DOMAIN",
            description="Domain is a raw IP address — often used in phishing.",
            risk_contribution=0.4, confidence=0.85,
            evidence=f"IP: {domain}",
        ))

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            signals.append(URLSignal(
                layer="B", signal_id="SUSPICIOUS_TLD",
                description=f"Uses suspicious TLD '{tld}' frequently associated with abuse.",
                risk_contribution=0.2, confidence=0.6,
                evidence=f"TLD: {tld}",
            ))
            break

    # Very long URL (common in phishing)
    if len(url) > 200:
        signals.append(URLSignal(
            layer="B", signal_id="EXCESSIVELY_LONG_URL",
            description="URL is unusually long — often used to hide malicious paths.",
            risk_contribution=0.15, confidence=0.5,
            evidence=f"Length: {len(url)} characters",
        ))

    # Many subdomains
    subdomain_count = len(domain.split(".")) - 2
    if subdomain_count >= 3:
        signals.append(URLSignal(
            layer="B", signal_id="MANY_SUBDOMAINS",
            description="Domain has many subdomains — can indicate subdomain abuse.",
            risk_contribution=0.15, confidence=0.5,
            evidence=f"Subdomain depth: {subdomain_count}",
        ))

    # URL shortener patterns
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
    root = ".".join(domain.split(".")[-2:])
    if root in shorteners:
        signals.append(URLSignal(
            layer="B", signal_id="URL_SHORTENER",
            description="URL uses a shortening service — destination is hidden.",
            risk_contribution=0.2, confidence=0.8,
            evidence=f"Shortener: {root}",
        ))

    # Encoded characters in URL
    decoded = unquote(url)
    if decoded != url:
        suspicious_encoded = len(url) - len(decoded)
        if suspicious_encoded > 10:
            signals.append(URLSignal(
                layer="B", signal_id="HEAVILY_ENCODED_URL",
                description="URL contains many encoded characters — may hide malicious content.",
                risk_contribution=0.2, confidence=0.6,
                evidence=f"Encoded chars: ~{suspicious_encoded}",
            ))

    # @ symbol in URL (credential injection)
    if "@" in parsed.netloc:
        signals.append(URLSignal(
            layer="B", signal_id="CREDENTIAL_IN_URL",
            description="URL contains @ symbol — can be used to disguise the real destination.",
            risk_contribution=0.5, confidence=0.9,
            evidence=f"Netloc: {parsed.netloc}",
        ))

    # Suspicious query parameters
    params = parse_qs(parsed.query)
    sensitive_param_names = {"password", "token", "key", "secret", "auth", "session", "redirect"}
    for param_name in params:
        if param_name.lower() in sensitive_param_names:
            signals.append(URLSignal(
                layer="B", signal_id="SENSITIVE_QUERY_PARAM",
                description=f"URL contains sensitive parameter '{param_name}'.",
                risk_contribution=0.15, confidence=0.7,
                evidence=f"Parameter: {param_name}",
            ))

    # Phishing keywords in path
    path_lower = (parsed.path + parsed.query).lower()
    found_keywords = [kw for kw in _PHISHING_KEYWORDS if kw in path_lower]
    if len(found_keywords) >= 2:
        signals.append(URLSignal(
            layer="B", signal_id="PHISHING_KEYWORDS_IN_URL",
            description="URL path contains multiple phishing-related keywords.",
            risk_contribution=0.25, confidence=0.6,
            evidence=f"Keywords found: {', '.join(found_keywords[:5])}",
        ))

    # Homograph detection
    homograph_found = []
    for char in domain:
        if char in _HOMOGRAPH_MAP:
            homograph_found.append(f"'{char}'→'{_HOMOGRAPH_MAP[char]}'")
    if homograph_found:
        signals.append(URLSignal(
            layer="B", signal_id="HOMOGRAPH_CHARACTERS",
            description="Domain contains Unicode characters that look like ASCII — possible IDN homograph attack.",
            risk_contribution=0.6, confidence=0.85,
            evidence=f"Substitutions: {', '.join(homograph_found[:5])}",
        ))

    # Brand impersonation check
    for brand, real_domain in _IMPERSONATION_TARGETS.items():
        root_domain = ".".join(domain.split(".")[-2:])
        if brand in domain.lower() and root_domain != real_domain:
            signals.append(URLSignal(
                layer="B", signal_id="BRAND_IMPERSONATION",
                description=f"Domain contains brand name '{brand}' but is not the official domain.",
                risk_contribution=0.5, confidence=0.75,
                evidence=f"Domain: {domain}, Real: {real_domain}",
            ))
            break

    return signals


# ──────────────────────────────────────────────────────────
# Layer C — ML Classifier (placeholder, clearly labelled)
# ──────────────────────────────────────────────────────────

def _layer_c_ml_classifier(url: str, domain: str) -> List[URLSignal]:
    """
    Layer C: ML-based classification.
    STATUS: PLACEHOLDER — No ML model is loaded.
    When a model is trained and deployed, this layer will provide
    probability-based phishing/malware classification.
    """
    # Intentionally returns no signals — clearly not providing fake ML results
    return []


# ──────────────────────────────────────────────────────────
# Layer D — Threat Intelligence
# ──────────────────────────────────────────────────────────

def _layer_d_threat_intel(url: str, domain: str) -> List[URLSignal]:
    """
    Layer D: External threat intelligence lookup.
    STATUS: No threat intelligence provider is configured.
    When providers are configured (VirusTotal, AbuseIPDB, etc.),
    this layer will query them and report findings with source attribution.
    """
    signals = []
    # NOTE: Intentionally does not fabricate intelligence.
    # When configured, this will query real providers.
    signals.append(URLSignal(
        layer="D", signal_id="THREAT_INTEL_UNCONFIGURED",
        description="No external threat intelligence provider is configured. Analysis is local-only.",
        risk_contribution=0.0, confidence=1.0,
        evidence="Configure threat intelligence providers in Settings → Integrations.",
    ))
    return signals


# ──────────────────────────────────────────────────────────
# Layer E — Behavior/Context Analysis
# ──────────────────────────────────────────────────────────

def _layer_e_context(url: str, parsed: Any, domain: str) -> List[URLSignal]:
    """Layer E: Contextual and behavioral analysis."""
    signals = []

    # Data URI (can embed malicious content)
    if parsed.scheme == "data":
        signals.append(URLSignal(
            layer="E", signal_id="DATA_URI",
            description="Data URI detected — can embed executable content.",
            risk_contribution=0.5, confidence=0.9,
            evidence=f"Scheme: data",
        ))

    # JavaScript URI
    if parsed.scheme == "javascript":
        signals.append(URLSignal(
            layer="E", signal_id="JAVASCRIPT_URI",
            description="JavaScript URI detected — executes code directly.",
            risk_contribution=0.8, confidence=0.99,
            evidence="Scheme: javascript",
        ))

    # Download-triggering file extensions
    download_extensions = {
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".scr", ".pif", ".com", ".hta", ".cpl", ".wsf", ".wsh",
    }
    path_lower = parsed.path.lower()
    for ext in download_extensions:
        if path_lower.endswith(ext):
            signals.append(URLSignal(
                layer="E", signal_id="EXECUTABLE_DOWNLOAD",
                description=f"URL points to an executable file type ({ext}).",
                risk_contribution=0.4, confidence=0.85,
                evidence=f"Extension: {ext}",
            ))
            break

    return signals


# ──────────────────────────────────────────────────────────
# Composite Score and Risk Level
# ──────────────────────────────────────────────────────────

def _compute_risk(signals: List[URLSignal]) -> tuple[float, URLRiskLevel]:
    """Compute composite risk score from individual signals."""
    if not signals:
        return 0.0, URLRiskLevel.UNKNOWN

    # Weighted sum with confidence
    total_risk = 0.0
    for s in signals:
        total_risk += s.risk_contribution * s.confidence

    # Clamp to [0, 1]
    total_risk = max(0.0, min(1.0, total_risk))

    # Check for immediate blockers
    for s in signals:
        if s.signal_id == "KNOWN_MALICIOUS_DOMAIN":
            return total_risk, URLRiskLevel.BLOCKED
        if s.signal_id == "JAVASCRIPT_URI":
            return total_risk, URLRiskLevel.BLOCKED

    # Threshold-based classification
    if total_risk >= 0.7:
        return total_risk, URLRiskLevel.HIGH_RISK
    elif total_risk >= 0.3:
        return total_risk, URLRiskLevel.SUSPICIOUS
    else:
        return total_risk, URLRiskLevel.SAFE


def _build_explanation(signals: List[URLSignal], risk_level: URLRiskLevel) -> str:
    """Generate a human-readable explanation of the scan result."""
    if risk_level == URLRiskLevel.SAFE:
        if any(s.signal_id == "KNOWN_SAFE_DOMAIN" for s in signals):
            return "This URL belongs to a known, trusted domain."
        return "No significant security risks detected in the URL structure."

    risky_signals = [s for s in signals if s.risk_contribution > 0]
    risky_signals.sort(key=lambda s: s.risk_contribution * s.confidence, reverse=True)

    reasons = []
    for s in risky_signals[:5]:
        reasons.append(f"• {s.description}")

    prefix = {
        URLRiskLevel.SUSPICIOUS: "This URL shows some suspicious characteristics:",
        URLRiskLevel.HIGH_RISK: "This URL has multiple high-risk indicators:",
        URLRiskLevel.BLOCKED: "This URL has been blocked due to confirmed risk:",
    }.get(risk_level, "Analysis results:")

    return f"{prefix}\n" + "\n".join(reasons)


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def scan_url(url: str) -> URLScanResult:
    """
    Perform a multi-layer security analysis of a URL.

    Returns a URLScanResult with explainable signals.
    Never fabricates intelligence or invents threats.
    """
    layers_used = []

    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc or ""
        domain = domain.lower().strip()
    except Exception as e:
        return URLScanResult(
            url=url, domain="", risk_level=URLRiskLevel.UNKNOWN,
            risk_score=0.0, explanation=f"URL parsing failed: {e}",
        )

    if not domain:
        return URLScanResult(
            url=url, domain="", risk_level=URLRiskLevel.UNKNOWN,
            risk_score=0.0, explanation="Could not extract domain from URL.",
        )

    all_signals: List[URLSignal] = []

    # Layer A — Rules
    layer_a = _layer_a_rules(url, domain)
    all_signals.extend(layer_a)
    layers_used.append("A:RuleEngine")

    # Layer B — Features
    layer_b = _layer_b_features(url, parsed, domain)
    all_signals.extend(layer_b)
    layers_used.append("B:FeatureAnalysis")

    # Layer C — ML (placeholder)
    layer_c = _layer_c_ml_classifier(url, domain)
    all_signals.extend(layer_c)
    if layer_c:
        layers_used.append("C:MLClassifier")

    # Layer D — Threat Intel
    layer_d = _layer_d_threat_intel(url, domain)
    all_signals.extend(layer_d)
    layers_used.append("D:ThreatIntel(unconfigured)")

    # Layer E — Context
    layer_e = _layer_e_context(url, parsed, domain)
    all_signals.extend(layer_e)
    layers_used.append("E:ContextAnalysis")

    # Compute composite risk
    risk_score, risk_level = _compute_risk(all_signals)

    # Generate explanation
    explanation = _build_explanation(all_signals, risk_level)

    result = URLScanResult(
        url=url,
        domain=domain,
        risk_level=risk_level,
        risk_score=risk_score,
        signals=all_signals,
        explanation=explanation,
        is_https=parsed.scheme == "https",
        scan_layers_used=layers_used,
    )

    logger.info(
        "URL SCAN | %s | domain=%s | risk=%s | score=%.3f | signals=%d",
        risk_level.value, domain, risk_score, risk_score, len(all_signals),
    )

    return result
