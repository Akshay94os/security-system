"""
AK Master Security System — Prompt Injection Detector (§28)
Enhanced detection of prompt injection attempts in Nexus inputs.

Layers:
  1. Pattern-based detection (regex rules)
  2. Content classification (separate DATA from INSTRUCTIONS)
  3. Entropy / anomaly scoring
  4. Untrusted content marking

SECURITY PRINCIPLE (§103):
  External content (webpages, emails, documents, clipboard) is
  ALWAYS marked as DATA and can NEVER override system instructions.
  The firewall already blocks untrusted-origin + high-risk tool calls,
  but this module provides an additional defense-in-depth layer.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class ContentOrigin(str, Enum):
    USER_DIRECT = "USER_DIRECT"
    USER_VOICE = "USER_VOICE"
    EXTERNAL_WEBPAGE = "EXTERNAL_WEBPAGE"
    EXTERNAL_EMAIL = "EXTERNAL_EMAIL"
    EXTERNAL_DOCUMENT = "EXTERNAL_DOCUMENT"
    EXTERNAL_CLIPBOARD = "EXTERNAL_CLIPBOARD"
    UNKNOWN = "UNKNOWN"


class InjectionType(str, Enum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    ROLE_MANIPULATION = "ROLE_MANIPULATION"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"


@dataclass
class InjectionSignal:
    injection_type: InjectionType
    pattern_matched: str
    description: str
    confidence: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "injection_type": self.injection_type.value,
            "pattern_matched": self.pattern_matched,
            "description": self.description,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "evidence": self.evidence,
        }


@dataclass
class InjectionAnalysisResult:
    is_suspicious: bool = False
    is_blocked: bool = False
    risk_score: float = 0.0
    signals: List[InjectionSignal] = field(default_factory=list)
    recommendation: str = ""
    content_origin: str = "USER_DIRECT"

    def to_dict(self) -> dict:
        return {
            "is_suspicious": self.is_suspicious,
            "is_blocked": self.is_blocked,
            "risk_score": round(self.risk_score, 3),
            "signals": [s.to_dict() for s in self.signals],
            "recommendation": self.recommendation,
            "content_origin": self.content_origin,
        }


# ──────────────────────────────────────────────────────────
# Layer 1: Pattern-based detection rules
# ──────────────────────────────────────────────────────────

_INJECTION_RULES: List[Tuple[str, InjectionType, str, str, float]] = [
    # (regex, type, description, severity, confidence)

    # Instruction override attempts
    (r"ignore\s+(previous|all|above|prior|every)\s+(instructions?|context|rules?|prompts?|constraints?)",
     InjectionType.INSTRUCTION_OVERRIDE,
     "Instruction override: attempts to nullify system instructions",
     "CRITICAL", 0.95),

    (r"forget\s+(everything|all|previous|your|the)\s*(instructions?|context|rules?|training)?",
     InjectionType.INSTRUCTION_OVERRIDE,
     "Memory wipe: attempts to clear system context",
     "CRITICAL", 0.9),

    (r"new\s+instructions?\s*:",
     InjectionType.INSTRUCTION_OVERRIDE,
     "New instruction injection attempt",
     "HIGH", 0.85),

    (r"disregard\s+(all|any|previous|above)\s+(safety|security|rules?|guidelines?|instructions?)",
     InjectionType.INSTRUCTION_OVERRIDE,
     "Safety disregard attempt",
     "CRITICAL", 0.95),

    # Role manipulation
    (r"you\s+are\s+now\s+(a\s+)?(?:different|new|unrestricted|jailbroken|evil|DAN)",
     InjectionType.ROLE_MANIPULATION,
     "Role reassignment: attempts to change agent identity",
     "CRITICAL", 0.95),

    (r"act\s+as\s+(if\s+)?(you\s+are\s+)?(an?\s+)?(unrestricted|unfiltered|evil|jailbroken|admin)",
     InjectionType.ROLE_MANIPULATION,
     "Role play injection: attempts to bypass restrictions via persona",
     "HIGH", 0.85),

    (r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(hacker|admin|root|unrestricted)",
     InjectionType.ROLE_MANIPULATION,
     "Pretend-role injection",
     "HIGH", 0.8),

    # System prompt leaking
    (r"(show|reveal|print|display|output|repeat)\s+(your|the|system)\s+(prompt|instructions?|rules?|config)",
     InjectionType.SYSTEM_PROMPT_LEAK,
     "System prompt extraction attempt",
     "HIGH", 0.85),

    (r"what\s+are\s+your\s+(system\s+)?(instructions?|rules?|prompts?|constraints?)",
     InjectionType.SYSTEM_PROMPT_LEAK,
     "System instruction query attempt",
     "MEDIUM", 0.6),

    # Privilege escalation
    (r"(override|bypass|disable|turn\s+off|deactivate)\s+(security|auth|permission|policy|firewall|protection)",
     InjectionType.PRIVILEGE_ESCALATION,
     "Security bypass attempt",
     "CRITICAL", 0.95),

    (r"(grant|give)\s+(me|yourself)\s+(admin|root|elevated|full)\s+(access|permission|privilege)",
     InjectionType.PRIVILEGE_ESCALATION,
     "Privilege grant attempt",
     "CRITICAL", 0.9),

    (r"run\s+as\s+(root|admin|administrator|system|elevated)",
     InjectionType.PRIVILEGE_ESCALATION,
     "Elevated execution attempt",
     "CRITICAL", 0.9),

    # Command injection
    (r"execute\s+(this\s+)?(command|code|script|shell)\s*:",
     InjectionType.COMMAND_INJECTION,
     "Direct command injection attempt",
     "HIGH", 0.8),

    (r"(sudo|chmod|chown|rm\s+-rf|del\s+/[sqf]|format\s+[a-z]:)",
     InjectionType.COMMAND_INJECTION,
     "Dangerous system command detected",
     "CRITICAL", 0.9),

    (r"(eval|exec|os\.system|subprocess|shell_exec|system\s*\()",
     InjectionType.COMMAND_INJECTION,
     "Code execution function detected in input",
     "HIGH", 0.85),

    # Data exfiltration
    (r"(send|post|upload|transmit|exfiltrate)\s+(all|this|the|my)\s+(data|files?|info|secrets?|keys?|tokens?)\s+(to|via)",
     InjectionType.DATA_EXFILTRATION,
     "Data exfiltration instruction detected",
     "CRITICAL", 0.85),

    # Jailbreak patterns
    (r"DAN\s*(mode|prompt|jailbreak)?",
     InjectionType.JAILBREAK_ATTEMPT,
     "DAN jailbreak pattern detected",
     "HIGH", 0.8),

    (r"(developer|maintenance|debug|test)\s+mode\s*(enabled?|on|activate)",
     InjectionType.JAILBREAK_ATTEMPT,
     "Debug/developer mode activation attempt",
     "HIGH", 0.7),

    # XML/HTML tag injection (system prompt markers)
    (r"<\s*system\s*>|<\s*/?\s*instruction\s*>|\[system\]|\[INST\]",
     InjectionType.INSTRUCTION_OVERRIDE,
     "System prompt tag injection attempt",
     "HIGH", 0.85),

    # Social engineering
    (r"(this\s+is\s+an?\s+)?(emergency|urgent|critical)\s*[.!:]\s*(you\s+must|immediately|right\s+now)",
     InjectionType.SOCIAL_ENGINEERING,
     "Urgency-based social engineering attempt",
     "MEDIUM", 0.5),
]

_COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), inj_type, desc, sev, conf)
    for pattern, inj_type, desc, sev, conf in _INJECTION_RULES
]


# ──────────────────────────────────────────────────────────
# Layer 2: Content classification
# ──────────────────────────────────────────────────────────

def _classify_content_risk(text: str) -> float:
    """
    Score how likely the text is an instruction vs. data.
    Higher score = more likely to be an injection attempt.
    """
    instruction_markers = [
        "you must", "you should", "you will", "you are now",
        "from now on", "starting now", "henceforth",
        "do not", "don't", "never", "always",
        "respond as", "behave as", "act as",
        "your new", "your task", "your role",
    ]

    text_lower = text.lower()
    marker_count = sum(1 for m in instruction_markers if m in text_lower)

    # Normalize by text length
    words = len(text.split())
    if words == 0:
        return 0.0

    # High instruction density = suspicious
    density = marker_count / max(words, 1) * 100
    return min(1.0, density * 0.3)


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

def analyze(
    text: str,
    origin: ContentOrigin = ContentOrigin.USER_DIRECT,
    additional_context: Optional[str] = None,
) -> InjectionAnalysisResult:
    """
    Analyze text for prompt injection attempts.

    Returns an InjectionAnalysisResult with all detected signals.
    This is a DEFENSE-IN-DEPTH layer — the Agent Firewall provides
    the primary security boundary.
    """
    result = InjectionAnalysisResult(content_origin=origin.value)
    all_texts = [text]
    if additional_context:
        all_texts.append(additional_context)

    # Layer 1: Pattern matching
    for check_text in all_texts:
        for compiled, inj_type, desc, sev, conf in _COMPILED_RULES:
            match = compiled.search(check_text)
            if match:
                result.signals.append(InjectionSignal(
                    injection_type=inj_type,
                    pattern_matched=compiled.pattern[:60],
                    description=desc,
                    confidence=conf,
                    severity=sev,
                    evidence=match.group(0)[:100],
                ))

    # Layer 2: Content classification
    instruction_risk = _classify_content_risk(text)
    if instruction_risk > 0.4:
        result.signals.append(InjectionSignal(
            injection_type=InjectionType.INSTRUCTION_OVERRIDE,
            pattern_matched="[instruction_density_analysis]",
            description=f"Text has high instruction density (score: {instruction_risk:.2f})",
            confidence=instruction_risk * 0.8,
            severity="MEDIUM" if instruction_risk < 0.7 else "HIGH",
        ))

    # Layer 3: Origin-based risk amplification
    untrusted_origins = {
        ContentOrigin.EXTERNAL_WEBPAGE,
        ContentOrigin.EXTERNAL_EMAIL,
        ContentOrigin.EXTERNAL_DOCUMENT,
        ContentOrigin.EXTERNAL_CLIPBOARD,
        ContentOrigin.UNKNOWN,
    }

    if origin in untrusted_origins and result.signals:
        # Amplify risk for untrusted content with injection signals
        for signal in result.signals:
            signal.confidence = min(1.0, signal.confidence * 1.3)
            if signal.severity == "MEDIUM":
                signal.severity = "HIGH"
            elif signal.severity == "HIGH":
                signal.severity = "CRITICAL"

    # Compute aggregate risk
    if result.signals:
        severity_weights = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}
        max_risk = max(
            s.confidence * severity_weights.get(s.severity, 0.1)
            for s in result.signals
        )
        result.risk_score = max_risk
        result.is_suspicious = max_risk > 0.3
        result.is_blocked = max_risk > 0.7 or any(
            s.severity == "CRITICAL" and s.confidence > 0.8
            for s in result.signals
        )

        if result.is_blocked:
            result.recommendation = (
                "BLOCK: High-confidence prompt injection detected. "
                "This input should NOT be processed by the AI agent."
            )
        elif result.is_suspicious:
            result.recommendation = (
                "CAUTION: Suspicious patterns detected. "
                "Require user confirmation before processing."
            )
    else:
        result.recommendation = "No injection patterns detected."

    if result.signals:
        logger.warning(
            "INJECTION ANALYSIS | origin=%s | suspicious=%s | blocked=%s | signals=%d | score=%.3f",
            origin.value, result.is_suspicious, result.is_blocked,
            len(result.signals), result.risk_score,
        )

    return result
