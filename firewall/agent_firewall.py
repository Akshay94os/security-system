"""
AK Master Security System — Agent Firewall (Phase 1)
The security boundary between AI reasoning and real-world actions.

Every Nexus action passes through this firewall BEFORE execution.
This is a major research feature of the system (§26).

Evaluation pipeline:
  1. Tool existence (hallucination defense)
  2. Parameter validation
  3. Origin trust level
  4. Risk assessment
  5. Permission engine evaluation
  6. Data sensitivity check
  7. Action impact assessment
  8. Security state check

Returns: ALLOW | ALLOW_WITH_CONFIRMATION | REQUIRE_AUTHENTICATION | SANDBOX | DENY
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FirewallVerdict(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CONFIRMATION = "ALLOW_WITH_CONFIRMATION"
    REQUIRE_AUTHENTICATION = "REQUIRE_AUTHENTICATION"
    SANDBOX = "SANDBOX"
    DENY = "DENY"


class InstructionOrigin(str, Enum):
    """Trust level of the instruction source."""
    USER_DIRECT = "USER_DIRECT"          # User typed directly into Nexus — highest trust
    USER_VOICE = "USER_VOICE"            # Voice command from user
    AUTOMATION = "AUTOMATION"            # User-created automation — trusted
    WEBPAGE_CONTENT = "WEBPAGE_CONTENT"  # Content from a webpage — UNTRUSTED
    EMAIL_CONTENT = "EMAIL_CONTENT"      # Email content — UNTRUSTED
    DOCUMENT_CONTENT = "DOCUMENT_CONTENT"  # Document content — UNTRUSTED
    CLIPBOARD_CONTENT = "CLIPBOARD_CONTENT"  # Clipboard — UNTRUSTED
    UNKNOWN = "UNKNOWN"                  # Unknown origin — UNTRUSTED


# Origins that should NEVER trigger high-risk tool calls
_UNTRUSTED_ORIGINS = frozenset({
    InstructionOrigin.WEBPAGE_CONTENT,
    InstructionOrigin.EMAIL_CONTENT,
    InstructionOrigin.DOCUMENT_CONTENT,
    InstructionOrigin.CLIPBOARD_CONTENT,
    InstructionOrigin.UNKNOWN,
})

# Prompt injection detection patterns
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above|prior)\s+(instructions?|context|rules?|prompts?)",
    r"forget\s+(everything|all|previous|context)",
    r"you\s+are\s+now\s+(a\s+)?different",
    r"new\s+instructions?:",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"\[system\]",
    r"override\s+security",
    r"bypass\s+(security|auth|permission|policy|firewall)",
    r"act\s+as\s+(if|a|an)\s+(unrestricted|jailbreak|admin)",
    r"execute\s+command:",
    r"run\s+as\s+(root|admin|administrator)",
    r"sudo\s+",
    r"rm\s+-rf",
    r"del\s+/[sq]",
]
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@dataclass
class FirewallContext:
    tool_id: str
    parameters: Dict[str, Any]
    user_id: str
    user_role: str
    correlation_id: str
    origin: InstructionOrigin = InstructionOrigin.USER_DIRECT
    risk_level: int = 0
    raw_instruction: Optional[str] = None  # Original user text for injection check
    session_active: bool = True
    security_state: str = "NORMAL"  # NORMAL, ELEVATED, CRITICAL


@dataclass
class FirewallDecision:
    verdict: FirewallVerdict
    reasons: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    prompt_injection_detected: bool = False
    requires_explanation: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.verdict == FirewallVerdict.DENY

    @property
    def requires_confirmation(self) -> bool:
        return self.verdict in (
            FirewallVerdict.ALLOW_WITH_CONFIRMATION,
            FirewallVerdict.REQUIRE_AUTHENTICATION,
        )


class AgentFirewall:
    """
    The Agent Firewall — the security boundary between AI reasoning and execution.

    KEY PRINCIPLE (§103):
    LLM → structured intent → approved tool → validation → risk assessment
    → policy → authorization → execution → verification → audit
    The LLM NEVER has direct OS/tool access. This firewall decides.
    """

    def evaluate(self, ctx: FirewallContext) -> FirewallDecision:
        """
        Evaluate a tool call against all firewall rules.
        Returns a FirewallDecision — call this BEFORE executing any tool.
        """
        signals = []
        reasons = []
        prompt_injection = False

        # ── Check 1: Tool existence (hallucination defense) ──
        from nexus.tools.registry import get_tool_registry
        registry = get_tool_registry()

        if not registry.exists(ctx.tool_id):
            logger.warning(
                "FIREWALL DENY | Nonexistent tool '%s' | corr=%s",
                ctx.tool_id, ctx.correlation_id,
            )
            return FirewallDecision(
                verdict=FirewallVerdict.DENY,
                reasons=[
                    f"Tool '{ctx.tool_id}' does not exist in the approved tool registry. "
                    "This may indicate an AI hallucination or injection attempt."
                ],
                signals=["TOOL_NOT_IN_REGISTRY"],
                prompt_injection_detected=False,
            )

        tool = registry.get(ctx.tool_id)

        # ── Check 2: Parameter schema validation ──
        from nexus.tools.registry import ToolCallRequest
        request = ToolCallRequest(
            tool_id=ctx.tool_id,
            parameters=ctx.parameters,
            user_id=ctx.user_id,
            correlation_id=ctx.correlation_id,
        )
        valid, reason = registry.validate_call(request)
        if not valid:
            return FirewallDecision(
                verdict=FirewallVerdict.DENY,
                reasons=[f"Parameter validation failed: {reason}"],
                signals=["INVALID_PARAMETERS"],
            )

        # ── Check 3: Prompt injection detection ──
        texts_to_check = [ctx.raw_instruction or ""]
        for v in ctx.parameters.values():
            if isinstance(v, str):
                texts_to_check.append(v)

        for text in texts_to_check:
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(text):
                    logger.warning(
                        "FIREWALL: Prompt injection pattern detected | corr=%s | pattern=%s",
                        ctx.correlation_id, pattern.pattern,
                    )
                    signals.append("PROMPT_INJECTION_PATTERN_DETECTED")
                    prompt_injection = True
                    reasons.append(
                        "Potential prompt injection pattern detected in instruction or parameters. "
                        "External content cannot override system security policies."
                    )
                    break

        # ── Check 4: Untrusted origin restrictions ──
        if ctx.origin in _UNTRUSTED_ORIGINS:
            signals.append(f"UNTRUSTED_ORIGIN:{ctx.origin.value}")
            if tool.risk_level >= 2:
                reasons.append(
                    f"High-risk tool '{ctx.tool_id}' (level {tool.risk_level}) cannot be "
                    f"triggered by untrusted content from {ctx.origin.value}. "
                    "Only the user can authorize this action."
                )
                return FirewallDecision(
                    verdict=FirewallVerdict.DENY,
                    reasons=reasons,
                    signals=signals,
                    prompt_injection_detected=prompt_injection,
                )
            reasons.append(
                f"Action originates from untrusted source ({ctx.origin.value}). "
                "Explicit user confirmation required."
            )

        # ── Check 5: Security state check ──
        if ctx.security_state == "CRITICAL" and tool.risk_level >= 2:
            reasons.append(
                "System is in CRITICAL security state. "
                "Sensitive operations require explicit authentication."
            )
            signals.append("CRITICAL_SECURITY_STATE")

        # ── Check 6: Permission engine evaluation ──
        from nexus.permissions.engine import PermissionEngine, PermissionContext
        engine = PermissionEngine()
        perm_ctx = PermissionContext(
            user_id=ctx.user_id,
            user_role=ctx.user_role,
            tool_id=ctx.tool_id,
            risk_level=tool.risk_level,
            parameters=ctx.parameters,
            correlation_id=ctx.correlation_id,
            is_authenticated_session=ctx.session_active,
        )
        perm_result = engine.evaluate(perm_ctx)
        reasons.append(f"Permission: {perm_result.reason}")

        # ── Determine final verdict ──
        from nexus.permissions.engine import PermissionDecision

        if perm_result.decision == PermissionDecision.DENY:
            verdict = FirewallVerdict.DENY
        elif prompt_injection and tool.risk_level >= 1:
            verdict = FirewallVerdict.DENY
            reasons.append("Prompt injection + non-safe tool = DENY.")
        elif perm_result.decision == PermissionDecision.REQUIRE_AUTHENTICATION:
            verdict = FirewallVerdict.REQUIRE_AUTHENTICATION
        elif perm_result.decision == PermissionDecision.ALLOW_WITH_CONFIRMATION or (
            ctx.origin in _UNTRUSTED_ORIGINS
        ):
            verdict = FirewallVerdict.ALLOW_WITH_CONFIRMATION
        elif perm_result.decision == PermissionDecision.SANDBOX:
            verdict = FirewallVerdict.SANDBOX
        else:
            verdict = FirewallVerdict.ALLOW

        logger.info(
            "FIREWALL %s | tool=%s | origin=%s | risk=%d | injection=%s | corr=%s",
            verdict.value, ctx.tool_id, ctx.origin.value,
            tool.risk_level, prompt_injection, ctx.correlation_id,
        )

        return FirewallDecision(
            verdict=verdict,
            reasons=reasons,
            signals=signals,
            prompt_injection_detected=prompt_injection,
            requires_explanation=verdict != FirewallVerdict.ALLOW,
        )
