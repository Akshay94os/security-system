"""
AK Master Security System — Permission Engine
Risk-based permission evaluation for all Nexus tool calls.

Risk Levels (§7):
  LEVEL 0 — SAFE: read-only, no confirmation normally required
  LEVEL 1 — LOW: create file, open website — may require confirmation by policy
  LEVEL 2 — SENSITIVE: clipboard, email, contacts — explicit confirmation required
  LEVEL 3 — HIGH: install software, delete files, modify config — confirm + auth
  LEVEL 4 — CRITICAL: disable security, bulk destructive — strong auth + admin approval

DEFAULT POLICY: DENY for undefined capabilities.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PermissionDecision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CONFIRMATION = "ALLOW_WITH_CONFIRMATION"
    REQUIRE_AUTHENTICATION = "REQUIRE_AUTHENTICATION"
    SANDBOX = "SANDBOX"
    DENY = "DENY"


@dataclass
class PermissionContext:
    user_id: str
    user_role: str
    tool_id: str
    risk_level: int
    parameters: Dict[str, Any]
    correlation_id: str
    session_id: Optional[str] = None
    is_authenticated_session: bool = True
    previous_failures: int = 0


@dataclass
class PermissionResult:
    decision: PermissionDecision
    reason: str
    policy_matched: Optional[str] = None
    requires_user_confirm: bool = False
    requires_auth: bool = False
    confirmation_message: Optional[str] = None


# ──────────────────────────────────────────────────────────
# Default risk-level policies
# ──────────────────────────────────────────────────────────

_DEFAULT_RISK_POLICIES: Dict[int, PermissionDecision] = {
    0: PermissionDecision.ALLOW,
    1: PermissionDecision.ALLOW_WITH_CONFIRMATION,
    2: PermissionDecision.ALLOW_WITH_CONFIRMATION,
    3: PermissionDecision.REQUIRE_AUTHENTICATION,
    4: PermissionDecision.DENY,  # Critical actions require explicit policy to allow
}

# Tools that are always denied regardless of user role (Phase 1)
_ALWAYS_DENY = frozenset({
    "security.disable_protection",
    "security.modify_auth_config",
    "system.arbitrary_shell",
    "system.exec",
    "system.eval",
})

# Tools that are always allowed for any authenticated user (Level 0 safe tools)
_ALWAYS_ALLOW_AUTHENTICATED = frozenset({
    "system.information",
    "system.battery_status",
    "security.health_check",
})


class PermissionEngine:
    """
    Evaluates permission decisions for tool calls.

    Policy cascade (highest priority first):
    1. Always-deny list (hardcoded, cannot be overridden)
    2. Always-allow list for authenticated users
    3. User-specific policy overrides
    4. Role-based policies
    5. Default risk-level policies
    6. Default: DENY
    """

    def __init__(self, custom_policies: Optional[List[dict]] = None):
        self._custom_policies: List[dict] = custom_policies or []

    def evaluate(self, ctx: PermissionContext) -> PermissionResult:
        """
        Evaluate a permission request. Returns a PermissionResult.
        Every call is logged — caller must record in audit log.
        """

        # --- Layer 1: Hard deny list ---
        if ctx.tool_id in _ALWAYS_DENY:
            logger.warning(
                "PERMISSION DENY (hardcoded) | tool=%s | user=%s | corr=%s",
                ctx.tool_id, ctx.user_id, ctx.correlation_id,
            )
            return PermissionResult(
                decision=PermissionDecision.DENY,
                reason=f"Tool '{ctx.tool_id}' is permanently restricted and cannot be authorized.",
                policy_matched="HARDCODED_DENY_LIST",
            )

        # --- Layer 2: Session validity ---
        if not ctx.is_authenticated_session:
            return PermissionResult(
                decision=PermissionDecision.DENY,
                reason="No valid authenticated session. Please log in.",
                policy_matched="SESSION_REQUIRED",
            )

        # --- Layer 3: Always-allow for Level 0 authenticated tools ---
        if ctx.tool_id in _ALWAYS_ALLOW_AUTHENTICATED and ctx.risk_level == 0:
            return PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason="Safe read-only tool — no confirmation required.",
                policy_matched="ALWAYS_ALLOW_LEVEL_0",
            )

        # --- Layer 4: Custom user/role policies ---
        for policy in self._custom_policies:
            if self._policy_matches(policy, ctx):
                decision = PermissionDecision(policy["action"])
                return PermissionResult(
                    decision=decision,
                    reason=f"Custom policy applied: {policy.get('name', policy['action'])}",
                    policy_matched=policy.get("id"),
                    requires_user_confirm=decision == PermissionDecision.ALLOW_WITH_CONFIRMATION,
                    requires_auth=decision == PermissionDecision.REQUIRE_AUTHENTICATION,
                    confirmation_message=policy.get("confirmation_message"),
                )

        # --- Layer 5: Risk-level defaults ---
        decision = _DEFAULT_RISK_POLICIES.get(ctx.risk_level, PermissionDecision.DENY)

        # SECURITY_ADMIN can execute Level 3 with confirmation instead of full auth
        if ctx.user_role in ("SECURITY_ADMIN", "SYSTEM_ADMIN") and ctx.risk_level == 3:
            decision = PermissionDecision.ALLOW_WITH_CONFIRMATION

        # SYSTEM_ADMIN can be granted Level 4 with authentication
        if ctx.user_role == "SYSTEM_ADMIN" and ctx.risk_level == 4:
            decision = PermissionDecision.REQUIRE_AUTHENTICATION

        requires_confirm = decision == PermissionDecision.ALLOW_WITH_CONFIRMATION
        requires_auth = decision == PermissionDecision.REQUIRE_AUTHENTICATION

        reason = self._format_reason(ctx.risk_level, decision)

        logger.info(
            "PERMISSION %s | tool=%s | risk=%d | user=%s | role=%s | corr=%s",
            decision.value, ctx.tool_id, ctx.risk_level,
            ctx.user_id, ctx.user_role, ctx.correlation_id,
        )

        return PermissionResult(
            decision=decision,
            reason=reason,
            policy_matched=f"DEFAULT_RISK_LEVEL_{ctx.risk_level}",
            requires_user_confirm=requires_confirm,
            requires_auth=requires_auth,
        )

    def _policy_matches(self, policy: dict, ctx: PermissionContext) -> bool:
        """Check whether a custom policy applies to this context."""
        if not policy.get("is_active", True):
            return False
        scope = policy.get("scope", "system")
        if scope == "user" and policy.get("scope_id") != ctx.user_id:
            return False
        if scope == "role" and policy.get("scope_id") != ctx.user_role:
            return False
        tool_id = policy.get("tool_id")
        if tool_id and tool_id != ctx.tool_id:
            return False
        return True

    def _format_reason(self, risk_level: int, decision: PermissionDecision) -> str:
        reasons = {
            0: "Safe, read-only operation.",
            1: "Low-risk operation — lightweight confirmation may be required.",
            2: "Sensitive operation involving user data or external communication.",
            3: "High-impact operation that modifies system state. Authentication required.",
            4: "Critical operation. Restricted by default security policy.",
        }
        base = reasons.get(risk_level, "Unknown risk level.")
        return f"{base} Decision: {decision.value}."
