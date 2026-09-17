"""
AK Master Security System — Nexus Command Executor
The full secure execution pipeline per §2 and §103.

Pipeline:
USER INPUT
  → Intent Parser
  → Task Planner
  → Tool Selection
  → Structured Tool Call
  → Input Validation (Tool Registry)
  → Risk Analysis (Permission Engine)
  → Agent Firewall
  → Policy Decision
  → [User Confirmation if required]
  → Approved Tool
  → Execution
  → Verification (compare expected vs actual)
  → Audit Log
  → User Notification
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    PARSING = "PARSING"
    PLANNING = "PLANNING"
    FIREWALL_CHECK = "FIREWALL_CHECK"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    AWAITING_AUTH = "AWAITING_AUTH"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


@dataclass
class ExecutionResult:
    correlation_id: str
    status: ExecutionStatus
    user_message: str
    tool_output: Optional[Dict[str, Any]] = None
    firewall_decision: Optional[str] = None
    permission_decision: Optional[str] = None
    requires_confirmation: bool = False
    confirmation_message: Optional[str] = None
    requires_auth: bool = False
    error: Optional[str] = None
    audit_log_id: Optional[str] = None
    steps_taken: List[str] = field(default_factory=list)


class NexusExecutor:
    """
    Orchestrates the full secure execution pipeline for Nexus commands.
    """

    async def execute(
        self,
        user_input: str,
        user_id: str,
        user_role: str,
        session_active: bool = True,
        db=None,
        ip_address: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a Nexus command through the full secure pipeline."""
        correlation_id = str(uuid.uuid4())
        steps = []

        try:
            # ── Step 1: Parse Intent ──
            steps.append("PARSING")
            from nexus.agent.intent_parser import parse_intent
            intent = await parse_intent(user_input)
            logger.info("Intent parsed: action=%s tool=%s corr=%s",
                        intent.action, intent.suggested_tool_id, correlation_id)

            # ── Step 2: Check if we have a tool to execute ──
            if not intent.suggested_tool_id:
                # Informational or clarification needed
                response = await self._handle_informational(intent, user_id, db, correlation_id)
                return ExecutionResult(
                    correlation_id=correlation_id,
                    status=ExecutionStatus.COMPLETED,
                    user_message=response,
                    steps_taken=steps,
                )

            # ── Step 3: Build firewall context ──
            steps.append("FIREWALL_CHECK")
            from nexus.firewall.agent_firewall import AgentFirewall, FirewallContext, InstructionOrigin
            firewall = AgentFirewall()
            fw_ctx = FirewallContext(
                tool_id=intent.suggested_tool_id,
                parameters=intent.parameters,
                user_id=user_id,
                user_role=user_role,
                correlation_id=correlation_id,
                origin=InstructionOrigin.USER_DIRECT,
                risk_level=intent.risk_estimate,
                raw_instruction=user_input,
                session_active=session_active,
            )
            fw_decision = firewall.evaluate(fw_ctx)

            # ── Step 4: Handle firewall verdict ──
            if fw_decision.verdict.value == "DENY":
                steps.append("BLOCKED")
                await self._audit(
                    db, correlation_id, user_id, intent.suggested_tool_id,
                    "NEXUS_TOOL_CALL", "BLOCKED",
                    ip_address=ip_address,
                    firewall_verdict="DENY",
                    reasons=fw_decision.reasons,
                )
                reason_text = " ".join(fw_decision.reasons)
                return ExecutionResult(
                    correlation_id=correlation_id,
                    status=ExecutionStatus.BLOCKED,
                    user_message=f"🛡️ **Security Block**: {reason_text}",
                    firewall_decision="DENY",
                    steps_taken=steps,
                )

            if fw_decision.verdict.value in ("ALLOW_WITH_CONFIRMATION", "REQUIRE_AUTHENTICATION"):
                steps.append("AWAITING_CONFIRMATION")
                msg = " ".join(fw_decision.reasons)
                return ExecutionResult(
                    correlation_id=correlation_id,
                    status=ExecutionStatus.AWAITING_CONFIRMATION,
                    user_message=f"⚠️ **Confirmation Required**: {msg}",
                    firewall_decision=fw_decision.verdict.value,
                    requires_confirmation=fw_decision.requires_confirmation,
                    requires_auth=fw_decision.verdict.value == "REQUIRE_AUTHENTICATION",
                    confirmation_message=f"Nexus wants to execute: **{intent.suggested_tool_id}**\n\n{msg}",
                    steps_taken=steps,
                )

            # ── Step 5: Execute approved tool ──
            steps.append("EXECUTING")
            from nexus.tools.registry import get_tool_registry, ToolCallRequest
            registry = get_tool_registry()
            request = ToolCallRequest(
                tool_id=intent.suggested_tool_id,
                parameters=intent.parameters,
                user_id=user_id,
                correlation_id=correlation_id,
            )
            tool_result = await registry.execute(request)

            # ── Step 6: Verification ──
            steps.append("VERIFYING")
            verified = tool_result.success and not tool_result.was_blocked

            # ── Step 7: Audit ──
            await self._audit(
                db, correlation_id, user_id, intent.suggested_tool_id,
                "NEXUS_TOOL_CALL",
                "SUCCESS" if verified else "FAILURE",
                ip_address=ip_address,
                firewall_verdict=fw_decision.verdict.value,
                tool_output=tool_result.output,
                error=tool_result.error,
            )

            steps.append("COMPLETED")
            if verified:
                output_summary = self._summarize_output(intent.suggested_tool_id, tool_result.output)
                return ExecutionResult(
                    correlation_id=correlation_id,
                    status=ExecutionStatus.COMPLETED,
                    user_message=f"✅ {output_summary}",
                    tool_output=tool_result.output,
                    firewall_decision=fw_decision.verdict.value,
                    steps_taken=steps,
                )
            else:
                return ExecutionResult(
                    correlation_id=correlation_id,
                    status=ExecutionStatus.FAILED,
                    user_message=f"❌ Tool execution failed: {tool_result.error}",
                    error=tool_result.error,
                    steps_taken=steps,
                )

        except Exception as e:
            logger.error("Executor unhandled error: %s | corr=%s", e, correlation_id)
            return ExecutionResult(
                correlation_id=correlation_id,
                status=ExecutionStatus.FAILED,
                user_message=f"❌ An internal error occurred. Please try again. (ID: {correlation_id[:8]})",
                error=str(e),
                steps_taken=steps,
            )

    async def _handle_informational(
        self,
        intent,
        user_id: str,
        db,
        correlation_id: str,
    ) -> str:
        """Handle commands that don't map to a specific tool."""
        if intent.action == "greeting":
            return (
                "👋 Hello! I'm **AK Nexus**, your security AI assistant.\n\n"
                "I can help you monitor system health, scan files and URLs for threats, "
                "and browse local directories safely. What would you like to do?"
            )

        if intent.action == "help":
            return (
                "🛡️ **AK Nexus Capabilities:**\n\n"
                "• `system info` — View CPU, RAM, Disk & OS information\n"
                "• `battery status` — View battery percentage & charging status\n"
                "• `security status` — View health of all security modules\n"
                "• `scan url <url>` — Analyze URL for malware & phishing\n"
                "• `scan file <path>` — Analyze local file for security threats\n"
                "• `list files in <path>` — Browse local directory contents"
            )

        if intent.action == "web_download":
            return (
                "ℹ️ Unrestricted web downloading is disabled to protect your system from malware.\n\n"
                "However, you can use `scan url <url>` to analyze any link or file download URL for security risks!"
            )

        if intent.action == "security_status":
            from backend.security.health_monitor import run_health_check
            health = await run_health_check()
            status_emoji = "🟢" if health.overall_status.value == "OPERATIONAL" else "🟡"
            lines = [f"{status_emoji} **Security Status: {health.overall_status.value}**\n"]
            for module in health.modules:
                emoji = "✅" if module.status.value == "OPERATIONAL" else ("⚠️" if module.status.value in ("DEGRADED","UNCONFIGURED") else "❌")
                lines.append(f"{emoji} {module.name}: {module.status.value}")
            return "\n".join(lines)

        if intent.action == "unknown":
            return (
                "I understood your request but couldn't identify a specific action. "
                "Try being more specific, for example:\n"
                "- 'Show system information'\n"
                "- 'Check my security status'\n"
                "- 'Scan URL https://example.com'\n"
                "- 'List files in Downloads'"
            )

        return f"Request understood (action: {intent.action}). This feature is not yet available in Phase 1."

    def _summarize_output(self, tool_id: str, output: dict) -> str:
        """Generate a human-readable summary of tool output."""
        if tool_id == "system.information":
            return (
                f"System: {output.get('os', 'Unknown')} | "
                f"CPU: {output.get('cpu_percent', '?')}% | "
                f"RAM: {output.get('memory_used_percent', '?')}% | "
                f"Disk: {output.get('disk_used_percent', '?')}%"
            )
        if tool_id == "system.battery_status":
            if not output.get("available"):
                return output.get("message", "No battery information available.")
            return (
                f"Battery: {output.get('percent', '?')}% "
                f"({'charging' if output.get('charging') else 'not charging'})"
            )
        if tool_id == "file.list":
            return (
                f"Found {output.get('count', 0)} items in {output.get('path', '?')}"
                + (" (results truncated)" if output.get("truncated") else "")
            )
        if tool_id == "file.search":
            return (
                f"Found {output.get('count', 0)} files matching '{output.get('pattern', '?')}'"
                + (" (results truncated)" if output.get("truncated") else "")
            )
        return f"Tool completed successfully. Output: {str(output)[:200]}"

    async def _audit(
        self,
        db,
        correlation_id: str,
        user_id: str,
        tool_id: Optional[str],
        action: str,
        outcome: str,
        ip_address: Optional[str] = None,
        firewall_verdict: Optional[str] = None,
        tool_output: Optional[dict] = None,
        error: Optional[str] = None,
        reasons: Optional[list] = None,
    ) -> None:
        """Write audit log entry if DB is available."""
        if db is None:
            return
        try:
            from backend.security.audit_log import write_audit_log
            await write_audit_log(
                db=db,
                correlation_id=correlation_id,
                actor_user_id=user_id,
                actor_type="nexus",
                action=action,
                tool_id=tool_id,
                outcome=outcome,
                permission_result=firewall_verdict,
                error_message=error or ("; ".join(reasons) if reasons else None),
                ip_address=ip_address,
            )
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)
